import copy
import glob
import hashlib
import os
import pwd
import shutil
import subprocess
import tempfile
import threading
import uuid

from collections import OrderedDict
from swift_context import (
    get_swift_hash,
    SwiftHashContext,
    SwiftIdentityContext,
    HAProxyContext,
    SwiftRingContext,
    ApacheSSLContext,
    MemcachedContext,
)

import charmhelpers.contrib.openstack.context as context
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.contrib.openstack.utils import (
    os_release,
    get_os_codename_package,
    get_os_codename_install_source,
    configure_installation_source,
    set_os_workload_status,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    peer_units,
)
from charmhelpers.core.hookenv import (
    log,
    DEBUG,
    INFO,
    WARNING,
    config,
    relation_get,
    unit_get,
    relation_set,
    relation_ids,
    related_units,
    status_get,
    status_set,
)
from charmhelpers.fetch import (
    apt_update,
    apt_upgrade,
    apt_install,
    add_source
)
from charmhelpers.core.host import (
    lsb_release,
    restart_on_change,
)
from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
    get_ipv6_addr,
)
from charmhelpers.core.decorators import (
    retry_on_exception,
)

# Various config files that are managed via templating.
SWIFT_CONF_DIR = '/etc/swift'
SWIFT_RING_EXT = 'ring.gz'
SWIFT_CONF = os.path.join(SWIFT_CONF_DIR, 'swift.conf')
SWIFT_PROXY_CONF = os.path.join(SWIFT_CONF_DIR, 'proxy-server.conf')
SWIFT_CONF_DIR = os.path.dirname(SWIFT_CONF)
MEMCACHED_CONF = '/etc/memcached.conf'
SWIFT_RINGS_CONF = '/etc/apache2/conf.d/swift-rings'
SWIFT_RINGS_24_CONF = '/etc/apache2/conf-available/swift-rings.conf'
HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_SITES_AVAILABLE = '/etc/apache2/sites-available'
APACHE_SITE_CONF = os.path.join(APACHE_SITES_AVAILABLE,
                                'openstack_https_frontend')
APACHE_SITE_24_CONF = os.path.join(APACHE_SITES_AVAILABLE,
                                   'openstack_https_frontend.conf')

WWW_DIR = '/var/www/swift-rings'
ALTERNATE_WWW_DIR = '/var/www/html/swift-rings'

RING_SYNC_SEMAPHORE = threading.Semaphore()


def get_www_dir():
    if os.path.isdir(os.path.dirname(ALTERNATE_WWW_DIR)):
        return ALTERNATE_WWW_DIR
    else:
        return WWW_DIR


SWIFT_RINGS = {
    'account': os.path.join(SWIFT_CONF_DIR, 'account.builder'),
    'container': os.path.join(SWIFT_CONF_DIR, 'container.builder'),
    'object': os.path.join(SWIFT_CONF_DIR, 'object.builder')
}

SSL_CERT = os.path.join(SWIFT_CONF_DIR, 'cert.crt')
SSL_KEY = os.path.join(SWIFT_CONF_DIR, 'cert.key')

# Essex packages
BASE_PACKAGES = [
    'swift',
    'swift-proxy',
    'memcached',
    'apache2',
    'python-keystone',
]
# > Folsom specific packages
FOLSOM_PACKAGES = BASE_PACKAGES + ['swift-plugin-s3']

SWIFT_HA_RES = 'grp_swift_vips'
TEMPLATES = 'templates/'

# Map config files to hook contexts and services that will be associated
# with file in restart_on_changes()'s service map.
CONFIG_FILES = OrderedDict([
    (SWIFT_CONF, {
        'hook_contexts': [SwiftHashContext()],
        'services': ['swift-proxy'],
    }),
    (SWIFT_PROXY_CONF, {
        'hook_contexts': [SwiftIdentityContext(),
                          context.BindHostContext()],
        'services': ['swift-proxy'],
    }),
    (HAPROXY_CONF, {
        'hook_contexts': [context.HAProxyContext(singlenode_mode=True),
                          HAProxyContext()],
        'services': ['haproxy'],
    }),
    (SWIFT_RINGS_CONF, {
        'hook_contexts': [SwiftRingContext()],
        'services': ['apache2'],
    }),
    (SWIFT_RINGS_24_CONF, {
        'hook_contexts': [SwiftRingContext()],
        'services': ['apache2'],
    }),
    (APACHE_SITE_CONF, {
        'hook_contexts': [ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_SITE_24_CONF, {
        'hook_contexts': [ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (MEMCACHED_CONF, {
        'hook_contexts': [MemcachedContext()],
        'services': ['memcached'],
    }),
])


class SwiftProxyCharmException(Exception):
    pass


class SwiftProxyClusterRPC(object):
    """Provides cluster relation rpc dicts.

    Crucially, this ensures that any settings we don't use in any given call
    are set to None, therefore removing them from the relation so they don't
    get accidentally interpreted by the receiver as part of the request.

    NOTE: these are only intended to be used from cluster peer relations.
    """

    KEY_STOP_PROXY_SVC = 'stop-proxy-service'
    KEY_STOP_PROXY_SVC_ACK = 'stop-proxy-service-ack'
    KEY_NOTIFY_LEADER_CHANGED = 'leader-changed-notification'

    def __init__(self, version=1):
        self._version = version

    def template(self):
        # Everything must be None by default so it gets dropped from the
        # relation unless we want it to be set.
        templates = {1: {'trigger': None,
                         'broker-token': None,
                         'builder-broker': None,
                         self.KEY_STOP_PROXY_SVC: None,
                         self.KEY_STOP_PROXY_SVC_ACK: None,
                         self.KEY_NOTIFY_LEADER_CHANGED: None,
                         'peers-only': None,
                         'sync-only-builders': None}}
        return copy.deepcopy(templates[self._version])

    def stop_proxy_request(self, peers_only=False):
        """Request to stop peer proxy service.

        NOTE: leader action
        """
        rq = self.template()
        rq['trigger'] = str(uuid.uuid4())
        rq[self.KEY_STOP_PROXY_SVC] = rq['trigger']
        if peers_only:
            rq['peers-only'] = 1

        return rq

    def stop_proxy_ack(self, echo_token, echo_peers_only):
        """Ack that peer proxy service is stopped.

        NOTE: non-leader action
        """
        rq = self.template()
        rq['trigger'] = str(uuid.uuid4())
        # These echo values should match those received in the request
        rq[self.KEY_STOP_PROXY_SVC_ACK] = echo_token
        rq['peers-only'] = echo_peers_only
        return rq

    def sync_rings_request(self, broker_host, broker_token,
                           builders_only=False):
        """Request for peer to sync rings.

        NOTE: leader action
        """
        rq = self.template()
        rq['trigger'] = str(uuid.uuid4())

        if builders_only:
            rq['sync-only-builders'] = 1

        rq['broker-token'] = broker_token
        rq['builder-broker'] = broker_host
        return rq

    def notify_leader_changed(self):
        """Notify peers that leader has changed.

        NOTE: leader action
        """
        rq = self.template()
        rq['trigger'] = str(uuid.uuid4())
        rq[self.KEY_NOTIFY_LEADER_CHANGED] = rq['trigger']
        return rq


def get_first_available_value(responses, key, default=None):
    for r in responses:
        if key in r:
            return r[key]

    return default


def all_responses_equal(responses, key, must_exist=True):
    """If key exists in responses, all values for it must be equal.

    If all equal return True. If key does not exist and must_exist is True
    return False otherwise True.
    """
    sentinel = object()
    val = None
    all_equal = True
    for r in responses:
        _val = r.get(key, sentinel)
        if val is not None and val != _val:
            all_equal = False
            break
        elif _val != sentinel:
            val = _val

    if must_exist and val is None:
        all_equal = False

    if all_equal:
        return True

    log("Responses not all equal for key '%s'" % (key), level=DEBUG)
    return False


def register_configs():
    """Register config files with their respective contexts.

    Registration of some configs may not be required depending on
    existing of certain relations.
    """
    # if called without anything installed (eg during install hook)
    # just default to earliest supported release. configs dont get touched
    # till post-install, anyway.
    release = get_os_codename_package('swift-proxy', fatal=False) \
        or 'essex'
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)

    confs = [SWIFT_CONF,
             SWIFT_PROXY_CONF,
             HAPROXY_CONF,
             MEMCACHED_CONF]

    for conf in confs:
        configs.register(conf, CONFIG_FILES[conf]['hook_contexts'])

    if os.path.exists('/etc/apache2/conf-available'):
        configs.register(SWIFT_RINGS_24_CONF,
                         CONFIG_FILES[SWIFT_RINGS_24_CONF]['hook_contexts'])
        configs.register(APACHE_SITE_24_CONF,
                         CONFIG_FILES[APACHE_SITE_24_CONF]['hook_contexts'])
    else:
        configs.register(SWIFT_RINGS_CONF,
                         CONFIG_FILES[SWIFT_RINGS_CONF]['hook_contexts'])
        configs.register(APACHE_SITE_CONF,
                         CONFIG_FILES[APACHE_SITE_CONF]['hook_contexts'])
    return configs


def restart_map():
    """Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    """
    _map = []
    for f, ctxt in CONFIG_FILES.iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map.append((f, svcs))

    return OrderedDict(_map)


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def swift_user(username='swift'):
    user = pwd.getpwnam(username)
    return (user.pw_uid, user.pw_gid)


def ensure_swift_dir(conf_dir=os.path.dirname(SWIFT_CONF)):
    if not os.path.isdir(conf_dir):
        os.mkdir(conf_dir, 0o750)

    uid, gid = swift_user()
    os.chown(conf_dir, uid, gid)


def determine_packages(release):
    """Determine what packages are needed for a given OpenStack release."""
    if release == 'essex':
        return BASE_PACKAGES
    elif release == 'folsom':
        return FOLSOM_PACKAGES
    elif release == 'grizzly':
        return FOLSOM_PACKAGES
    else:
        return FOLSOM_PACKAGES


def _load_builder(path):
    # lifted straight from /usr/bin/swift-ring-builder
    from swift.common.ring import RingBuilder
    import cPickle as pickle
    try:
        builder = pickle.load(open(path, 'rb'))
        if not hasattr(builder, 'devs'):
            builder_dict = builder
            builder = RingBuilder(1, 1, 1)
            builder.copy_from(builder_dict)
    except ImportError:  # Happens with really old builder pickles
        builder = RingBuilder(1, 1, 1)
        builder.copy_from(pickle.load(open(path, 'rb')))
    for dev in builder.devs:
        if dev and 'meta' not in dev:
            dev['meta'] = ''

    return builder


def _write_ring(ring, ring_path):
    import cPickle as pickle
    with open(ring_path, "wb") as fd:
        pickle.dump(ring.to_dict(), fd, protocol=2)


def ring_port(ring_path, node):
    """Determine correct port from relation settings for a given ring file."""
    for name in ['account', 'object', 'container']:
        if name in ring_path:
            return node[('%s_port' % name)]


def initialize_ring(path, part_power, replicas, min_hours):
    """Initialize a new swift ring with given parameters."""
    from swift.common.ring import RingBuilder
    ring = RingBuilder(part_power, replicas, min_hours)
    _write_ring(ring, path)


def exists_in_ring(ring_path, node):
    ring = _load_builder(ring_path).to_dict()
    node['port'] = ring_port(ring_path, node)

    for dev in ring['devs']:
        d = [(i, dev[i]) for i in dev if i in node and i != 'zone']
        n = [(i, node[i]) for i in node if i in dev and i != 'zone']
        if sorted(d) == sorted(n):

            log('Node already exists in ring (%s).' % ring_path, level=INFO)
            return True

    return False


def add_to_ring(ring_path, node, device):
    ring = _load_builder(ring_path)
    port = ring_port(ring_path, node)

    devs = ring.to_dict()['devs']
    next_id = 0
    if devs:
        next_id = len([d['id'] for d in devs])

    new_dev = {
        'id': next_id,
        'zone': node['zone'],
        'ip': node['ip'],
        'port': port,
        'device': device,
        'weight': 100,
        'meta': '',
    }
    ring.add_dev(new_dev)
    _write_ring(ring, ring_path)
    msg = 'Added new device to ring %s: %s' % (ring_path, new_dev)
    log(msg, level=INFO)


def _get_zone(ring_builder):
    replicas = ring_builder.replicas
    zones = [d['zone'] for d in ring_builder.devs]
    if not zones:
        return 1

    # zones is a per-device list, so we may have one
    # node with 3 devices in zone 1.  For balancing
    # we need to track the unique zones being used
    # not necessarily the number of devices
    unique_zones = list(set(zones))
    if len(unique_zones) < replicas:
        return sorted(unique_zones).pop() + 1

    zone_distrib = {}
    for z in zones:
        zone_distrib[z] = zone_distrib.get(z, 0) + 1

    if len(set([total for total in zone_distrib.itervalues()])) == 1:
        # all zones are equal, start assigning to zone 1 again.
        return 1

    return sorted(zone_distrib, key=zone_distrib.get).pop(0)


def get_min_part_hours(ring):
    builder = _load_builder(ring)
    return builder.min_part_hours


def set_min_part_hours(path, value):
    cmd = ['swift-ring-builder', path, 'set_min_part_hours', str(value)]
    p = subprocess.Popen(cmd)
    p.communicate()
    rc = p.returncode
    if rc != 0:
        msg = ("Failed to set min_part_hours=%s on %s" % (value, path))
        raise SwiftProxyCharmException(msg)


def get_zone(assignment_policy):
    """Determine appropriate zone based on configured assignment policy.

    Manual assignment relies on each storage zone being deployed as a
    separate service unit with its desired zone set as a configuration
    option.

    Auto assignment distributes swift-storage machine units across a number
    of zones equal to the configured minimum replicas.  This allows for a
    single swift-storage service unit, with each 'add-unit'd machine unit
    being assigned to a different zone.
    """
    if assignment_policy == 'manual':
        return relation_get('zone')
    elif assignment_policy == 'auto':
        potential_zones = []
        for ring in SWIFT_RINGS.itervalues():
            builder = _load_builder(ring)
            potential_zones.append(_get_zone(builder))
        return set(potential_zones).pop()
    else:
        msg = ('Invalid zone assignment policy: %s' % assignment_policy)
        raise SwiftProxyCharmException(msg)


def balance_ring(ring_path):
    """Balance a ring.

    Returns True if it needs redistribution.
    """
    # shell out to swift-ring-builder instead, since the balancing code there
    # does a bunch of un-importable validation.'''
    cmd = ['swift-ring-builder', ring_path, 'rebalance']
    p = subprocess.Popen(cmd)
    p.communicate()
    rc = p.returncode
    if rc == 0:
        return True

    if rc == 1:
        # Ring builder exit-code=1 is supposed to indicate warning but I have
        # noticed that it can also return 1 with the following sort of message:
        #
        #   NOTE: Balance of 166.67 indicates you should push this ring, wait
        #         at least 0 hours, and rebalance/repush.
        #
        # This indicates that a balance has occurred and a resync would be
        # required so not sure why 1 is returned in this case.
        return False

    msg = ('balance_ring: %s returned %s' % (cmd, rc))
    raise SwiftProxyCharmException(msg)


def should_balance(rings):
    """Determine whether or not a re-balance is required and allowed.

    Ring balance can be disabled/postponed using the disable-ring-balance
    config option.

    Otherwise, using zones vs min. replicas, determine whether or not the rings
    should be balanced.
    """
    if config('disable-ring-balance'):
        return False

    return has_minimum_zones(rings)


def do_openstack_upgrade(configs):
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)

    log('Performing OpenStack upgrade to %s.' % (new_os_rel), level=DEBUG)
    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]
    apt_update()
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    configs.set_release(openstack_release=new_os_rel)
    configs.write_all()


def setup_ipv6():
    """Validate that we can support IPv6 mode.

    This should be called if prefer-ipv6 is True to ensure that we are running
    in an environment that supports ipv6.
    """
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if ubuntu_rel < "trusty":
        msg = ("IPv6 is not supported in the charms for Ubuntu versions less "
               "than Trusty 14.04")
        raise SwiftProxyCharmException(msg)

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if ubuntu_rel == 'trusty' and os_release('swift-proxy') < 'liberty':
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


@retry_on_exception(3, base_delay=2, exc_type=subprocess.CalledProcessError)
def sync_proxy_rings(broker_url, builders=True, rings=True):
    """The leader proxy is responsible for intialising, updating and
    rebalancing the ring. Once the leader is ready the rings must then be
    synced into each other proxy unit.

    Note that we sync the ring builder and .gz files since the builder itself
    is linked to the underlying .gz ring.
    """
    log('Fetching swift rings & builders from proxy @ %s.' % broker_url,
        level=DEBUG)
    target = SWIFT_CONF_DIR
    synced = []
    tmpdir = tempfile.mkdtemp(prefix='swiftrings')
    try:
        for server in ['account', 'object', 'container']:
            if builders:
                url = '%s/%s.builder' % (broker_url, server)
                log('Fetching %s.' % url, level=DEBUG)
                builder = "%s.builder" % (server)
                cmd = ['wget', url, '--retry-connrefused', '-t', '10', '-O',
                       os.path.join(tmpdir, builder)]
                subprocess.check_call(cmd)
                synced.append(builder)

            if rings:
                url = '%s/%s.%s' % (broker_url, server, SWIFT_RING_EXT)
                log('Fetching %s.' % url, level=DEBUG)
                ring = '%s.%s' % (server, SWIFT_RING_EXT)
                cmd = ['wget', url, '--retry-connrefused', '-t', '10', '-O',
                       os.path.join(tmpdir, ring)]
                subprocess.check_call(cmd)
                synced.append(ring)

        # Once all have been successfully downloaded, move them to actual
        # location.
        for f in synced:
            os.rename(os.path.join(tmpdir, f), os.path.join(target, f))
    finally:
        shutil.rmtree(tmpdir)


def ensure_www_dir_permissions(www_dir):
    if not os.path.isdir(www_dir):
        os.mkdir(www_dir, 0o755)
    else:
        os.chmod(www_dir, 0o755)

    uid, gid = swift_user()
    os.chown(www_dir, uid, gid)


def update_www_rings(rings=True, builders=True):
    """Copy rings to apache www dir.

    Try to do this as atomically as possible to avoid races with storage nodes
    syncing rings.
    """
    if not (rings or builders):
        return

    tmp_dir = tempfile.mkdtemp(prefix='swift-rings-www-tmp')
    for ring, builder_path in SWIFT_RINGS.iteritems():
        if rings:
            ringfile = '%s.%s' % (ring, SWIFT_RING_EXT)
            src = os.path.join(SWIFT_CONF_DIR, ringfile)
            dst = os.path.join(tmp_dir, ringfile)
            shutil.copyfile(src, dst)

        if builders:
            src = builder_path
            dst = os.path.join(tmp_dir, os.path.basename(builder_path))
            shutil.copyfile(src, dst)

    www_dir = get_www_dir()
    deleted = "%s.deleted" % (www_dir)
    ensure_www_dir_permissions(tmp_dir)
    os.rename(www_dir, deleted)
    os.rename(tmp_dir, www_dir)
    shutil.rmtree(deleted)


def get_rings_checksum():
    """Returns sha256 checksum for rings in /etc/swift."""
    sha = hashlib.sha256()
    for ring in SWIFT_RINGS.iterkeys():
        path = os.path.join(SWIFT_CONF_DIR, '%s.%s' % (ring, SWIFT_RING_EXT))
        if not os.path.isfile(path):
            continue

        with open(path, 'rb') as fd:
            sha.update(fd.read())

    return sha.hexdigest()


def get_builders_checksum():
    """Returns sha256 checksum for builders in /etc/swift."""
    sha = hashlib.sha256()
    for builder in SWIFT_RINGS.itervalues():
        if not os.path.exists(builder):
            continue

        with open(builder, 'rb') as fd:
            sha.update(fd.read())

    return sha.hexdigest()


def get_broker_token():
    """Get ack token from peers to be used as broker token.

    Must be equal across all peers.

    Returns token or None if not found.
    """
    responses = []
    ack_key = SwiftProxyClusterRPC.KEY_STOP_PROXY_SVC_ACK
    for rid in relation_ids('cluster'):
        for unit in related_units(rid):
            responses.append(relation_get(attribute=ack_key, rid=rid,
                                          unit=unit))

    # If no acks exist we have probably never done a sync so make up a token
    if len(responses) == 0:
        return str(uuid.uuid4())

    if not all(responses) or len(set(responses)) != 1:
        log("Not all ack tokens equal - %s" % (responses), level=DEBUG)
        return None

    return responses[0]


def sync_builders_and_rings_if_changed(f):
    """Only trigger a ring or builder sync if they have changed as a result of
    the decorated operation.
    """
    def _inner_sync_builders_and_rings_if_changed(*args, **kwargs):
        if not is_elected_leader(SWIFT_HA_RES):
            log("Sync rings called by non-leader - skipping", level=WARNING)
            return

        try:
            # Ensure we don't do a double sync if we are nested.
            do_sync = False
            if RING_SYNC_SEMAPHORE.acquire(blocking=0):
                do_sync = True
                rings_before = get_rings_checksum()
                builders_before = get_builders_checksum()

            ret = f(*args, **kwargs)

            if not do_sync:
                return ret

            rings_after = get_rings_checksum()
            builders_after = get_builders_checksum()

            rings_path = os.path.join(SWIFT_CONF_DIR, '*.%s' %
                                      (SWIFT_RING_EXT))
            rings_ready = len(glob.glob(rings_path)) == len(SWIFT_RINGS)
            rings_changed = rings_after != rings_before
            builders_changed = builders_after != builders_before
            if rings_changed or builders_changed:
                # Copy builders and rings (if available) to the server dir.
                update_www_rings(rings=rings_ready)
                if rings_changed and rings_ready:
                    # Trigger sync
                    cluster_sync_rings(peers_only=not rings_changed)
                else:
                    cluster_sync_rings(peers_only=True, builders_only=True)
                    log("Rings not ready for sync - syncing builders",
                        level=DEBUG)
            else:
                log("Rings/builders unchanged - skipping sync", level=DEBUG)

            return ret
        finally:
            RING_SYNC_SEMAPHORE.release()

    return _inner_sync_builders_and_rings_if_changed


@sync_builders_and_rings_if_changed
def update_rings(node_settings=None, min_part_hours=None):
    """Update builder with node settings and balance rings if necessary.

    Also update min_part_hours if provided.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        log("Update rings called by non-leader - skipping", level=WARNING)
        return

    balance_required = False

    if min_part_hours:
        # NOTE: no need to stop the proxy since we are not changing the rings,
        # only the builder.

        # Only update if all exist
        if all([os.path.exists(p) for p in SWIFT_RINGS.itervalues()]):
            for ring, path in SWIFT_RINGS.iteritems():
                current_min_part_hours = get_min_part_hours(path)
                if min_part_hours != current_min_part_hours:
                    log("Setting ring %s min_part_hours to %s" %
                        (ring, min_part_hours), level=INFO)
                    try:
                        set_min_part_hours(path, min_part_hours)
                    except SwiftProxyCharmException as exc:
                        # TODO: ignore for now since this should not be
                        # critical but in the future we should support a
                        # rollback.
                        log(str(exc), level=WARNING)
                    else:
                        balance_required = True

    if node_settings:
        for dev in node_settings.get('devices', []):
            for ring in SWIFT_RINGS.itervalues():
                if not exists_in_ring(ring, node_settings):
                    add_to_ring(ring, node_settings, dev)
                    balance_required = True

    if balance_required:
        balance_rings()


@sync_builders_and_rings_if_changed
def balance_rings():
    """Rebalance each ring and notify peers that new rings are available."""
    if not is_elected_leader(SWIFT_HA_RES):
        log("Balance rings called by non-leader - skipping", level=WARNING)
        return

    if not should_balance([r for r in SWIFT_RINGS.itervalues()]):
        log("Not yet ready to balance rings - insufficient replicas?",
            level=INFO)
        return

    rebalanced = False
    for path in SWIFT_RINGS.itervalues():
        if balance_ring(path):
            log('Balanced ring %s' % path, level=DEBUG)
            rebalanced = True
        else:
            log('Ring %s not rebalanced' % path, level=DEBUG)

    if not rebalanced:
        log("Rings unchanged by rebalance", level=DEBUG)
        # NOTE: checksum will tell for sure


def mark_www_rings_deleted():
    """Mark any rings from the apache server directory as deleted so that
    storage units won't see them.
    """
    www_dir = get_www_dir()
    for ring, _ in SWIFT_RINGS.iteritems():
        path = os.path.join(www_dir, '%s.ring.gz' % ring)
        if os.path.exists(path):
            os.rename(path, "%s.deleted" % (path))


def notify_peers_builders_available(broker_token, builders_only=False):
    """Notify peer swift-proxy units that they should synchronise ring and
    builder files.

    Note that this should only be called from the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        log("Ring availability peer broadcast requested by non-leader - "
            "skipping", level=WARNING)
        return

    hostname = get_hostaddr()
    hostname = format_ipv6_addr(hostname) or hostname
    # Notify peers that builders are available
    log("Notifying peer(s) that rings are ready for sync.", level=INFO)
    rq = SwiftProxyClusterRPC().sync_rings_request(hostname,
                                                   broker_token,
                                                   builders_only=builders_only)
    for rid in relation_ids('cluster'):
        log("Notifying rid=%s (%s)" % (rid, rq), level=DEBUG)
        relation_set(relation_id=rid, relation_settings=rq)


def broadcast_rings_available(broker_token, peers=True, storage=True,
                              builders_only=False):
    """Notify storage relations and cluster (peer) relations that rings and
    builders are availble for sync.

    We can opt to only notify peer or storage relations if needs be.
    """
    if storage:
        # TODO: get ack from storage units that they are synced before
        # syncing proxies.
        notify_storage_rings_available()
    else:
        log("Skipping notify storage relations", level=DEBUG)

    if peers:
        notify_peers_builders_available(broker_token,
                                        builders_only=builders_only)
    else:
        log("Skipping notify peer relations", level=DEBUG)


def cluster_sync_rings(peers_only=False, builders_only=False):
    """Notify peer relations that they should stop their proxy services.

    Peer units will then be expected to do a relation_set with
    stop-proxy-service-ack set rq value. Once all peers have responded, the
    leader will send out notification to all relations that rings are available
    for sync.

    If peers_only is True, only peer units will be synced. This is typically
    used when only builder files have been changed.

    This should only be called by the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        # Only the leader can do this.
        return

    if not peer_units():
        # If we have no peer units just go ahead and broadcast to storage
        # relations. If we have been instructed to only broadcast to peers this
        # should do nothing.
        broker_token = get_broker_token()
        broadcast_rings_available(broker_token, peers=False,
                                  storage=not peers_only)
        return
    elif builders_only:
        # No need to stop proxies if only syncing builders between peers.
        broker_token = get_broker_token()
        broadcast_rings_available(broker_token, storage=False,
                                  builders_only=builders_only)
        return

    rel_ids = relation_ids('cluster')
    trigger = str(uuid.uuid4())

    log("Sending request to stop proxy service to all peers (%s)" % (trigger),
        level=INFO)
    rq = SwiftProxyClusterRPC().stop_proxy_request(peers_only)
    for rid in rel_ids:
        relation_set(relation_id=rid, relation_settings=rq)


def notify_storage_rings_available():
    """Notify peer swift-storage relations that they should synchronise ring
    and builder files.

    Note that this should only be called from the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        log("Ring availability storage-relation broadcast requested by "
            "non-leader - skipping", level=WARNING)
        return

    hostname = get_hostaddr()
    hostname = format_ipv6_addr(hostname) or hostname
    path = os.path.basename(get_www_dir())
    rings_url = 'http://%s/%s' % (hostname, path)
    trigger = uuid.uuid4()
    # Notify storage nodes that there is a new ring to fetch.
    log("Notifying storage nodes that new ring is ready for sync.", level=INFO)
    for relid in relation_ids('swift-storage'):
        relation_set(relation_id=relid, swift_hash=get_swift_hash(),
                     rings_url=rings_url, trigger=trigger)


def fully_synced():
    """Check that we have all the rings and builders synced from the leader.

    Returns True if we have all rings and builders.
    """
    not_synced = []
    for ring, builder in SWIFT_RINGS.iteritems():
        if not os.path.exists(builder):
            not_synced.append(builder)

        ringfile = os.path.join(SWIFT_CONF_DIR,
                                '%s.%s' % (ring, SWIFT_RING_EXT))
        if not os.path.exists(ringfile):
            not_synced.append(ringfile)

    if not_synced:
        log("Not yet synced: %s" % ', '.join(not_synced), level=INFO)
        return False

    return True


def get_hostaddr():
    if config('prefer-ipv6'):
        return get_ipv6_addr(exc_list=[config('vip')])[0]

    return unit_get('private-address')


def is_paused(status_get=status_get):
    """Is the unit paused?"""
    status, message = status_get()
    return status == "maintenance" and message.startswith("Paused")


def pause_aware_restart_on_change(restart_map):
    """Avoids restarting services if config changes when unit is paused."""
    def wrapper(f):
        if is_paused():
            return f
        else:
            return restart_on_change(restart_map)(f)
    return wrapper


def has_minimum_zones(rings):
    """Determine if enough zones exist to satisfy minimum replicas"""
    for ring in rings:
        builder = _load_builder(ring).to_dict()
        replicas = builder['replicas']
        zones = [dev['zone'] for dev in builder['devs']]
        num_zones = len(set(zones))
        if num_zones < replicas:
            log("Not enough zones (%d) defined to satisfy minimum replicas "
                "(need >= %d)" % (num_zones, replicas), level=INFO)
            return False

    return True


def assess_status(configs):
    """Assess status of current unit"""
    required_interfaces = {}

    # Check for required swift-storage relation
    if len(relation_ids('swift-storage')) < 1:
        status_set('blocked', 'Missing relation: storage')
        return

    # Verify allowed_hosts is populated with enough unit IP addresses
    ctxt = SwiftRingContext()()
    if len(ctxt['allowed_hosts']) < config('replicas'):
        status_set('blocked', 'Not enough related storage nodes')
        return

    # Verify there are enough storage zones to satisfy minimum replicas
    rings = [r for r in SWIFT_RINGS.itervalues()]
    if not has_minimum_zones(rings):
        status_set('blocked', 'Not enough storage zones for minimum replicas')
        return

    if relation_ids('identity-service'):
        required_interfaces['identity'] = ['identity-service']

    if required_interfaces:
        set_os_workload_status(configs, required_interfaces)
    else:
        status_set('active', 'Unit is ready')

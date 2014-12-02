import os
import pwd
import shutil
import subprocess
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
    get_os_codename_package,
    get_os_codename_install_source,
    configure_installation_source
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    is_clustered,
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
)
from charmhelpers.fetch import (
    apt_update,
    apt_upgrade,
    apt_install,
    add_source
)
from charmhelpers.core.host import (
    lsb_release
)
from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
    get_ipv6_addr,
)


# Various config files that are managed via templating.
SWIFT_CONF = '/etc/swift/swift.conf'
SWIFT_PROXY_CONF = '/etc/swift/proxy-server.conf'
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


def get_www_dir():
    if os.path.isdir(os.path.dirname(ALTERNATE_WWW_DIR)):
        return ALTERNATE_WWW_DIR
    else:
        return WWW_DIR


SWIFT_RINGS = {
    'account': '/etc/swift/account.builder',
    'container': '/etc/swift/container.builder',
    'object': '/etc/swift/object.builder'
}

SSL_CERT = '/etc/swift/cert.crt'
SSL_KEY = '/etc/swift/cert.key'

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
        'hook_contexts': [context.HAProxyContext(),
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


class SwiftCharmException(Exception):
    pass


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
    pickle.dump(ring.to_dict(), open(ring_path, 'wb'), protocol=2)


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


def add_to_ring(ring_path, node):
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
        'device': node['device'],
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
        raise SwiftCharmException("Failed to set min_part_hours=%s on %s" %
                                  (value, path))


def get_zone(assignment_policy):
    """Determine the appropriate zone depending on configured assignment policy.

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
        raise Exception(msg)


def balance_ring(ring_path):
    """Balance a ring.  return True if it needs redistribution."""
    # shell out to swift-ring-builder instead, since the balancing code there
    # does a bunch of un-importable validation.'''
    cmd = ['swift-ring-builder', ring_path, 'rebalance']
    p = subprocess.Popen(cmd)
    p.communicate()
    rc = p.returncode
    if rc == 0:
        return True
    elif rc == 1:
        # Ring builder exit-code=1 is supposed to indicate warning but I have
        # noticed that it can also return 1 with the following sort of message:
        #
        #   NOTE: Balance of 166.67 indicates you should push this ring, wait
        #         at least 0 hours, and rebalance/repush.
        #
        # This indicates that a balance has occurred and a resync would be
        # required so not sure why 1 is returned in this case.
        return False
    else:
        msg = ('balance_ring: %s returned %s' % (cmd, rc))
        raise Exception(msg)


def should_balance(rings):
    """Based on zones vs min. replicas, determine whether or not the rings
    should be balanced during initial configuration.
    """
    for ring in rings:
        builder = _load_builder(ring).to_dict()
        replicas = builder['replicas']
        zones = [dev['zone'] for dev in builder['devs']]
        num_zones = len(set(zones))
        if num_zones < replicas:
            log("Not enough zones (%d) defined to allow rebalance "
                "(need >= %d)" % (num_zones, replicas), level=DEBUG)
            return False

    return True


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
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if ubuntu_rel < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # NOTE(xianghui): Need to install haproxy(1.5.3) from trusty-backports
    # to support ipv6 address, so check is required to make sure not
    # breaking other versions, IPv6 only support for >= Trusty
    if ubuntu_rel == 'trusty':
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports'
                   ' main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


def sync_proxy_rings(broker_url):
    """The leader proxy is responsible for intialising, updating and
    rebalancing the ring. Once the leader is ready the rings must then be
    synced into each other proxy unit.

    Note that we sync the ring builder and .gz files since the builder itself
    is linked to the underlying .gz ring.
    """
    log('Fetching swift rings & builders from proxy @ %s.' % broker_url,
        level=DEBUG)
    target = '/etc/swift'
    for server in ['account', 'object', 'container']:
        url = '%s/%s.builder' % (broker_url, server)
        log('Fetching %s.' % url, level=DEBUG)
        cmd = ['wget', url, '--retry-connrefused', '-t', '10', '-O',
               "%s/%s.builder" % (target, server)]
        subprocess.check_call(cmd)

        url = '%s/%s.ring.gz' % (broker_url, server)
        log('Fetching %s.' % url, level=DEBUG)
        cmd = ['wget', url, '--retry-connrefused', '-t', '10', '-O',
               '%s/%s.ring.gz' % (target, server)]
        subprocess.check_call(cmd)


def update_www_rings():
    """Copy rings to apache www dir."""
    www_dir = get_www_dir()
    for ring, builder_path in SWIFT_RINGS.iteritems():
        ringfile = '%s.ring.gz' % ring
        shutil.copyfile(os.path.join(SWIFT_CONF_DIR, ringfile),
                        os.path.join(www_dir, ringfile))
        shutil.copyfile(builder_path,
                        os.path.join(www_dir, os.path.basename(builder_path)))


def balance_rings():
    """Rebalance each ring and notify peers that new rings are available."""
    if not is_elected_leader(SWIFT_HA_RES):
        log("Balance rings called by non-leader - skipping", level=WARNING)
        return

    rebalanced = False
    for path in SWIFT_RINGS.itervalues():
        if balance_ring(path):
            log('Balanced ring %s' % path, level=DEBUG)
            rebalanced = True
        else:
            log('Ring %s not rebalanced' % path, level=DEBUG)

    if not rebalanced:
        log("Rings unchanged by rebalance", level=INFO)


def mark_www_rings_deleted():
    """Mark any rings from the apache server directory as deleted so that
    storage units won't see them.
    """
    www_dir = get_www_dir()
    for ring, _ in SWIFT_RINGS.iteritems():
        path = os.path.join(www_dir, '%s.ring.gz' % ring)
        if os.path.exists(path):
            os.rename(path, "%s.deleted" % (path))


def notify_peers_builders_available():
    """Notify peer swift-proxy peer units that they should synchronise ring and
    builder files.

    Note that this should only be called from the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        log("Ring availability peer broadcast requested by non-leader - "
            "skipping", level=WARNING)
        return

    if is_clustered():
        hostname = config('vip')
    else:
        hostname = get_hostaddr()

    hostname = format_ipv6_addr(hostname) or hostname
    # Notify peers that builders are available
    log("Notifying peer(s) that rings are ready for sync.", level=INFO)
    trigger = str(uuid.uuid4())
    for rid in relation_ids('cluster'):
        log("Notifying rid=%s" % (rid), level=DEBUG)
        # NOTE(dosaboy): we add some random data to the relation settings
        # otherwise subsequent calls will not fire (since hostname is always
        # the same).
        relation_set(relation_id=rid,
                     relation_settings={'trigger': trigger,
                                        'builder-broker': hostname,
                                        'disable-proxy-service': 0})


def broadcast_rings_available(peers=True, storage=True):
    if storage:
        # TODO: get ack from storage units that they are synced before
        # syncing proxies.
        notify_storage_rings_available()

    if peers:
        notify_peers_builders_available()


def cluster_sync_rings(peers_only=False):
    """Notify peer relations that they should disable their proxy services.

    Peer units will then be expected to do a relation_set with
    disable-proxy-service set 0. Once all peers have responded, the leader
    will send out notification to all relations that rings are available for
    sync.

    If peers_only is True, only peer units will be synced. This is typically
    used when only builder files have been changed.

    This should only be called by the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        # Only the leader can do this.
        return

    # If we have no peer units just go ahead and broadcast to storage
    # relations. If we have been instructed to only broadcast to peers, do
    # nothing.
    if not peer_units():
        if peers_only:
            broadcast_rings_available(peers=False)

        return

    log("Sending request to disable proxy service to all peers", level=INFO)
    rel_ids = relation_ids('cluster')
    trigger = str(uuid.uuid4())
    if peers_only:
        peers_only = 1
    else:
        peers_only = 0

    for rid in rel_ids:
        # NOTE: we set a trigger to ensure the hook is fired
        relation_set(relation_id=rid,
                     relation_settings={'trigger': trigger,
                                        'disable-proxy-service': 1,
                                        'peers-only': peers_only})


def notify_storage_rings_available():
    """Notify peer swift-storage relations that they should synchronise ring and
    builder files.

    Note that this should only be called from the leader unit.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        log("Ring availability storage-relation broadcast requested by "
            "non-leader - skipping", level=WARNING)
        return

    if is_clustered():
        hostname = config('vip')
    else:
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


def builders_synced():
    """Check that we have all the ring builders synced from the leader.

    Returns True if we have all ring builders.
    """
    for ring in SWIFT_RINGS.itervalues():
        if not os.path.exists(ring):
            log("Builder not yet synced - %s" % (ring), level=DEBUG)
            return False

    return True


def get_hostaddr():
    if config('prefer-ipv6'):
        return get_ipv6_addr(exc_list=[config('vip')])[0]

    return unit_get('private-address')


def update_min_part_hours():
    """Update the min_part_hours setting on swift rings.

    This should only be called by the leader unit. Once update has been
    performed and if setting has changed, rings will be resynced across the
    cluster.
    """
    if not is_elected_leader(SWIFT_HA_RES):
        # Only the leader can do this.
        return

    # NOTE: no need to stop the proxy since we are not changing the rings,
    # only the builder.

    new_min_part_hours = config('min-hours')
    resync_builders = False
    # Only update if all exist
    if all([os.path.exists(p) for p in SWIFT_RINGS.itervalues()]):
        for ring, path in SWIFT_RINGS.iteritems():
            min_part_hours = get_min_part_hours(path)
            if min_part_hours != new_min_part_hours:
                log("Setting ring %s min_part_hours to %s" %
                    (ring, new_min_part_hours), level=INFO)
                try:
                    set_min_part_hours(path, new_min_part_hours)
                except SwiftCharmException as exc:
                    # TODO: ignore for now since this should not be critical
                    # but in the future we should support a rollback.
                    log(str(exc), level=WARNING)
                else:
                    resync_builders = True

    if resync_builders:
        update_www_rings()
        cluster_sync_rings(peers_only=True)

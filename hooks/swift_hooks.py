#!/usr/bin/python

import os
import sys
import subprocess
import uuid

from swift_utils import (
    SwiftCharmException,
    register_configs,
    restart_map,
    determine_packages,
    ensure_swift_dir,
    SWIFT_RINGS,
    get_www_dir,
    initialize_ring,
    swift_user,
    SWIFT_HA_RES,
    get_zone,
    exists_in_ring,
    add_to_ring,
    should_balance,
    do_openstack_upgrade,
    setup_ipv6,
    balance_rings,
    builders_synced,
    sync_proxy_rings,
    update_min_part_hours,
    notify_storage_rings_available,
    notify_peers_builders_available,
    mark_www_rings_deleted,
    cluster_sync_rings,
)

import charmhelpers.contrib.openstack.utils as openstack
from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    is_crm_leader
)
from charmhelpers.core.hookenv import (
    config,
    unit_get,
    relation_set,
    relation_ids,
    relation_get,
    related_units,
    log,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    Hooks, UnregisteredHookError,
    open_port,
)
from charmhelpers.core.host import (
    service_restart,
    service_stop,
    service_start,
    restart_on_change,
)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC,
    INTERNAL,
    ADMIN,
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    get_address_in_network,
    get_ipv6_addr,
    is_ipv6,
)
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

extra_pkgs = [
    "haproxy",
    "python-jinja2"
]

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('install')
def install():
    execd_preinstall()
    src = config('openstack-origin')
    if src != 'distro':
        openstack.configure_installation_source(src)

    apt_update(fatal=True)
    rel = openstack.get_os_codename_install_source(src)
    pkgs = determine_packages(rel)
    apt_install(pkgs, fatal=True)
    apt_install(extra_pkgs, fatal=True)
    ensure_swift_dir()

    if is_elected_leader(SWIFT_HA_RES):
        log("Leader established, generating ring builders", level=INFO)
        # initialize new storage rings.
        for path in SWIFT_RINGS.itervalues():
            initialize_ring(path,
                            config('partition-power'),
                            config('replicas'),
                            config('min-hours'))

    # configure a directory on webserver for distributing rings.
    www_dir = get_www_dir()
    if not os.path.isdir(www_dir):
        os.mkdir(www_dir, 0o755)

    uid, gid = swift_user()
    os.chown(www_dir, uid, gid)


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if config('prefer-ipv6'):
        setup_ipv6()

    configure_https()
    open_port(config('bind-port'))

    # Determine whether or not we should do an upgrade.
    if openstack.openstack_upgrade_available('python-swift'):
        do_openstack_upgrade(CONFIGS)

    update_min_part_hours()

    if config('force-cluster-ring-sync'):
        log("Disabling peer proxy apis and syncing rings across cluster.")
        cluster_sync_rings()

    for r_id in relation_ids('identity-service'):
        keystone_joined(relid=r_id)


@hooks.hook('identity-service-relation-joined')
def keystone_joined(relid=None):
    if not is_elected_leader(SWIFT_HA_RES):
        return

    port = config('bind-port')
    admin_url = '%s:%s' % (canonical_url(CONFIGS, ADMIN), port)
    internal_url = '%s:%s/v1/AUTH_$(tenant_id)s' % \
        (canonical_url(CONFIGS, INTERNAL), port)
    public_url = '%s:%s/v1/AUTH_$(tenant_id)s' % \
        (canonical_url(CONFIGS, PUBLIC), port)
    relation_set(service='swift',
                 region=config('region'),
                 public_url=public_url,
                 internal_url=internal_url,
                 admin_url=admin_url,
                 requested_roles=config('operator-roles'),
                 relation_id=relid)


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map())
def keystone_changed():
    configure_https()


@hooks.hook('swift-storage-relation-joined')
def storage_joined():
    if not is_elected_leader(SWIFT_HA_RES):
        log("New storage relation joined - stopping proxy until ring builder "
            "synced", level=INFO)
        service_stop('swift-proxy')

        # Mark rings in the www directory as stale since this unit is no longer
        # responsible distributing rings but may become responsible again at
        # some time in the future so were do this to avoid storage nodes
        # getting out-of-date rings.
        mark_www_rings_deleted()


@hooks.hook('swift-storage-relation-changed')
@restart_on_change(restart_map())
def storage_changed():
    if not is_elected_leader(SWIFT_HA_RES):
        log("Not the leader - ignoring storage relation until leader ready.",
            level=DEBUG)
        return

    log("Leader established, updating ring builders", level=INFO)
    if config('prefer-ipv6'):
        host_ip = '[%s]' % relation_get('private-address')
    else:
        host_ip = openstack.get_host_ip(relation_get('private-address'))

    zone = get_zone(config('zone-assignment'))
    node_settings = {
        'ip': host_ip,
        'zone': zone,
        'account_port': relation_get('account_port'),
        'object_port': relation_get('object_port'),
        'container_port': relation_get('container_port'),
    }

    if None in node_settings.itervalues():
        missing = [k for k, v in node_settings.iteritems() if v is None]
        log("Relation not ready - some required values not provided by "
            "relation (missing=%s)" % (', '.join(missing)), level=INFO)
        return None

    for k in ['zone', 'account_port', 'object_port', 'container_port']:
        node_settings[k] = int(node_settings[k])

    CONFIGS.write_all()

    # Allow for multiple devs per unit, passed along as a : separated list
    devs = relation_get('device').split(':')
    for dev in devs:
        node_settings['device'] = dev
        for ring in SWIFT_RINGS.itervalues():
            if not exists_in_ring(ring, node_settings):
                add_to_ring(ring, node_settings)

    if should_balance([r for r in SWIFT_RINGS.itervalues()]):
        balance_rings()
        cluster_sync_rings()
        # Restart proxy here in case no config changes made (so
        # restart_on_change() ineffective).
        service_restart('swift-proxy')
    else:
        log("Not yet ready to balance rings - insufficient replicas?",
            level=INFO)


@hooks.hook('swift-storage-relation-broken')
@restart_on_change(restart_map())
def storage_broken():
    CONFIGS.write_all()


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    for addr_type in ADDRESS_TYPES:
        netaddr_cfg = 'os-{}-network'.format(addr_type)
        address = get_address_in_network(config(netaddr_cfg))
        if address:
            settings = {'{}-address'.format(addr_type): address}
            relation_set(relation_id=relation_id, relation_settings=settings)

    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_set(relation_id=relation_id,
                     relation_settings={'private-address': private_addr})
    else:
        private_addr = unit_get('private-address')


def all_responses_equal(responses, key):
    val = None
    for r in responses:
        if val and val != r[key]:
            log("Responses not all equal for key '%s'" % (key), level=DEBUG)
            return False
        else:
            val = r[key]

    return True


def all_peers_disabled(responses):
    """Establish whether all proxies have disables their apis.

    Each peer unit will set disable-proxy-service to 0 to indicate hat it has
    stopped its proxy service. We wait for all units to be stopped before
    triggering a sync. Peer services will be  restarted once their rings are
    synced with the leader.

    To be safe, default expectation is that api is still running.
    """
    key = 'disable-proxy-service'
    if not all_responses_equal(responses, key):
        return False

    rsp_int = [int(d) for d in responses.get(key, 1)]
    # Ensure all 0 and all the same
    if any(rsp_int):
        return False

    return True


def cluster_leader_actions():
    """Cluster relation hook actions to be performed by leader units."""
    # Find out if all peer units have been disabled.
    responses = []
    units = 0
    for rid in relation_ids('cluster'):
        for unit in related_units(rid):
            units += 1
            responses.append(relation_get(rid=rid, unit=unit))

    # Ensure all peers stopped before starting sync
    if all_peers_disabled(responses):
        log("Syncing rings and builders across %s peer units" % (units),
            level=DEBUG)

        key = 'peers-only'
        if all_responses_equal(responses, key):
            peers_only = responses[key]
            msg = ("Did not get equal responses from each peer unit for '%s'" %
                   (key))
            raise SwiftCharmException(msg)
        else:
            peers_only = False

        if not peers_only:
            # TODO: get ack from storage units that they are synced before
            # syncing proxies.
            notify_storage_rings_available()

        notify_peers_builders_available()
    else:
        log("Not all apis disabled - skipping sync until all peers ready "
            "(got %s)" % (responses), level=INFO)

    CONFIGS.write_all()


def cluster_non_leader_actions():
    """Cluster relation hook actions to be performed by non-leader units."""
    settings = relation_get()

    # Check whether we have been requested to stop proxy service
    if int(settings.get('disable-proxy-service', 0)):
        log("Peer request to disable proxy api received", level=INFO)
        service_stop('swift-proxy')
        trigger = str(uuid.uuid4())
        relation_set(relation_settings={'trigger': trigger,
                                        'disable-proxy-service': 0})
        return

    # Check if there are any builder files we can sync from the leader.
    log("Non-leader peer - checking if updated rings available", level=DEBUG)
    broker = settings.get('builder-broker', None)
    if not broker:
        log("No update available", level=DEBUG)
        return

    path = os.path.basename(get_www_dir())
    try:
        sync_proxy_rings('http://%s/%s' % (broker, path))
    except subprocess.CalledProcessError:
        log("Ring builder sync failed, builders not yet available - "
            "leader not ready?", level=WARNING)
        return None

    # Re-enable the proxy once all builders are synced
    if builders_synced():
        log("Ring builders synced - starting proxy", level=INFO)
        CONFIGS.write_all()
        service_start('swift-proxy')
    else:
        log("Not all builders synced yet - waiting for peer sync before "
            "starting proxy", level=INFO)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map())
def cluster_changed():
    if is_elected_leader(SWIFT_HA_RES):
        cluster_leader_actions()
    else:
        cluster_non_leader_actions()


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if clustered and is_crm_leader(SWIFT_HA_RES):
        log("Cluster configured, notifying other services and updating "
            "keystone endpoint configuration", level=INFO)
        # Tell all related services to start using
        # the VIP instead
        for r_id in relation_ids('identity-service'):
            keystone_joined(relid=r_id)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    # Obtain the config values necessary for the cluster config. These
    # include multicast port and interface to bind to.
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')
    vip = config('vip')
    if not vip:
        log('Unable to configure hacluster as vip not provided', level=ERROR)
        sys.exit(1)

    # Obtain resources
    resources = {'res_swift_haproxy': 'lsb:haproxy'}
    resource_params = {'res_swift_haproxy': 'op monitor interval="5s"'}

    vip_group = []
    for vip in vip.split():
        if is_ipv6(vip):
            res_swift_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_swift_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = get_iface_for_address(vip)
        if iface is not None:
            vip_key = 'res_swift_{}_vip'.format(iface)
            resources[vip_key] = res_swift_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=get_netmask_for_address(vip))
            )
            vip_group.append(vip_key)

    if len(vip_group) >= 1:
        relation_set(groups={'grp_swift_vips': ' '.join(vip_group)})

    init_services = {'res_swift_haproxy': 'haproxy'}
    clones = {'cl_swift_haproxy': 'res_swift_haproxy'}

    relation_set(init_services=init_services,
                 corosync_bindiface=corosync_bindiface,
                 corosync_mcastport=corosync_mcastport,
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


def configure_https():
    """Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    """
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        subprocess.check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        subprocess.check_call(cmd)

    # Apache 2.4 required enablement of configuration
    if os.path.exists('/usr/sbin/a2enconf'):
        subprocess.check_call(['a2enconf', 'swift-rings'])

    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)

    env_vars = {'OPENSTACK_SERVICE_SWIFT': 'proxy-server',
                'OPENSTACK_PORT_API': config('bind-port'),
                'OPENSTACK_PORT_MEMCACHED': 11211}
    openstack.save_script_rc(**env_vars)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e), level=DEBUG)


if __name__ == '__main__':
    main()

#!/usr/bin/python

import os
import sys
import shutil
import uuid
import subprocess

import charmhelpers.contrib.openstack.utils as openstack
import charmhelpers.contrib.hahelpers.cluster as cluster
from swift_utils import (
    register_configs,
    restart_map,
    services,
    determine_packages,
    ensure_swift_dir,
    SWIFT_RINGS, get_www_dir,
    initialize_ring,
    swift_user,
    SWIFT_HA_RES,
    balance_ring,
    SWIFT_CONF_DIR,
    get_zone,
    exists_in_ring,
    add_to_ring,
    should_balance,
    do_openstack_upgrade,
    write_rc_script,
    setup_ipv6
)
from swift_context import get_swift_hash

from charmhelpers.core.hookenv import (
    config,
    unit_get,
    relation_set,
    relation_ids,
    relation_get,
    relations_of_type,
    local_unit,
    log, ERROR,
    Hooks, UnregisteredHookError,
    open_port
)
from charmhelpers.core.host import (
    service_restart,
    restart_on_change
)
from charmhelpers.fetch import (
    apt_install,
    apt_update
)
from charmhelpers.payload.execd import execd_preinstall

from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    get_address_in_network,
    get_ipv6_addr,
    format_ipv6_addr,
    is_ipv6
)

from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport.nrpe import NRPE

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
    # initialize new storage rings.
    for ring in SWIFT_RINGS.iteritems():
        initialize_ring(ring[1],
                        config('partition-power'),
                        config('replicas'),
                        config('min-hours'))

    # configure a directory on webserver for distributing rings.
    www_dir = get_www_dir()
    if not os.path.isdir(www_dir):
        os.mkdir(www_dir, 0o755)
    uid, gid = swift_user()
    os.chown(www_dir, uid, gid)


@hooks.hook('identity-service-relation-joined')
def keystone_joined(relid=None):
    if not cluster.eligible_leader(SWIFT_HA_RES):
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


def balance_rings():
    '''handle doing ring balancing and distribution.'''
    new_ring = False
    for ring in SWIFT_RINGS.itervalues():
        if balance_ring(ring):
            log('Balanced ring %s' % ring)
            new_ring = True
    if not new_ring:
        return

    www_dir = get_www_dir()
    for ring in SWIFT_RINGS.keys():
        f = '%s.ring.gz' % ring
        shutil.copyfile(os.path.join(SWIFT_CONF_DIR, f),
                        os.path.join(www_dir, f))

    if cluster.eligible_leader(SWIFT_HA_RES):
        msg = 'Broadcasting notification to all storage nodes that new '\
              'ring is ready for consumption.'
        log(msg)
        path = os.path.basename(www_dir)
        trigger = uuid.uuid4()

        if cluster.is_clustered():
            hostname = config('vip')
        elif config('prefer-ipv6'):
            hostname = get_ipv6_addr(exc_list=[config('vip')])[0]
        else:
            hostname = unit_get('private-address')

        hostname = format_ipv6_addr(hostname) or hostname
        rings_url = 'http://%s/%s' % (hostname, path)
        # notify storage nodes that there is a new ring to fetch.
        for relid in relation_ids('swift-storage'):
            relation_set(relation_id=relid, swift_hash=get_swift_hash(),
                         rings_url=rings_url, trigger=trigger)

    service_restart('swift-proxy')


@hooks.hook('swift-storage-relation-changed')
@restart_on_change(restart_map())
def storage_changed():
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
        log('storage_changed: Relation not ready.')
        return None

    for k in ['zone', 'account_port', 'object_port', 'container_port']:
        node_settings[k] = int(node_settings[k])

    CONFIGS.write_all()

    # allow for multiple devs per unit, passed along as a : separated list
    devs = relation_get('device').split(':')
    for dev in devs:
        node_settings['device'] = dev
        for ring in SWIFT_RINGS.itervalues():
            if not exists_in_ring(ring, node_settings):
                add_to_ring(ring, node_settings)

    if should_balance([r for r in SWIFT_RINGS.itervalues()]):
        balance_rings()


@hooks.hook('swift-storage-relation-broken')
@restart_on_change(restart_map())
def storage_broken():
    CONFIGS.write_all()


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if config('prefer-ipv6'):
        setup_ipv6()

    configure_https()
    open_port(config('bind-port'))
    update_nrpe_config()
    # Determine whether or not we should do an upgrade, based on the
    # the version offered in keyston-release.
    if (openstack.openstack_upgrade_available('python-swift')):
        do_openstack_upgrade(CONFIGS)
    for r_id in relation_ids('identity-service'):
        keystone_joined(relid=r_id)
    [cluster_joined(rid) for rid in relation_ids('cluster')]


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    for addr_type in ADDRESS_TYPES:
        address = get_address_in_network(
            config('os-{}-network'.format(addr_type))
        )
        if address:
            relation_set(
                relation_id=relation_id,
                relation_settings={'{}-address'.format(addr_type): address}
            )
    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_set(relation_id=relation_id,
                     relation_settings={'private-address': private_addr})


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map())
def cluster_changed():
    CONFIGS.write_all()


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if clustered and cluster.is_leader(SWIFT_HA_RES):
        log('Cluster configured, notifying other services and'
            'updating keystone endpoint configuration')
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
        log('Unable to configure hacluster as vip not provided',
            level=ERROR)
        sys.exit(1)

    # Obtain resources
    resources = {
        'res_swift_haproxy': 'lsb:haproxy'
    }
    resource_params = {
        'res_swift_haproxy': 'op monitor interval="5s"'
    }

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

    init_services = {
        'res_swift_haproxy': 'haproxy'
    }
    clones = {
        'cl_swift_haproxy': 'res_swift_haproxy'
    }

    relation_set(init_services=init_services,
                 corosync_bindiface=corosync_bindiface,
                 corosync_mcastport=corosync_mcastport,
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
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

    write_rc_script()


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    apt_install('python-dbus')
    # Find out if nrpe set nagios_hostname
    hostname = None
    host_context = None
    for rel in relations_of_type('nrpe-external-master'):
        if 'nagios_hostname' in rel:
            hostname = rel['nagios_hostname']
            host_context = rel['nagios_host_context']
            break
    nrpe = NRPE(hostname=hostname)

    if host_context:
        current_unit = "%s:%s" % (host_context, local_unit())
    else:
        current_unit = local_unit()

    services_to_monitor = services()
    for service in services_to_monitor:
        upstart_init = '/etc/init/%s.conf' % service
        sysv_init = '/etc/init.d/%s' % service

        if os.path.exists(upstart_init):
            nrpe.add_check(
                shortname=service,
                description='process check {%s}' % current_unit,
                check_cmd='check_upstart_job %s' % service,
                )
        elif os.path.exists(sysv_init):
            cronpath = '/etc/cron.d/nagios-service-check-%s' % service
            checkpath = os.path.join(os.environ['CHARM_DIR'],
                                     'files/nrpe-external-master',
                                     'check_exit_status.pl'),
            cron_template = '*/5 * * * * root %s -s \
/etc/init.d/%s status > /var/lib/nagios/service-check-%s.txt\n' \
                % (checkpath[0], service, service)
            f = open(cronpath, 'w')
            f.write(cron_template)
            f.close()
            nrpe.add_check(
                shortname=service,
                description='process check {%s}' % current_unit,
                check_cmd='check_status_file.py -f \
/var/lib/nagios/service-check-%s.txt' % service,
                )

    nrpe.write()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()

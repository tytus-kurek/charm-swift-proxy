#!/usr/bin/python

import amulet
import swiftclient

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG, # flake8: noqa
    ERROR
)

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(ERROR)


class SwiftProxyBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic swift-proxy deployment."""

    def __init__(self, series, openstack=None, source=None, stable=False):
        """Deploy the entire test environment."""
        super(SwiftProxyBasicDeployment, self).__init__(series, openstack,
                                                        source, stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where swift-proxy is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'swift-proxy'}
        other_services = [{'name': 'mysql'}, {'name': 'keystone'},
                          {'name': 'glance'}, {'name': 'swift-storage'}]
        super(SwiftProxyBasicDeployment, self)._add_services(this_service,
                                                             other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
          'keystone:shared-db': 'mysql:shared-db',
          'swift-proxy:identity-service': 'keystone:identity-service',
          'swift-storage:swift-storage': 'swift-proxy:swift-storage',
          'glance:identity-service': 'keystone:identity-service',
          'glance:shared-db': 'mysql:shared-db',
          'glance:object-store': 'swift-proxy:object-store'
        }
        super(SwiftProxyBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        swift_proxy_config = {'zone-assignment': 'manual',
                           'replicas': '1',
                           'swift-hash': 'fdfef9d4-8b06-11e2-8ac0-531c923c8fae'}
        swift_storage_config = {'zone': '1',
                                'block-device': 'vdb',
                                'overwrite': 'true'}
        configs = {'keystone': keystone_config,
                   'swift-proxy': swift_proxy_config,
                   'swift-storage': swift_storage_config}
        super(SwiftProxyBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.glance_sentry = self.d.sentry.unit['glance/0']
        self.swift_proxy_sentry = self.d.sentry.unit['swift-proxy/0']
        self.swift_storage_sentry = self.d.sentry.unit['swift-storage/0']

        # Authenticate admin with keystone
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with glance endpoint
        self.glance = u.authenticate_glance_admin(self.keystone)

        # Authenticate swift user
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        ep = self.keystone.service_catalog.url_for(service_type='identity',
                                                   endpoint_type='publicURL')
        self.swift = swiftclient.Connection(authurl=ep,
                                user=keystone_relation['service_username'],
                                key=keystone_relation['service_password'],
                                tenant_name=keystone_relation['service_tenant'],
                                auth_version='2.0')

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)
            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user,
                                       password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

        # Authenticate demo user with keystone
        self.keystone_demo = \
            u.authenticate_keystone_user(self.keystone, user=self.demo_user,
                                         password='password',
                                         tenant=self.demo_tenant)

    def test_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        swift_storage_services = ['status swift-account',
                                  'status swift-account-auditor',
                                  'status swift-account-reaper',
                                  'status swift-account-replicator',
                                  'status swift-container',
                                  'status swift-container-auditor',
                                  'status swift-container-replicator',
                                  'status swift-container-updater',
                                  'status swift-object',
                                  'status swift-object-auditor',
                                  'status swift-object-replicator',
                                  'status swift-object-updater']
        if self._get_openstack_release() >= self.precise_icehouse:
            swift_storage_services.append('status swift-container-sync')

        commands = {
            self.mysql_sentry: ['status mysql'],
            self.keystone_sentry: ['status keystone'],
            self.glance_sentry: ['status glance-registry', 'status glance-api'],
            self.swift_proxy_sentry: ['status swift-proxy'],
            self.swift_storage_sentry: swift_storage_services
        }

        ret = u.validate_services(commands)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_users(self):
        """Verify all existing roles."""
        user1 = {'name': 'demoUser',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': 'demo@demo.com'}
        user2 = {'name': 'admin',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': 'juju@localhost'}
        user3 = {'name': 'glance',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': u'juju@localhost'}
        user4 = {'name': 'swift',
                 'enabled': True,
                 'tenantId': u.not_null,
                 'id': u.not_null,
                 'email': u'juju@localhost'}
        expected = [user1, user2, user3, user4]
        actual = self.keystone.users.list()

        ret = u.validate_user_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}
        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}
        if self._get_openstack_release() >= self.precise_folsom:
            endpoint_vol['id'] = u.not_null
            endpoint_id['id'] = u.not_null
        expected = {'image': [endpoint_id], 'object-store': [endpoint_id],
                    'identity': [endpoint_id]}
        actual = self.keystone_demo.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_openstack_object_store_endpoint(self):
        """Verify the swift object-store endpoint data."""
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8080'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'object-store endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_swift_proxy_identity_service_relation(self):
        """Verify the swift-proxy to keystone identity-service relation data."""
        unit = self.swift_proxy_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'service': 'swift',
            'region': 'RegionOne',
            'public_url': u.valid_url,
            'internal_url': u.valid_url,
            'private-address': u.valid_ip,
            'requested_roles': 'Member,Admin',
            'admin_url': u.valid_url
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('swift-proxy identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_keystone_identity_service_relation(self):
        """Verify the keystone to swift-proxy identity-service relation data."""
        unit = self.keystone_sentry
        relation = ['identity-service', 'swift-proxy:identity-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'admin_token': 'ubuntutesting',
            'service_password': u.not_null,
            'service_port': '5000',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'https_keystone': 'False',
            'auth_host': u.valid_ip,
            'service_username': 'swift',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_swift_storage_swift_storage_relation(self):
        """Verify the swift-storage to swift-proxy swift-storage relation
           data."""
        unit = self.swift_storage_sentry
        relation = ['swift-storage', 'swift-proxy:swift-storage']
        expected = {
            'account_port': '6002',
            'zone': '1',
            'object_port': '6000',
            'container_port': '6001',
            'private-address': u.valid_ip,
            'device': 'vdb'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('swift-storage swift-storage', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_swift_proxy_swift_storage_relation(self):
        """Verify the swift-proxy to swift-storage swift-storage relation
           data."""
        unit = self.swift_proxy_sentry
        relation = ['swift-storage', 'swift-storage:swift-storage']
        expected = {
            'private-address': u.valid_ip,
            'trigger': u.not_null,
            'rings_url': u.valid_url,
            'swift_hash': u.not_null
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('swift-proxy swift-storage', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_glance_object_store_relation(self):
        """Verify the glance to swift-proxy object-store relation data."""
        unit = self.glance_sentry
        relation = ['object-store', 'swift-proxy:object-store']
        expected = { 'private-address': u.valid_ip }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('glance object-store', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_swift_proxy_object_store_relation(self):
        """Verify the swift-proxy to glance object-store relation data."""
        unit = self.swift_proxy_sentry
        relation = ['object-store', 'glance:object-store']
        expected = {'private-address': u.valid_ip}
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('swift-proxy object-store', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_z_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed.

           Note(coreycb): The method name with the _z_ is a little odd
           but it forces the test to run last.  It just makes things
           easier because restarting services requires re-authorization.
           """
        svc = 'swift-proxy'
        self.d.configure('swift-proxy', {'node-timeout': '90'})

        if not u.service_restarted(self.swift_proxy_sentry, svc,
                                   '/etc/swift/proxy-server.conf'):
            self.d.configure('swift-proxy', {'node-timeout': '60'})
            msg = "service {} didn't restart after config change".format(svc)
            amulet.raise_status(amulet.FAIL, msg=msg)

        self.d.configure('swift-proxy', {'node-timeout': '60'})

    def test_swift_config(self):
        """Verify the data in the swift config file."""
        unit = self.swift_proxy_sentry
        conf = '/etc/swift/swift.conf'
        swift_proxy_relation = unit.relation('swift-storage',
                                             'swift-storage:swift-storage')
        expected = {
            'swift_hash_path_suffix': swift_proxy_relation['swift_hash']
        }

        ret = u.validate_config_data(unit, conf, 'swift-hash', expected)
        if ret:
            message = "swift config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_proxy_server_icehouse_config(self):
        """Verify the data in the proxy-server config file."""
        if self._get_openstack_release() < self.precise_icehouse:
            return

        unit = self.swift_proxy_sentry
        conf = '/etc/swift/proxy-server.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        swift_proxy_relation = unit.relation('identity-service',
                                             'keystone:identity-service')
        swift_proxy_ip = swift_proxy_relation['private-address']
        auth_host = keystone_relation['auth_host']
        auth_protocol = keystone_relation['auth_protocol']

        expected = {
            'DEFAULT': {
                'bind_port': '8070',
                'user': 'swift'
            },
            'pipeline:main': {
                'pipeline': 'gatekeeper healthcheck cache swift3 s3token '
                            'container_sync bulk tempurl slo dlo formpost '
                            'authtoken keystoneauth staticweb '
                            'container-quotas account-quotas proxy-server'
            },
            'app:proxy-server': {
                'use': 'egg:swift#proxy',
                'allow_account_management': 'true',
                'account_autocreate': 'true',
                'node_timeout': '60',
                'recoverable_node_timeout': '30'
            },
            'filter:tempauth': {
                'use': 'egg:swift#tempauth',
                'user_system_root': 'testpass .admin https://{}:8080/v1/'
                                    'AUTH_system'.format(swift_proxy_ip)
            },
            'filter:healthcheck': {'use': 'egg:swift#healthcheck'},
            'filter:cache': {
                'use': 'egg:swift#memcache',
                'memcache_servers': '{}:11211'.format(swift_proxy_ip)
            },
            'filter:account-quotas': {'use': 'egg:swift#account_quotas'},
            'filter:container-quotas': {'use': 'egg:swift#container_quotas'},
            'filter:staticweb': {'use': 'egg:swift#staticweb'},
            'filter:bulk': {'use': 'egg:swift#bulk'},
            'filter:slo': {'use': 'egg:swift#slo'},
            'filter:dlo': {'use': 'egg:swift#dlo'},
            'filter:formpost': {'use': 'egg:swift#formpost'},
            'filter:tempurl': {'use': 'egg:swift#tempurl'},
            'filter:container_sync': {'use': 'egg:swift#container_sync'},
            'filter:gatekeeper': {'use': 'egg:swift#gatekeeper'},
            'filter:keystoneauth': {
                'use': 'egg:swift#keystoneauth',
                'operator_roles': 'Member,Admin'
            },
            'filter:authtoken': {
                'paste.filter_factory': 'keystoneclient.middleware.'
                                        'auth_token:filter_factory',
                'auth_host': auth_host,
                'auth_port': keystone_relation['auth_port'],
                'auth_protocol': auth_protocol,
                'auth_uri': '{}://{}:{}'.format(auth_protocol, auth_host,
                                             keystone_relation['service_port']),
                'admin_tenant_name': keystone_relation['service_tenant'],
                'admin_user': keystone_relation['service_username'],
                'admin_password': keystone_relation['service_password'],
                'delay_auth_decision': 'true',
                'signing_dir': '/var/cache/swift',
                'cache': 'swift.cache'
            },
            'filter:s3token': {
                'paste.filter_factory': 'keystoneclient.middleware.'
                                        's3_token:filter_factory',
                'service_host': keystone_relation['service_host'],
                'service_port': keystone_relation['service_port'],
                'auth_port': keystone_relation['auth_port'],
                'auth_host': keystone_relation['auth_host'],
                'auth_protocol': keystone_relation['auth_protocol'],
                'auth_token': keystone_relation['admin_token'],
                'admin_token': keystone_relation['admin_token']
            },
            'filter:swift3': {'use': 'egg:swift3#swift3'}
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "proxy-server config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_proxy_server_havana_config(self):
        """Verify the data in the proxy-server config file."""
        if self._get_openstack_release() != self.precise_havana:
            return

        unit = self.swift_proxy_sentry
        conf = '/etc/swift/proxy-server.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        swift_proxy_relation = unit.relation('identity-service',
                                             'keystone:identity-service')
        swift_proxy_ip = swift_proxy_relation['private-address']
        auth_host = keystone_relation['auth_host']
        auth_protocol = keystone_relation['auth_protocol']

        expected = {
            'DEFAULT': {
                'bind_port': '8070',
                'user': 'swift'
            },
            'pipeline:main': {
                'pipeline': 'healthcheck cache swift3 authtoken '
                            'keystoneauth container-quotas account-quotas '
                            'proxy-server'
            },
            'app:proxy-server': {
                'use': 'egg:swift#proxy',
                'allow_account_management': 'true',
                'account_autocreate': 'true',
                'node_timeout': '60',
                'recoverable_node_timeout': '30'
            },
            'filter:tempauth': {
                'use': 'egg:swift#tempauth',
                'user_system_root': 'testpass .admin https://{}:8080/v1/'
                                    'AUTH_system'.format(swift_proxy_ip)
            },
            'filter:healthcheck': {'use': 'egg:swift#healthcheck'},
            'filter:cache': {
                'use': 'egg:swift#memcache',
                'memcache_servers': '{}:11211'.format(swift_proxy_ip)
            },
            'filter:account-quotas': {'use': 'egg:swift#account_quotas'},
            'filter:container-quotas': {'use': 'egg:swift#container_quotas'},
            'filter:keystoneauth': {
                'use': 'egg:swift#keystoneauth',
                'operator_roles': 'Member,Admin'
            },
            'filter:authtoken': {
                'paste.filter_factory': 'keystoneclient.middleware.'
                                        'auth_token:filter_factory',
                'auth_host': auth_host,
                'auth_port': keystone_relation['auth_port'],
                'auth_protocol': auth_protocol,
                'auth_uri': '{}://{}:{}'.format(auth_protocol, auth_host,
                                             keystone_relation['service_port']),
                'admin_tenant_name': keystone_relation['service_tenant'],
                'admin_user': keystone_relation['service_username'],
                'admin_password': keystone_relation['service_password'],
                'delay_auth_decision': 'true',
                'signing_dir': '/var/cache/swift',
                'cache': 'swift.cache'
            },
            'filter:s3token': {
                'paste.filter_factory': 'keystone.middleware.s3_token:'
                                        'filter_factory',
                'service_host': keystone_relation['service_host'],
                'service_port': keystone_relation['service_port'],
                'auth_port': keystone_relation['auth_port'],
                'auth_host': keystone_relation['auth_host'],
                'auth_protocol': keystone_relation['auth_protocol'],
                'auth_token': keystone_relation['admin_token'],
                'admin_token': keystone_relation['admin_token'],
                'service_protocol': keystone_relation['service_protocol']
            },
            'filter:swift3': {'use': 'egg:swift3#swift3'}
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "proxy-server config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_proxy_server_grizzly_config(self):
        """Verify the data in the proxy-server config file."""
        if self._get_openstack_release() != self.precise_grizzly:
            return

        unit = self.swift_proxy_sentry
        conf = '/etc/swift/proxy-server.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        swift_proxy_relation = unit.relation('identity-service',
                                             'keystone:identity-service')
        swift_proxy_ip = swift_proxy_relation['private-address']
        auth_host = keystone_relation['auth_host']
        auth_protocol = keystone_relation['auth_protocol']

        expected = {
            'DEFAULT': {
                'bind_port': '8070',
                'user': 'swift'
            },
            'pipeline:main': {
                'pipeline': 'healthcheck cache swift3 s3token authtoken '
                            'keystone container-quotas account-quotas '
                            'proxy-server'
            },
            'app:proxy-server': {
                'use': 'egg:swift#proxy',
                'allow_account_management': 'true',
                'account_autocreate': 'true',
                'node_timeout': '60',
                'recoverable_node_timeout': '30'
            },
            'filter:tempauth': {
                'use': 'egg:swift#tempauth',
                'user_system_root': 'testpass .admin https://{}:8080/v1/'
                                    'AUTH_system'.format(swift_proxy_ip)
            },
            'filter:healthcheck': {'use': 'egg:swift#healthcheck'},
            'filter:cache': {
                'use': 'egg:swift#memcache',
                'memcache_servers': '{}:11211'.format(swift_proxy_ip)
            },
            'filter:account-quotas': {'use': 'egg:swift#account_quotas'},
            'filter:container-quotas': {'use': 'egg:swift#container_quotas'},
            'filter:keystone': {
                'paste.filter_factory': 'swift.common.middleware.'
                                        'keystoneauth:filter_factory',
                'operator_roles': 'Member,Admin'
            },
            'filter:authtoken': {
                'paste.filter_factory': 'keystone.middleware.auth_token:'
                                        'filter_factory',
                'auth_host': auth_host,
                'auth_port': keystone_relation['auth_port'],
                'auth_protocol': auth_protocol,
                'auth_uri': '{}://{}:{}'.format(auth_protocol, auth_host,
                                             keystone_relation['service_port']),
                'admin_tenant_name': keystone_relation['service_tenant'],
                'admin_user': keystone_relation['service_username'],
                'admin_password': keystone_relation['service_password'],
                'delay_auth_decision': 'true',
                'signing_dir': '/var/cache/swift'
            },
            'filter:s3token': {
                'paste.filter_factory': 'keystone.middleware.s3_token:'
                                        'filter_factory',
                'service_host': keystone_relation['service_host'],
                'service_port': keystone_relation['service_port'],
                'auth_port': keystone_relation['auth_port'],
                'auth_host': keystone_relation['auth_host'],
                'auth_protocol': keystone_relation['auth_protocol'],
                'auth_token': keystone_relation['admin_token'],
                'admin_token': keystone_relation['admin_token'],
                'service_protocol': keystone_relation['service_protocol']
            },
            'filter:swift3': {'use': 'egg:swift3#swift3'}
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "proxy-server config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_proxy_server_folsom_config(self):
        """Verify the data in the proxy-server config file."""
        if self._get_openstack_release() != self.precise_folsom:
            return

        unit = self.swift_proxy_sentry
        conf = '/etc/swift/proxy-server.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        swift_proxy_relation = unit.relation('identity-service',
                                             'keystone:identity-service')
        swift_proxy_ip = swift_proxy_relation['private-address']
        auth_host = keystone_relation['auth_host']
        auth_protocol = keystone_relation['auth_protocol']

        expected = {
            'DEFAULT': {
                'bind_port': '8070',
                'user': 'swift'
            },
            'pipeline:main': {
                'pipeline': 'healthcheck cache swift3 s3token authtoken '
                            'keystone proxy-server'
            },
            'app:proxy-server': {
                'use': 'egg:swift#proxy',
                'allow_account_management': 'true',
                'account_autocreate': 'true',
                'node_timeout': '60',
                'recoverable_node_timeout': '30'
            },
            'filter:tempauth': {
                'use': 'egg:swift#tempauth',
                'user_system_root': 'testpass .admin https://{}:8080/v1/'
                                    'AUTH_system'.format(swift_proxy_ip)
            },
            'filter:healthcheck': {'use': 'egg:swift#healthcheck'},
            'filter:cache': {
                'use': 'egg:swift#memcache',
                'memcache_servers': '{}:11211'.format(swift_proxy_ip)
            },
            'filter:keystone': {
                'paste.filter_factory': 'keystone.middleware.swift_auth:'
                                        'filter_factory',
                'operator_roles': 'Member,Admin'
            },
            'filter:authtoken': {
                'paste.filter_factory': 'keystone.middleware.auth_token:'
                                        'filter_factory',
                'auth_host': auth_host,
                'auth_port': keystone_relation['auth_port'],
                'auth_protocol': auth_protocol,
                'auth_uri': '{}://{}:{}'.format(auth_protocol, auth_host,
                                             keystone_relation['service_port']),
                'admin_tenant_name': keystone_relation['service_tenant'],
                'admin_user': keystone_relation['service_username'],
                'admin_password': keystone_relation['service_password'],
                'delay_auth_decision': '1'
            },
            'filter:s3token': {
                'paste.filter_factory': 'keystone.middleware.s3_token:'
                                        'filter_factory',
                'service_host': keystone_relation['service_host'],
                'service_port': keystone_relation['service_port'],
                'auth_port': keystone_relation['auth_port'],
                'auth_host': keystone_relation['auth_host'],
                'auth_protocol': keystone_relation['auth_protocol'],
                'auth_token': keystone_relation['admin_token'],
                'admin_token': keystone_relation['admin_token'],
                'service_protocol': keystone_relation['service_protocol']
            },
            'filter:swift3': {'use': 'egg:swift#swift3'}
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "proxy-server config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_proxy_server_essex_config(self):
        """Verify the data in the proxy-server config file."""
        if self._get_openstack_release() != self.precise_essex:
            return

        unit = self.swift_proxy_sentry
        conf = '/etc/swift/proxy-server.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                                 'swift-proxy:identity-service')
        swift_proxy_relation = unit.relation('identity-service',
                                             'keystone:identity-service')
        swift_proxy_ip = swift_proxy_relation['private-address']
        auth_host = keystone_relation['auth_host']
        auth_protocol = keystone_relation['auth_protocol']

        expected = {
            'DEFAULT': {
                'bind_port': '8070',
                'user': 'swift'
            },
            'pipeline:main': {
                'pipeline': 'healthcheck cache swift3 s3token authtoken '
                            'keystone proxy-server'
            },
            'app:proxy-server': {
                'use': 'egg:swift#proxy',
                'allow_account_management': 'true',
                'account_autocreate': 'true',
                'node_timeout': '60',
                'recoverable_node_timeout': '30'
            },
            'filter:tempauth': {
                'use': 'egg:swift#tempauth',
                'user_system_root': 'testpass .admin https://{}:8080/v1/'
                                    'AUTH_system'.format(swift_proxy_ip)
            },
            'filter:healthcheck': {'use': 'egg:swift#healthcheck'},
            'filter:cache': {
                'use': 'egg:swift#memcache',
                'memcache_servers': '{}:11211'.format(swift_proxy_ip)
            },
            'filter:keystone': {
                'paste.filter_factory': 'keystone.middleware.swift_auth:'
                                        'filter_factory',
                'operator_roles': 'Member,Admin'
            },
            'filter:authtoken': {
                'paste.filter_factory': 'keystone.middleware.auth_token:'
                                        'filter_factory',
                'auth_host': auth_host,
                'auth_port': keystone_relation['auth_port'],
                'auth_protocol': auth_protocol,
                'auth_uri': '{}://{}:{}'.format(auth_protocol, auth_host,
                                         keystone_relation['service_port']),
                'admin_tenant_name': keystone_relation['service_tenant'],
                'admin_user': keystone_relation['service_username'],
                'admin_password': keystone_relation['service_password'],
                'delay_auth_decision': '1'
            },
            'filter:s3token': {
                'paste.filter_factory': 'keystone.middleware.s3_token:'
                                        'filter_factory',
                'service_host': keystone_relation['service_host'],
                'service_port': keystone_relation['service_port'],
                'auth_port': keystone_relation['auth_port'],
                'auth_host': keystone_relation['auth_host'],
                'auth_protocol': keystone_relation['auth_protocol'],
                'auth_token': keystone_relation['admin_token'],
                'admin_token': keystone_relation['admin_token'],
                'service_protocol': keystone_relation['service_protocol']
            },
            'filter:swift3': {'use': 'egg:swift#swift3'}
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "proxy-server config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_image_create(self):
        """Create an instance in glance, which is backed by swift, and validate
           that some of the metadata for the image match in glance and swift."""
        # NOTE(coreycb): Skipping failing test on folsom until resolved. On
        #                folsom only, uploading an image to glance gets 400 Bad
        #                Request - Error uploading image: (error): [Errno 111]
        #                ECONNREFUSED (HTTP 400)
        if self._get_openstack_release() == self.precise_folsom:
            u.log.error("Skipping failing test until resolved")
            return

        # Create glance image
        image = u.create_cirros_image(self.glance, "cirros-image")
        if not image:
            amulet.raise_status(amulet.FAIL, msg="Image create failed")

        # Validate that cirros image exists in glance and get its checksum/size
        images = list(self.glance.images.list())
        if len(images) != 1:
            msg = "Expected 1 glance image, found {}".format(len(images))
            amulet.raise_status(amulet.FAIL, msg=msg)

        if images[0].name != 'cirros-image':
            message = "cirros image does not exist"
            amulet.raise_status(amulet.FAIL, msg=message)

        glance_image_md5 = image.checksum
        glance_image_size = image.size

        # Validate that swift object's checksum/size match that from glance
        headers, containers = self.swift.get_account()
        if len(containers) != 1:
            msg = "Expected 1 swift container, found {}".format(len(containers))
            amulet.raise_status(amulet.FAIL, msg=msg)

        container_name = containers[0].get('name')

        headers, objects = self.swift.get_container(container_name)
        if len(objects) != 1:
            msg = "Expected 1 swift object, found {}".format(len(objects))
            amulet.raise_status(amulet.FAIL, msg=msg)

        swift_object_size = objects[0].get('bytes')
        swift_object_md5 = objects[0].get('hash')

        if glance_image_size != swift_object_size:
            msg = "Glance image size {} != swift object size {}".format( \
                                           glance_image_size, swift_object_size)
            amulet.raise_status(amulet.FAIL, msg=msg)

        if glance_image_md5 != swift_object_md5:
            msg = "Glance image hash {} != swift object hash {}".format( \
                                             glance_image_md5, swift_object_md5)
            amulet.raise_status(amulet.FAIL, msg=msg)

        # Cleanup
        u.delete_image(self.glance, image)

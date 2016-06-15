import sys
import uuid

import unittest

from mock import (
    call,
    patch,
    MagicMock,
)

sys.path.append("hooks")

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = MagicMock()
sys.modules['apt_pkg'] = MagicMock()

with patch('hooks.charmhelpers.contrib.hardening.harden.harden') as mock_dec, \
        patch('hooks.charmhelpers.core.hookenv.log'):
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import swift_hooks


class SwiftHooksTestCase(unittest.TestCase):

    @patch("swift_hooks.relation_get")
    @patch("swift_hooks.local_unit")
    def test_is_all_peers_stopped(self, mock_local_unit, mock_relation_get):
        token1 = str(uuid.uuid4())
        token2 = str(uuid.uuid4())
        mock_relation_get.return_value = token1

        responses = [{'some-other-key': token1}]
        self.assertFalse(swift_hooks.is_all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token2}]
        self.assertFalse(swift_hooks.is_all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token1},
                     {'some-other-key': token1}]
        self.assertFalse(swift_hooks.is_all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token1}]
        self.assertTrue(swift_hooks.is_all_peers_stopped(responses))

        mock_relation_get.return_value = token2

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token1}]
        self.assertFalse(swift_hooks.is_all_peers_stopped(responses))

    @patch.object(swift_hooks, 'config')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch.object(swift_hooks, 'CONFIGS')
    @patch('charmhelpers.core.hookenv.local_unit')
    @patch('charmhelpers.core.hookenv.service_name')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch.object(swift_hooks, 'relation_set')
    def test_keystone_joined(self, _relation_set, _is_clustered, _unit_get,
                             _service_name, _local_unit, _CONFIGS, _ip_config,
                             _config):
        config_dict = {
            'bind-port': '1234',
            'region': 'RegionOne',
            'operator-roles': 'Operator,Monitor'
        }

        def foo(key=None):
            if key is None:
                return config_dict
            else:
                return config_dict.get(key)

        _config.side_effect = foo
        _ip_config.side_effect = foo
        _unit_get.return_value = 'swift-proxy'
        _local_unit.return_value = 'swift-proxy/0'
        _service_name.return_value = 'swift-proxy'
        _is_clustered.return_value = False

        swift_hooks.keystone_joined()

        _relation_set.assert_called_with(
            service='swift',
            region='RegionOne',
            public_url='http://swift-proxy:1234/v1/AUTH_$(tenant_id)s',
            internal_url='http://swift-proxy:1234/v1/AUTH_$(tenant_id)s',
            admin_url='http://swift-proxy:1234',
            requested_roles='Operator,Monitor',
            relation_id=None
        )

    @patch.object(swift_hooks, 'config')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch.object(swift_hooks, 'CONFIGS')
    @patch('charmhelpers.core.hookenv.local_unit')
    @patch('charmhelpers.core.hookenv.service_name')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch.object(swift_hooks, 'relation_set')
    def test_keystone_joined_public_hostname(self,
                                             _relation_set,
                                             _is_clustered,
                                             _unit_get,
                                             _service_name,
                                             _local_unit,
                                             _CONFIGS,
                                             _ip_config,
                                             _config):
        config_dict = {
            'bind-port': '1234',
            'region': 'RegionOne',
            'operator-roles': 'Operator,Monitor',
            'os-public-hostname': 'public.example.com'
        }

        def foo(key=None):
            if key is None:
                return config_dict
            else:
                return config_dict.get(key)

        _config.side_effect = _ip_config.side_effect = foo
        _unit_get.return_value = _service_name.return_value = 'swift-proxy'
        _local_unit.return_value = 'swift-proxy/0'
        _is_clustered.return_value = False

        swift_hooks.keystone_joined()

        _relation_set.assert_called_with(
            service='swift',
            region='RegionOne',
            public_url=('http://public.example.com:1234/'
                        'v1/AUTH_$(tenant_id)s'),
            internal_url='http://swift-proxy:1234/v1/AUTH_$(tenant_id)s',
            admin_url='http://swift-proxy:1234',
            requested_roles='Operator,Monitor',
            relation_id=None
        )

    @patch.object(swift_hooks.time, 'time')
    @patch.object(swift_hooks, 'get_host_ip')
    @patch.object(swift_hooks, 'is_elected_leader')
    @patch.object(swift_hooks, 'related_units')
    @patch.object(swift_hooks, 'relation_ids')
    @patch.object(swift_hooks, 'relation_set')
    def test_update_rsync_acls(self, mock_rel_set, mock_rel_ids,
                               mock_rel_units, mock_is_leader,
                               mock_get_host_ip, mock_time):
        mock_time.return_value = 1234
        mock_is_leader.return_value = True
        mock_rel_ids.return_value = ['storage:1']
        mock_rel_units.return_value = ['unit/0', 'unit/1']

        def fake_get_host_ip(rid, unit):
            if unit == 'unit/0':
                return '10.0.0.1'
            elif unit == 'unit/1':
                return '10.0.0.2'

        mock_get_host_ip.side_effect = fake_get_host_ip
        swift_hooks.update_rsync_acls()
        calls = [call(rsync_allowed_hosts='10.0.0.1 10.0.0.2',
                      relation_id='storage:1', timestamp=1234)]
        mock_rel_set.assert_has_calls(calls)

    @patch.object(swift_hooks, 'relation_set')
    @patch.object(swift_hooks, 'update_dns_ha_resource_params')
    @patch.object(swift_hooks, 'get_hacluster_config')
    @patch.object(swift_hooks, 'config')
    def test_ha_jrelation_oined_dns_ha(self, test_config, get_hacluster_config,
                                       update_dns_ha_resource_params,
                                       relation_set):
        def _fake_update(resources, resource_params, relation_id=None):
            resources.update({'res_swift_proxy_public_hostname':
                              'ocf:maas:dns'})
            resource_params.update({'res_swift_proxy_public_hostname':
                                    'params fqdn="keystone.maas" '
                                    'ip_address="10.0.0.1"'})

        test_config.set('dns-ha', True)
        get_hacluster_config.return_value = {
            'vip': None,
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'os-admin-hostname': None,
            'os-internal-hostname': None,
            'os-public-hostname': 'keystone.maas',
        }
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_swift_haproxy': 'haproxy'},
            'resources': {'res_swift_proxy_public_hostname': 'ocf:maas:dns',
                          'res_swift_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_swift_proxy_public_hostname':
                    'params fqdn="keystone.maas" '
                    'ip_address="10.0.0.1"',
                'res_swift_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_swift_haproxy': 'res_swift_haproxy'}
        }
        update_dns_ha_resource_params.side_effect = _fake_update

        swift_hooks.ha_relation_joined()
        self.assertTrue(update_dns_ha_resource_params.called)
        relation_set.assert_called_with(**args)

import mock
import os
import shutil
import tempfile
import uuid
import unittest

from mock import patch
with mock.patch('charmhelpers.core.hookenv.config'):
    with patch('lib.swift_utils.is_paused') as is_paused:
        import lib.swift_utils as swift_utils


def init_ring_paths(tmpdir):
    swift_utils.SWIFT_CONF_DIR = tmpdir
    for ring in swift_utils.SWIFT_RINGS.iterkeys():
        path = os.path.join(tmpdir, "%s.builder" % ring)
        swift_utils.SWIFT_RINGS[ring] = path
        with open(path, 'w') as fd:
            fd.write("0\n")


class SwiftUtilsTestCase(unittest.TestCase):

    @mock.patch('lib.swift_utils.get_broker_token')
    @mock.patch('lib.swift_utils.update_www_rings')
    @mock.patch('lib.swift_utils.get_builders_checksum')
    @mock.patch('lib.swift_utils.get_rings_checksum')
    @mock.patch('lib.swift_utils.balance_rings')
    @mock.patch('lib.swift_utils.log')
    @mock.patch('lib.swift_utils.os.path.exists')
    @mock.patch('lib.swift_utils.is_elected_leader')
    @mock.patch('lib.swift_utils.get_min_part_hours')
    @mock.patch('lib.swift_utils.set_min_part_hours')
    def test_update_rings(self, mock_set_min_hours,
                          mock_get_min_hours,
                          mock_is_elected_leader, mock_path_exists,
                          mock_log, mock_balance_rings,
                          mock_get_rings_checksum,
                          mock_get_builders_checksum, mock_update_www_rings,
                          mock_get_broker_token):
        mock_get_broker_token.return_value = "token1"

        # Make sure same is returned for both so that we don't try to sync
        mock_get_rings_checksum.return_value = None
        mock_get_builders_checksum.return_value = None

        # Test blocker 1
        mock_is_elected_leader.return_value = False
        swift_utils.update_rings()
        self.assertFalse(mock_balance_rings.called)

        # Test blocker 2
        mock_path_exists.return_value = False
        mock_is_elected_leader.return_value = True
        swift_utils.update_rings()
        self.assertFalse(mock_get_min_hours.called)
        self.assertFalse(mock_balance_rings.called)

        # Test blocker 3
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_get_min_hours.return_value = 10
        swift_utils.update_rings(min_part_hours=10)
        self.assertTrue(mock_get_min_hours.called)
        self.assertFalse(mock_set_min_hours.called)
        self.assertFalse(mock_balance_rings.called)

        mock_get_min_hours.reset_mock()

        # Test go through
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_get_min_hours.return_value = 0
        swift_utils.update_rings(min_part_hours=10)
        self.assertTrue(mock_get_min_hours.called)
        self.assertTrue(mock_set_min_hours.called)
        self.assertTrue(mock_balance_rings.called)

    @mock.patch('lib.swift_utils.get_broker_token')
    @mock.patch('lib.swift_utils.balance_rings')
    @mock.patch('lib.swift_utils.log')
    @mock.patch('lib.swift_utils.is_elected_leader')
    @mock.patch('lib.swift_utils.config')
    @mock.patch('lib.swift_utils.update_www_rings')
    @mock.patch('lib.swift_utils.cluster_sync_rings')
    def test_sync_builders_and_rings_if_changed(self, mock_cluster_sync_rings,
                                                mock_update_www_rings,
                                                mock_config,
                                                mock_is_elected_leader,
                                                mock_log,
                                                mock_balance_rings,
                                                mock_get_broker_token):
        mock_get_broker_token.return_value = "token1"

        @swift_utils.sync_builders_and_rings_if_changed
        def mock_balance():
            for ring, builder in swift_utils.SWIFT_RINGS.iteritems():
                ring = os.path.join(swift_utils.SWIFT_CONF_DIR,
                                    '%s.ring.gz' % ring)
                with open(ring, 'w') as fd:
                    fd.write(str(uuid.uuid4()))

                with open(builder, 'w') as fd:
                    fd.write(str(uuid.uuid4()))

        mock_balance_rings.side_effect = mock_balance

        init_ring_paths(tempfile.mkdtemp())
        try:
            swift_utils.balance_rings()
        finally:
            shutil.rmtree(swift_utils.SWIFT_CONF_DIR)

        self.assertTrue(mock_update_www_rings.called)
        self.assertTrue(mock_cluster_sync_rings.called)

    @mock.patch('lib.swift_utils.get_www_dir')
    def test_mark_www_rings_deleted(self, mock_get_www_dir):
        try:
            tmpdir = tempfile.mkdtemp()
            mock_get_www_dir.return_value = tmpdir
            swift_utils.mark_www_rings_deleted()
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch('lib.swift_utils.uuid')
    def test_cluster_rpc_stop_proxy_request(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'test-uuid'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.stop_proxy_request(peers_only=True)
        self.assertEqual({'trigger': 'test-uuid',
                          'broker-token': None,
                          'builder-broker': None,
                          'peers-only': True,
                          'leader-changed-notification': None,
                          'stop-proxy-service': 'test-uuid',
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

        rq = rpc.stop_proxy_request()
        self.assertEqual({'trigger': 'test-uuid',
                          'broker-token': None,
                          'builder-broker': None,
                          'peers-only': None,
                          'leader-changed-notification': None,
                          'stop-proxy-service': 'test-uuid',
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

    @mock.patch('lib.swift_utils.uuid')
    def test_cluster_rpc_stop_proxy_ack(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token2'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.stop_proxy_ack(echo_token='token1', echo_peers_only='1')
        self.assertEqual({'trigger': 'token2',
                          'broker-token': None,
                          'builder-broker': None,
                          'peers-only': '1',
                          'leader-changed-notification': None,
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': 'token1',
                          'sync-only-builders': None}, rq)

    @mock.patch('lib.swift_utils.uuid')
    def test_cluster_rpc_sync_request(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token2'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.sync_rings_request('HostA', 'token1')
        self.assertEqual({'trigger': 'token2',
                          'broker-token': 'token1',
                          'builder-broker': 'HostA',
                          'peers-only': None,
                          'leader-changed-notification': None,
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

    @mock.patch('lib.swift_utils.uuid')
    def test_cluster_rpc_notify_leader_changed(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token1'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.notify_leader_changed()
        self.assertEqual({'trigger': 'token1',
                          'broker-token': None,
                          'builder-broker': None,
                          'peers-only': None,
                          'leader-changed-notification': 'token1',
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

    def test_all_responses_equal(self):
        responses = [{'a': 1, 'c': 3}]
        self.assertTrue(swift_utils.all_responses_equal(responses, 'b',
                                                        must_exist=False))

        responses = [{'a': 1, 'c': 3}]
        self.assertFalse(swift_utils.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}]
        self.assertTrue(swift_utils.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 1, 'b': 2, 'c': 3}]
        self.assertTrue(swift_utils.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 2, 'b': 2, 'c': 3}]
        self.assertTrue(swift_utils.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 1, 'b': 3, 'c': 3}]
        self.assertFalse(swift_utils.all_responses_equal(responses, 'b'))

    def test_get_first_available_value(self):
        rsps = [{'key1': 'A'}, {'key1': 'B'}]
        self.assertEqual('A',
                         swift_utils.get_first_available_value(rsps, 'key1'))

        rsps = [{'key2': 'A'}, {'key1': 'B'}]
        self.assertEqual('B',
                         swift_utils.get_first_available_value(rsps, 'key1'))

        rsps = [{'key2': 'A'}, {'key1': 'B'}]
        self.assertIsNone(swift_utils.get_first_available_value(rsps, 'key3'))

        rsps = []
        self.assertIsNone(swift_utils.get_first_available_value(rsps, 'key3'))

    @mock.patch('lib.swift_utils.is_paused')
    @mock.patch('lib.swift_utils.config')
    @mock.patch('lib.swift_utils.set_os_workload_status')
    @mock.patch('lib.swift_utils.SwiftRingContext.__call__')
    @mock.patch('lib.swift_utils.status_set')
    @mock.patch('lib.swift_utils.has_minimum_zones')
    @mock.patch('lib.swift_utils.relation_ids')
    def test_assess_status(self, relation_ids, has_min_zones, status_set,
                           ctxt, workload_status, config, is_paused):
        config.return_value = 3

        is_paused.return_value = True
        swift_utils.assess_status(None)
        status_set.assert_called_with('maintenance',
                "Paused. Use 'resume' action to resume normal service.")

        is_paused.return_value = False
        relation_ids.return_value = []
        swift_utils.assess_status(None)
        status_set.assert_called_with('blocked', 'Missing relation: storage')

        relation_ids.return_value = ['swift-storage:1']

        ctxt.return_value = {'allowed_hosts': ['1.2.3.4']}
        swift_utils.assess_status(None)
        status_set.assert_called_with('blocked',
                                      'Not enough related storage nodes')

        ctxt.return_value = {'allowed_hosts': ['1.2.3.4', '2.3.4.5',
                                               '3.4.5.6']}
        has_min_zones.return_value = False
        swift_utils.assess_status(None)
        status_set.assert_called_with('blocked',
                                      'Not enough storage zones for minimum '
                                      'replicas')

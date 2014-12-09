import mock
import os
import shutil
import tempfile
import uuid
import unittest


with mock.patch('charmhelpers.core.hookenv.config'):
    import swift_utils


def init_ring_paths(tmpdir):
    swift_utils.SWIFT_CONF_DIR = tmpdir
    for ring in swift_utils.SWIFT_RINGS.iterkeys():
        path = os.path.join(tmpdir, "%s.builder" % ring)
        swift_utils.SWIFT_RINGS[ring] = path
        with open(path, 'w') as fd:
            fd.write("0\n")


class SwiftUtilsTestCase(unittest.TestCase):

    @mock.patch('swift_utils.sync_builders_and_rings_if_changed')
    @mock.patch('swift_utils.balance_rings')
    @mock.patch('swift_utils.log')
    @mock.patch('swift_utils.os.path.exists')
    @mock.patch('swift_utils.is_elected_leader')
    @mock.patch('swift_utils.config')
    @mock.patch('swift_utils.get_min_part_hours')
    @mock.patch('swift_utils.set_min_part_hours')
    def test_update_min_part_hours(self, mock_set_min_hours,
                                   mock_get_min_hours, mock_config,
                                   mock_is_elected_leader, mock_path_exists,
                                   mock_log, mock_balance_rings,
                                   mock_sync_builders_and_rings_if_changed):

        # Test blocker 1
        mock_is_elected_leader.return_value = False
        swift_utils.update_min_part_hours()
        self.assertFalse(mock_config.called)
        self.assertFalse(mock_balance_rings.called)

        # Test blocker 2
        mock_path_exists.return_value = False
        mock_is_elected_leader.return_value = True
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_config.called)
        self.assertFalse(mock_get_min_hours.called)
        self.assertFalse(mock_balance_rings.called)

        # Test blocker 3
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_config.return_value = 10
        mock_get_min_hours.return_value = 10
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_get_min_hours.called)
        self.assertFalse(mock_set_min_hours.called)
        self.assertFalse(mock_balance_rings.called)

        # Test go through
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_config.return_value = 10
        mock_get_min_hours.return_value = 0
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_config.called)
        self.assertTrue(mock_get_min_hours.called)
        self.assertTrue(mock_set_min_hours.called)
        self.assertTrue(mock_balance_rings.called)

    @mock.patch('swift_utils.balance_rings')
    @mock.patch('swift_utils.log')
    @mock.patch('swift_utils.is_elected_leader')
    @mock.patch('swift_utils.config')
    @mock.patch('swift_utils.update_www_rings')
    @mock.patch('swift_utils.cluster_sync_rings')
    def test_sync_builders_and_rings_if_changed(self, mock_cluster_sync_rings,
                                                mock_update_www_rings,
                                                mock_config,
                                                mock_is_elected_leader,
                                                mock_log,
                                                mock_balance_rings):

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

    @mock.patch('swift_utils.get_www_dir')
    def test_mark_www_rings_deleted(self, mock_get_www_dir):
        try:
            tmpdir = tempfile.mkdtemp()
            mock_get_www_dir.return_value = tmpdir
            swift_utils.mark_www_rings_deleted()
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch('swift_utils.uuid')
    def test_cluster_rpc_stop_proxy_request(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'test-uuid'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.stop_proxy_request(peers_only=True)
        self.assertEqual({'trigger': 'test-uuid',
                          'builder-broker': None,
                          'peers-only': True,
                          'stop-proxy-service': 'test-uuid',
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

        rq = rpc.stop_proxy_request()
        self.assertEqual({'trigger': 'test-uuid',
                          'builder-broker': None,
                          'peers-only': None,
                          'stop-proxy-service': 'test-uuid',
                          'stop-proxy-service-ack': None,
                          'sync-only-builders': None}, rq)

    @mock.patch('swift_utils.uuid')
    def test_cluster_rpc_stop_proxy_ack(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token2'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.stop_proxy_ack(echo_token='token1', echo_peers_only='1')
        self.assertEqual({'trigger': 'token2',
                          'builder-broker': None,
                          'peers-only': '1',
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': 'token1',
                          'sync-only-builders': None}, rq)

    @mock.patch('swift_utils.uuid')
    def test_cluster_rpc_sync_request(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token1'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.sync_rings_request('HostA')
        self.assertEqual({'trigger': 'token1',
                          'builder-broker': 'HostA',
                          'peers-only': None,
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

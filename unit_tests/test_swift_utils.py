import mock
import shutil
import tempfile
import unittest


with mock.patch('charmhelpers.core.hookenv.config'):
    import swift_utils


class SwiftUtilsTestCase(unittest.TestCase):

    @mock.patch('swift_utils.log')
    @mock.patch('swift_utils.os.path.exists')
    @mock.patch('swift_utils.is_elected_leader')
    @mock.patch('swift_utils.config')
    @mock.patch('swift_utils.get_min_part_hours')
    @mock.patch('swift_utils.set_min_part_hours')
    @mock.patch('swift_utils.update_www_rings')
    @mock.patch('swift_utils.cluster_sync_rings')
    def test_update_min_part_hours(self, mock_cluster_sync_rings,
                                   mock_update_www_rings,
                                   mock_set_min_hours, mock_get_min_hours,
                                   mock_config, mock_is_elected_leader,
                                   mock_path_exists, mock_log):

        # Test blocker 1
        mock_is_elected_leader.return_value = False
        swift_utils.update_min_part_hours()
        self.assertFalse(mock_config.called)

        # Test blocker 2
        mock_path_exists.return_value = False
        mock_is_elected_leader.return_value = True
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_config.called)
        self.assertFalse(mock_get_min_hours.called)

        # Test blocker 3
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_config.return_value = 10
        mock_get_min_hours.return_value = 10
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_config.called)
        self.assertTrue(mock_get_min_hours.called)
        self.assertFalse(mock_set_min_hours.called)

        # Test go through
        mock_path_exists.return_value = True
        mock_is_elected_leader.return_value = True
        mock_config.return_value = 10
        mock_get_min_hours.return_value = 11
        swift_utils.update_min_part_hours()
        self.assertTrue(mock_config.called)
        self.assertTrue(mock_get_min_hours.called)
        self.assertTrue(mock_set_min_hours.called)
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
                          'stop-proxy-service-ack': None}, rq)

        rq = rpc.stop_proxy_request()
        self.assertEqual({'trigger': 'test-uuid',
                          'builder-broker': None,
                          'peers-only': None,
                          'stop-proxy-service': 'test-uuid',
                          'stop-proxy-service-ack': None}, rq)

    @mock.patch('swift_utils.uuid')
    def test_cluster_rpc_stop_proxy_ack(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token2'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.stop_proxy_ack('token1')
        self.assertEqual({'trigger': 'token2',
                          'builder-broker': None,
                          'peers-only': None,
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': 'token1'}, rq)

    @mock.patch('swift_utils.uuid')
    def test_cluster_rpc_sync_request(self, mock_uuid):
        mock_uuid.uuid4.return_value = 'token1'
        rpc = swift_utils.SwiftProxyClusterRPC()
        rq = rpc.sync_rings_request('HostA')
        self.assertEqual({'trigger': 'token1',
                          'builder-broker': 'HostA',
                          'peers-only': None,
                          'stop-proxy-service': None,
                          'stop-proxy-service-ack': None}, rq)

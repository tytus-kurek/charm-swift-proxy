import mock
import unittest
import uuid


with mock.patch('charmhelpers.core.hookenv.log'):
    import swift_hooks


class SwiftHooksTestCase(unittest.TestCase):

    def test_all_responses_equal(self):
        responses = [{'a': 1, 'c': 3}]
        self.assertTrue(swift_hooks.all_responses_equal(responses, 'b',
                                                        must_exist=False))

        responses = [{'a': 1, 'c': 3}]
        self.assertFalse(swift_hooks.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}]
        self.assertTrue(swift_hooks.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 1, 'b': 2, 'c': 3}]
        self.assertTrue(swift_hooks.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 2, 'b': 2, 'c': 3}]
        self.assertTrue(swift_hooks.all_responses_equal(responses, 'b'))

        responses = [{'a': 1, 'b': 2, 'c': 3}, {'a': 1, 'b': 3, 'c': 3}]
        self.assertFalse(swift_hooks.all_responses_equal(responses, 'b'))

    def test_all_peers_stopped(self):
        token1 = str(uuid.uuid4())
        token2 = str(uuid.uuid4())
        responses = [{'some-other-key': token1}]
        self.assertFalse(swift_hooks.all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token2}]
        self.assertFalse(swift_hooks.all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token1}]
        self.assertTrue(swift_hooks.all_peers_stopped(responses))

        responses = [{'stop-proxy-service-ack': token1},
                     {'stop-proxy-service-ack': token1},
                     {'some-other-key': token1}]
        self.assertFalse(swift_hooks.all_peers_stopped(responses))

    def test_get_first_available_value(self):
        rsps = [{'key1': 'A'}, {'key1': 'B'}]
        self.assertEqual('A',
                         swift_hooks.get_first_available_value(rsps, 'key1'))

        rsps = [{'key2': 'A'}, {'key1': 'B'}]
        self.assertEqual('B',
                         swift_hooks.get_first_available_value(rsps, 'key1'))

        rsps = [{'key2': 'A'}, {'key1': 'B'}]
        self.assertIsNone(swift_hooks.get_first_available_value(rsps, 'key3'))

        rsps = []
        self.assertIsNone(swift_hooks.get_first_available_value(rsps, 'key3'))

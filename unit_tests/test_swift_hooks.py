import mock
import unittest


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

    def test_all_peers_disabled(self):
        responses = [{'some-other-key': 0}]
        self.assertFalse(swift_hooks.all_peers_disabled(responses))

        responses = [{'disable-proxy-service': 1},
                     {'disable-proxy-service': 0}]
        self.assertFalse(swift_hooks.all_peers_disabled(responses))

        responses = [{'disable-proxy-service': 0},
                     {'disable-proxy-service': 0}]
        self.assertTrue(swift_hooks.all_peers_disabled(responses))

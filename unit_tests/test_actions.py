import argparse
import sys
import tempfile

import mock
import yaml
import unittest

from mock import patch, MagicMock

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = MagicMock()
sys.modules['apt_pkg'] = MagicMock()

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    with patch('lib.swift_utils.is_paused') as is_paused:
        with patch('lib.swift_utils.register_configs') as configs:
            import actions.actions


class CharmTestCase(unittest.TestCase):

    def setUp(self, obj, patches):
        super(CharmTestCase, self).setUp()
        self.patches = patches
        self.obj = obj
        self.patch_all()

    def patch(self, method):
        _m = mock.patch.object(self.obj, method)
        mocked = _m.start()
        self.addCleanup(_m.stop)
        return mocked

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self.patch(method))


class PauseTestCase(CharmTestCase):

    def setUp(self):
        super(PauseTestCase, self).setUp(
            actions.actions, ["service_pause", "HookData", "kv",
                              "assess_status"])

        class FakeArgs(object):
            services = ['swift-proxy', 'haproxy', 'memcached', 'apache2']
        self.args = FakeArgs()

    def test_pauses_services(self):
        """Pause action pauses all of the Swift services."""
        pause_calls = []

        def fake_service_pause(svc):
            pause_calls.append(svc)
            return True

        self.service_pause.side_effect = fake_service_pause

        actions.actions.pause(self.args)
        self.assertEqual(
            pause_calls, ['swift-proxy', 'haproxy', 'memcached', 'apache2'])

    def test_bails_out_early_on_error(self):
        """Pause action fails early if there are errors stopping a service."""
        pause_calls = []

        def maybe_kill(svc):
            if svc == "haproxy":
                return False
            else:
                pause_calls.append(svc)
                return True

        self.service_pause.side_effect = maybe_kill
        self.assertRaisesRegexp(
            Exception, "haproxy didn't stop cleanly.",
            actions.actions.pause, self.args)
        self.assertEqual(pause_calls, ["swift-proxy"])

    def test_pause_sets_value(self):
        """Pause action sets the unit-paused value to True."""
        self.HookData()().return_value = True

        actions.actions.pause(self.args)
        self.kv().set.assert_called_with('unit-paused', True)


class ResumeTestCase(CharmTestCase):

    def setUp(self):
        super(ResumeTestCase, self).setUp(
            actions.actions, ["service_resume", "HookData", "kv",
                              "assess_status"])

        class FakeArgs(object):
            services = ['swift-proxy', 'haproxy', 'memcached', 'apache2']
        self.args = FakeArgs()

    def test_resumes_services(self):
        """Resume action resumes all of the Swift services."""
        resume_calls = []

        def fake_service_resume(svc):
            resume_calls.append(svc)
            return True

        self.service_resume.side_effect = fake_service_resume
        actions.actions.resume(self.args)
        self.assertEqual(
            resume_calls, ['swift-proxy', 'haproxy', 'memcached', 'apache2'])

    def test_bails_out_early_on_error(self):
        """Resume action fails early if there are errors starting a service."""
        resume_calls = []

        def maybe_kill(svc):
            if svc == "haproxy":
                return False
            else:
                resume_calls.append(svc)
                return True

        self.service_resume.side_effect = maybe_kill
        self.assertRaisesRegexp(
            Exception, "haproxy didn't start cleanly.",
            actions.actions.resume, self.args)
        self.assertEqual(resume_calls, ['swift-proxy'])

    def test_resume_sets_value(self):
        """Resume action sets the unit-paused value to False."""
        self.HookData()().return_value = True

        actions.actions.resume(self.args)
        self.kv().set.assert_called_with('unit-paused', False)


class GetActionParserTestCase(unittest.TestCase):

    def test_definition_from_yaml(self):
        """ArgumentParser is seeded from actions.yaml."""
        actions_yaml = tempfile.NamedTemporaryFile(
            prefix="GetActionParserTestCase", suffix="yaml")
        actions_yaml.write(yaml.dump({"foo": {"description": "Foo is bar"}}))
        actions_yaml.seek(0)
        parser = actions.actions.get_action_parser(actions_yaml.name, "foo",
                                                   get_services=lambda: [])
        self.assertEqual(parser.description, 'Foo is bar')


class MainTestCase(CharmTestCase):

    def setUp(self):
        super(MainTestCase, self).setUp(
            actions.actions, ["_get_action_name",
                              "get_action_parser",
                              "action_fail"])

    def test_invokes_pause(self):
        dummy_calls = []

        def dummy_action(args):
            dummy_calls.append(True)

        self._get_action_name.side_effect = lambda: "foo"
        self.get_action_parser = lambda: argparse.ArgumentParser()
        with mock.patch.dict(actions.actions.ACTIONS, {"foo": dummy_action}):
            actions.actions.main([])
        self.assertEqual(dummy_calls, [True])

    def test_unknown_action(self):
        """Unknown actions aren't a traceback."""
        self._get_action_name.side_effect = lambda: "foo"
        self.get_action_parser = lambda: argparse.ArgumentParser()
        exit_string = actions.actions.main([])
        self.assertEqual("Action foo undefined", exit_string)

    def test_failing_action(self):
        """Actions which traceback trigger action_fail() calls."""
        dummy_calls = []

        self.action_fail.side_effect = dummy_calls.append
        self._get_action_name.side_effect = lambda: "foo"

        def dummy_action(args):
            raise ValueError("uh oh")

        self.get_action_parser = lambda: argparse.ArgumentParser()
        with mock.patch.dict(actions.actions.ACTIONS, {"foo": dummy_action}):
            actions.actions.main([])
        self.assertEqual(dummy_calls, ["uh oh"])

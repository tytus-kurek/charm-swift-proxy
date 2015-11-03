from mock import patch
import os
import unittest

os.environ['JUJU_UNIT_NAME'] = 'swift-proxy'

with patch('lib.swift_utils.is_paused') as is_paused:
    with patch('lib.swift_utils.register_configs') as configs:
        import actions.openstack_upgrade as openstack_upgrade


TO_PATCH = [
    'config_changed',
    'do_openstack_upgrade',
]


class CharmTestCase(unittest.TestCase):

    def setUp(self, obj, patches):
        super(CharmTestCase, self).setUp()
        self.patches = patches
        self.obj = obj
        self.patch_all()

    def patch(self, method):
        _m = patch.object(self.obj, method)
        mocked = _m.start()
        self.addCleanup(_m.stop)
        return mocked

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self.patch(method))


class TestSwiftUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestSwiftUpgradeActions, self).setUp(openstack_upgrade,
                                                   TO_PATCH)

    @patch('actions.charmhelpers.contrib.openstack.utils.config')
    @patch('actions.charmhelpers.contrib.openstack.utils.action_set')
    @patch('actions.charmhelpers.contrib.openstack.utils.'
           'git_install_requested')
    @patch('actions.charmhelpers.contrib.openstack.utils.'
           'openstack_upgrade_available')
    def test_openstack_upgrade_true(self, upgrade_avail, git_requested,
                                    action_set, config):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = True

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.config_changed.called)

    @patch('actions.charmhelpers.contrib.openstack.utils.config')
    @patch('actions.charmhelpers.contrib.openstack.utils.action_set')
    @patch('actions.charmhelpers.contrib.openstack.utils.'
           'git_install_requested')
    @patch('actions.charmhelpers.contrib.openstack.utils.'
           'openstack_upgrade_available')
    def test_openstack_upgrade_false(self, upgrade_avail, git_requested,
                                     action_set, config):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)

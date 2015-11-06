import mock
import os
import tempfile
import unittest
import uuid


with mock.patch('charmhelpers.core.hookenv.config'):
    import lib.swift_context as swift_context


class SwiftContextTestCase(unittest.TestCase):

    @mock.patch('lib.swift_context.config')
    def test_get_swift_hash_file(self, mock_config):
        expected = '##FILEHASH##'
        with tempfile.NamedTemporaryFile() as tmpfile:
            swift_context.SWIFT_HASH_FILE = tmpfile.name
            tmpfile.write(expected)
            tmpfile.seek(0)
            os.fsync(tmpfile)
            hash = swift_context.get_swift_hash()

        self.assertFalse(mock_config.called)
        self.assertEqual(expected, hash)

    @mock.patch('lib.swift_context.config')
    def test_get_swift_hash_config(self, mock_config):
        expected = '##CFGHASH##'
        mock_config.return_value = expected
        tmpfile = tempfile.mktemp()
        swift_context.SWIFT_HASH_FILE = tmpfile
        hash = swift_context.get_swift_hash()

        with open(tmpfile, 'r') as fd:
            self.assertEqual(expected, fd.read())

        self.assertTrue(mock_config.called)
        self.assertEqual(expected, hash)

    @mock.patch('lib.swift_context.service_name')
    @mock.patch('lib.swift_context.config')
    def test_get_swift_hash_env(self, mock_config, mock_service_name):
        mock_config.return_value = None
        mock_service_name.return_value = "testsvc"
        tmpfile = tempfile.mktemp()
        swift_context.SWIFT_HASH_FILE = tmpfile
        with mock.patch('lib.swift_context.os.environ.get') as mock_env_get:
            mock_env_get.return_value = str(uuid.uuid4())
            hash_ = swift_context.get_swift_hash()
            mock_env_get.assert_called_with('JUJU_ENV_UUID')

        with open(tmpfile, 'r') as fd:
            self.assertEqual(hash_, fd.read())

        self.assertTrue(mock_config.called)

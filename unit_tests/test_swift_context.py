# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
            mock_env_get.assert_has_calls([
                mock.call('JUJU_MODEL_UUID'),
                mock.call('JUJU_ENV_UUID',
                          mock_env_get.return_value)
            ])

        with open(tmpfile, 'r') as fd:
            self.assertEqual(hash_, fd.read())

        self.assertTrue(mock_config.called)

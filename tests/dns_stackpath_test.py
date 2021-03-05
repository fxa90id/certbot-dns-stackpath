"""Tests for certbot_dns_stackpath._internal.dns_stackpath."""

import unittest

import pystackpath
try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_ERROR = pystackpath.HTTPError()

CLIENT_ID = 'clientId123'
CLIENT_SECRET = 'clientSecret123'
STACK_ID = 'stackId123'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_stackpath._internal.dns_stackpath import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({
            "dns_stackpath_client_id": CLIENT_ID,
            "dns_stackpath_client_secret": CLIENT_SECRET,
            "dns_stackpath_stack_id": STACK_ID
        }, path)

        self.config = mock.MagicMock(stackpath_credentials=path,
                                     stackpath_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "stackpath")

        self.mock_client = mock.MagicMock()
        # _get_stackpath_client | pylint: disable=protected-access
        self.auth._get_stackpath_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])
        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_no_credentials(self):
        dns_test_common.write({}, self.config.stackpath_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_missing_client_secret_and_stack_id(self):
        dns_test_common.write({"stackpath_client_id": CLIENT_ID}, self.config.stackpath_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_missing_stack_id(self):
        dns_test_common.write({"stackpath_client_secret": CLIENT_SECRET, "stackpath_client_id": CLIENT_ID},
                              self.config.stackpath_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_correct_credentials(self):
        dns_test_common.write({"dns_stackpath_client_secret": CLIENT_SECRET, "dns_stackpath_client_id": CLIENT_ID,
                               "dns_stackpath_stack_id": STACK_ID}, self.config.stackpath_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])


class StackPathClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    record_weight = 0
    zone_id = 1
    record_id = 2

    def setUp(self):
        from certbot_dns_stackpath._internal.dns_stackpath import _StackPathClient

        self.stackpath_client = _StackPathClient(CLIENT_ID, CLIENT_SECRET, STACK_ID)

        self.stackpath = mock.MagicMock()
        self.stackpath_client.stackpath = self.stackpath

    def test_add_txt_record(self):
        self.stackpath.stacks().get() \
            .zones().index.return_value = {
                'zones': [
                    pystackpath.util.BaseObject(client=mock.ANY).loaddict({
                        'id': self.zone_id
                    })
                ]
            }
        self.stackpath_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                              self.record_ttl)

        self.stackpath.stacks().get().zones().get().records().add.assert_called_with(name=mock.ANY,
                                                                                     type=mock.ANY,
                                                                                     ttl=mock.ANY,
                                                                                     data=mock.ANY,
                                                                                     weight=mock.ANY)

        post_data = self.stackpath.stacks().get().zones().get().records().add.call_args[1]
        self.assertEqual('TXT', post_data['type'])
        self.assertEqual(self.record_name, post_data['name'])
        self.assertEqual(self.record_content, post_data['data'])
        self.assertEqual(self.record_ttl, post_data['ttl'])
        self.assertEqual(self.record_weight, post_data['weight'])



if __name__ == "__main__":
    unittest.main()  # pragma: no cover

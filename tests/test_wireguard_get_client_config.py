"""WireGuardManager.get_client_config signature compatibility.

The panel calls manager methods through `_manager_call`, which passes
`(client_id, server_host, port)` for WireGuard. The WG manager used to accept
only `(client_id, server_host)`, so linking an existing WG peer to a user
crashed with "takes 3 positional arguments but 5 were given" (protocol id
included). The manager now accepts an optional `port`; when given it is used
for the Endpoint, otherwise the listen port is read from the server config.
"""

import unittest
from unittest import mock

from managers.wireguard_manager import WireGuardManager


CLIENT = {
    'clientId': 'pubkey123',
    'userData': {
        'clientPrivateKey': 'privkey',
        'clientIp': '10.8.0.6',
        'psk': 'psk123',
    },
}


def make_manager():
    mgr = WireGuardManager(ssh_manager=mock.Mock())
    mgr._get_clients_table = lambda: [CLIENT]
    mgr._get_server_public_key = lambda: 'serverpub'
    mgr._get_server_psk = lambda: 'serverpsk'
    mgr._get_listen_port = lambda: '51820'
    mgr._get_dns = lambda ud=None: '1.1.1.1'
    return mgr


class GetClientConfigTests(unittest.TestCase):
    def test_without_port_reads_listen_port(self):
        mgr = make_manager()
        config = mgr.get_client_config('pubkey123', 'example.com')
        self.assertIn('Endpoint = example.com:51820', config)
        self.assertIn('PrivateKey = privkey', config)

    def test_explicit_port_overrides_listen_port(self):
        mgr = make_manager()
        called = []
        mgr._get_listen_port = lambda: called.append(1) or '51820'
        config = mgr.get_client_config('pubkey123', 'example.com', '55424')
        self.assertIn('Endpoint = example.com:55424', config)
        self.assertEqual(called, [], 'explicit port must skip _get_listen_port')

    def test_manager_call_shim_signature(self):
        """Simulate the shim path: WG gets (client_id, host, port)."""
        mgr = make_manager()
        config = mgr.get_client_config('pubkey123', 'example.com', '55424')
        self.assertIn('[Interface]', config)


if __name__ == '__main__':
    unittest.main()

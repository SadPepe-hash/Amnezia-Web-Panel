import unittest
from unittest.mock import Mock

from managers.ssh_manager import SSHManager


class PooledConnectTests(unittest.TestCase):
    def test_connect_reuses_live_pooled_transport(self):
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        manager.client = Mock()
        manager.client.get_transport.return_value = transport
        manager._disconnect_locked = Mock()
        manager._connect_once = Mock()

        self.assertTrue(manager.connect())

        manager._disconnect_locked.assert_not_called()
        manager._connect_once.assert_not_called()

    def test_connect_replaces_dead_pooled_transport(self):
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = False
        manager.client = Mock()
        manager.client.get_transport.return_value = transport
        manager._disconnect_locked = Mock()
        manager._connect_once = Mock()

        self.assertTrue(manager.connect())

        manager._disconnect_locked.assert_called_once_with()
        manager._connect_once.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()

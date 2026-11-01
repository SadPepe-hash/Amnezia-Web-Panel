"""Regression guards for two self-healing / toggle fixes.

1. The RKN block card's toggle button was hardwired to
   ``onclick="toggleRknBlockApp(false)"``. When the block was off the label
   read "Start" but the click still sent ``enabled: false``, so the contour
   could never be switched back on. The inline handler is gone now and
   ``renderRknBlockCard()`` binds ``!liveOn`` on every render.

2. ``AWGManager._sync_server_config()`` ran ``awg syncconf <iface>`` without
   checking that the interface still exists. A kernel-module reload (DKMS
   update) removes every amneziawg interface while the container keeps
   running, so the sync died with "No such device". The container command now
   re-creates the interface from the on-disk config first -- but only when
   ``ip link show`` says it is missing, so a healthy interface is never torn
   down and re-created on every config save.

Everything here is offline: the template is read as text and SSH is a local
recorder double.
"""
import re
import unittest
from pathlib import Path

from managers.awg_manager import AWGManager

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / 'templates' / 'server.html'

TOGGLE_BUTTON_ID = 'rknblock-toggle-btn'
HARDWIRED_FALSE_ONCLICK = 'onclick="toggleRknBlockApp(false)"'


def template_source():
    return SERVER_TEMPLATE.read_text(encoding='utf-8')


def js_function_body(source, name):
    """Return the source of one top-level ``function name(...) {...}``.

    The template indents functions by four spaces and never nests a
    declaration, so the next ``\n    function``/``\n    async function``
    marks the end of the requested body.
    """
    start = source.index('function %s(' % name)
    following = re.search(r'\n    (?:async )?function ', source[start:])
    end = start + following.start() if following else len(source)
    return source[start:end]


def opening_tag(source, marker):
    """Return the complete opening tag that contains ``marker``."""
    at = source.index(marker)
    start = source.rindex('<', 0, at)
    end = source.index('>', at) + 1
    return source[start:end]


class RecordingSSH:
    """Minimal SSH double: records sudo commands, never touches the network."""

    def __init__(self):
        self.commands = []

    def upload_file(self, content, remote_path):
        raise AssertionError('_sync_server_config must not upload files')

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        # _resolve_config_path asks the container which candidate exists; the
        # first candidate is the one this protocol expects.
        if 'for p in ' in command:
            candidates = command.split('for p in ', 1)[1].split(';', 1)[0]
            return candidates.split()[0] + '\n', '', 0
        return '', '', 0


class RknBlockToggleTemplateTests(unittest.TestCase):
    def setUp(self):
        self.source = template_source()

    def test_toggle_button_has_no_hardwired_false_onclick(self):
        # The exact regression: a literal handler that always disables.
        self.assertNotIn(HARDWIRED_FALSE_ONCLICK, self.source)
        tag = opening_tag(self.source, 'id="%s"' % TOGGLE_BUTTON_ID)
        self.assertNotIn('onclick', tag)
        self.assertNotIn('toggleRknBlockApp', tag)

    def test_render_binds_the_click_handler_to_the_live_state(self):
        body = js_function_body(self.source, 'renderRknBlockCard')
        self.assertIn('const liveOn =', body)
        self.assertIn(
            'toggleBtn.onclick = () => toggleRknBlockApp(!liveOn);',
            body,
        )
        # No leftover unconditional call anywhere in the renderer.
        self.assertNotIn('toggleRknBlockApp(false)', body)

    def test_render_sets_the_label_from_the_live_state(self):
        body = js_function_body(self.source, 'renderRknBlockCard')
        label = re.search(
            r'toggleBtn\.textContent\s*=\s*liveOn\s*\?\s*'
            r"_\(\s*'rknblock_stop'\s*\)\s*:\s*_\('rknblock_start'\)",
            body,
        )
        self.assertIsNotNone(label, 'toggle label must follow liveOn')

    def test_template_still_has_the_toggle_button_id(self):
        self.assertIn('id="%s"' % TOGGLE_BUTTON_ID, self.source)
        # It lives in the installed-actions row, not the install row.
        installed = self.source.index('id="rknblock-installed-actions"')
        toggle = self.source.index('id="%s"' % TOGGLE_BUTTON_ID)
        self.assertLess(installed, toggle)


class SyncServerConfigGuardTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = AWGManager(self.ssh)
        # Names come from the real helpers (no SSH involved).
        self.container = self.manager._container_name('awg3')
        self.config = self.manager._config_path('awg3')
        self.iface = self.manager._interface_name('awg3', self.config)
        self.quick = self.manager._quick_binary('awg3')
        self.wg = self.manager._wg_binary('awg3')

    def sync(self):
        self.manager._sync_server_config('awg3')
        return next(c for c in self.ssh.commands if 'syncconf' in c)

    def test_command_heals_a_missing_interface_before_syncing(self):
        cmd = self.sync()
        self.assertTrue(
            cmd.startswith('docker exec -i %s bash -c ' % self.container), cmd
        )
        self.assertIn('chmod 600 %s' % self.config, cmd)
        self.assertIn('ip link show %s' % self.iface, cmd)
        self.assertIn('%s up %s' % (self.quick, self.config), cmd)
        self.assertIn('%s syncconf %s' % (self.wg, self.iface), cmd)
        self.assertIn('%s strip %s' % (self.quick, self.config), cmd)
        # Order matters: perms, existence check, heal, then apply.
        self.assertLess(cmd.index('chmod 600'), cmd.index('ip link show'))
        self.assertLess(
            cmd.index('ip link show'), cmd.index('%s up ' % self.quick)
        )
        self.assertLess(cmd.index('%s up ' % self.quick), cmd.index('syncconf'))

    def test_guard_is_conditional_and_never_restarts_the_interface(self):
        cmd = self.sync()
        # Up only runs when `ip link show` fails: `cmd || cmd up`.
        guard = re.search(
            r'ip link show (\S+) >/dev/null 2>&1 \|\| (\S+) up (\S+);', cmd
        )
        self.assertIsNotNone(guard, 'missing conditional link guard in: %s' % cmd)
        self.assertEqual(guard.group(1), self.iface)
        self.assertEqual(guard.group(2), self.quick)
        self.assertEqual(guard.group(3), self.config)
        # Idempotence: one guarded bring-up, no unconditional re-create.
        self.assertEqual(cmd.count('%s up %s' % (self.quick, self.config)), 1)
        self.assertNotIn('%s down' % self.quick, cmd)
        self.assertNotIn('restart', cmd)
        self.assertFalse(
            any(c.startswith('docker restart') for c in self.ssh.commands),
            self.ssh.commands,
        )

    def test_legacy_instance_uses_wg_naming(self):
        self.manager._sync_server_config('awg_legacy')
        cmd = next(c for c in self.ssh.commands if 'syncconf' in c)
        legacy_config = self.manager._config_path('awg_legacy')
        self.assertIn('ip link show wg0', cmd)
        self.assertIn('wg-quick up %s' % legacy_config, cmd)
        self.assertIn('wg syncconf wg0', cmd)


if __name__ == '__main__':
    unittest.main()

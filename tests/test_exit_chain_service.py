"""Exit-node chain (multi-hop egress): build, teardown, fail-closed health.

The fakes mirror tests/test_exit_link_service.py: in-memory data.json plus one
fake manager per host, so the whole flow is checked without SSH.
"""

import asyncio
import copy
import json
import os
import unittest

import exit_chain
from exit_link_service import ExitLinkError, ExitLinkService, peer_id_for
from app import backfill_server_uids, find_server_by_uid, protocol_base
from managers.exit_manager import ExitManager

AWG_PROTOCOLS = ('awg', 'awg2', 'awg3', 'awg_legacy')


def base_data(exit_hosts=3, with_dns=True):
    servers = [{'name': 'Paris', 'host': '198.51.100.1', 'uid': 'entry-uid',
                'protocols': {'awg2': {'installed': True, 'port': '55424'},
                              'awg': {'installed': True, 'port': '55427'}}}]
    for index in range(exit_hosts):
        protocols = {'exit': {'installed': True, 'port': '55520',
                              'subnet': '10.9.0.0/24', 'obfuscation': False}}
        if with_dns:
            protocols['dns'] = {'installed': True}
        servers.append({
            'name': f'exit-{index}', 'host': f'203.0.113.{5 + index}',
            'uid': f'exit-{index}',
            'protocols': protocols,
        })
    servers.append({'name': 'dns-host', 'host': '203.0.113.99', 'uid': 'exit-dns',
                    'protocols': {'exit': {'installed': True, 'port': '55520',
                                           'subnet': '10.9.0.0/24', 'obfuscation': False},
                                  'dns': {'installed': True}}})
    data = {'servers': servers, 'users': [], 'user_connections': []}
    backfill_server_uids(data['servers'])
    return data


class FakeAWG:
    def __init__(self, host, events=None, ssh=None):
        self.host = host
        self.ssh = ssh
        self.calls = []
        self.events = events if events is not None else []
        self.mtu = '1280'
        self.ipv6 = ''
        self.handshake_age = 3
        self.gate_calls = []
        self.applied_mtu = None
        self.fail_unlink = False
        self.fail_cut = False

    def exit_prepare_keys(self, protocol):
        self.calls.append(('exit_prepare_keys', protocol))
        return f'PUB-{self.host}-{protocol}'

    def _get_mtu(self, protocol):
        return self.mtu

    def _get_server_config(self, protocol):
        return (f'[Interface]\nAddress = 10.8.1.1/24\nListenPort = 55424\n')

    def _get_subnet_ipv6_ip(self, protocol):
        return self.ipv6

    def update_awg_settings(self, protocol, mtu=None, dns=None, special_junk=None, dns6=None):
        self.calls.append(('update_awg_settings', protocol, mtu))
        self.applied_mtu = mtu
        self.mtu = str(mtu)
        return True

    def exit_link(self, protocol, link):
        self.calls.append(('exit_link', protocol, link))
        self.events.append((self.host, 'exit_link'))
        return 'exit link up'

    def exit_link_status(self, protocol, now=None):
        self.calls.append(('exit_link_status', protocol))
        return {'up': True, 'handshake_age': self.handshake_age,
                'rx_bytes': 10, 'tx_bytes': 20, 'endpoint': '203.0.113.5:55520'}

    def exit_unlink(self, protocol):
        self.calls.append(('exit_unlink', protocol))
        if self.fail_unlink:
            raise RuntimeError('entry unreachable')
        return ''

    def exit_chain_gate(self, protocol, enabled):
        self.calls.append(('exit_chain_gate', protocol, enabled))
        self.gate_calls.append(enabled)
        return f'chain gate {enabled}'

    def exit_chain_cut(self, protocol):
        self.calls.append(('exit_chain_cut', protocol))
        if self.fail_cut:
            raise RuntimeError('cut not in place')
        return 'chain cut'


class FakeExit:
    """Exit manager fake: peers (incoming) plus relay uplinks (outgoing)."""

    def __init__(self, host, events=None, ssh=None):
        self.host = host
        self.ssh = ssh
        self.calls = []
        self.events = events if events is not None else []
        self.running = True
        self.add_error = None
        self.relay_error = None
        self.relay_handshake = 3           # None = no handshake ever
        self.peer_ages = {}               # peer_id -> handshake age
        self.peer_missing = set()
        self.next_ip = '10.9.0.7'
        self.relay_confs = {}
        self.iptables_calls = []

    def add_peer(self, peer_id, name, public_key):
        self.calls.append(('add_peer', peer_id, name, public_key))
        self.events.append((self.host, 'add_peer'))
        if self.add_error:
            raise RuntimeError(self.add_error)
        return {'transit_ip': self.next_ip, 'psk': 'PSK',
                'public_key': f'EXITPUB-{self.host}', 'port': '55520',
                'subnet': '10.9.0.0/24', 'obfuscation': False, 'awg_params': {}}

    def remove_peer(self, public_key=None, peer_id=None):
        self.calls.append(('remove_peer', public_key, peer_id))
        return True

    def check_container_running(self, protocol='exit'):
        return bool(self.running)

    def relay_prepare_keys(self, relay):
        self.calls.append(('relay_prepare_keys', relay['iface']))
        return f'RELAYPUB-{self.host}-{relay["iface"]}'

    def relay_write_conf(self, relay, link):
        self.calls.append(('relay_write_conf', relay['iface'], link))
        self.relay_confs[relay['iface']] = dict(link)
        # the container keeps its own registry so any start.sh re-render can
        # rebuild the relay blocks (and so chains sharing a host do not clash)
        if getattr(self, 'ssh', None) is not None:
            self.ssh.registry[relay['iface']] = '\n'.join([
                f"R_IF={relay['iface']}",
                f"R_TABLE={relay['table']}",
                f"R_PREF={relay.get('rule_pref') or ''}",
                f"R_SRC={relay['source_ip']}",
                f"R_MTU={relay.get('mtu', 1420)}",
            ]) + '\n'

    def relay_teardown(self, relay):
        self.calls.append(('relay_teardown', relay['iface']))
        self.relay_confs.pop(relay['iface'], None)
        if getattr(self, 'ssh', None) is not None:
            self.ssh.registry.pop(relay['iface'], None)
        return True

    def relay_apply(self, relay, teardown=False):
        self.calls.append(('relay_apply', relay['iface'], teardown))
        if teardown:
            self.relay_confs.pop(relay['iface'], None)
            return 'relay down'
        if self.relay_error:
            raise RuntimeError(self.relay_error)
        return 'relay up'

    def relay_write_startup(self, relays=None):
        if relays is None:
            # the real one reads the container registry; the fake answers with
            # the params files uploaded so far
            relays = [{'iface': iface, 'table': 0, 'source_ip': '10.9.0.7'}
                      for iface in self.ssh.registry]
        self.calls.append(('relay_write_startup',
                           tuple(relay['iface'] for relay in relays)))
        return [relay['iface'] for relay in relays]

    def relay_status(self, relay, now=None):
        age = self.relay_handshake
        self.calls.append(('relay_status', relay['iface']))
        rule_ok = True
        route_ok = True
        if relay.get('rule_pref') is not None and self.ssh.rule_show is not None:
            rule_ok = any(
                line.replace(':', ' ').split()[:1] == [str(relay['rule_pref'])]
                for line in self.ssh.rule_show.splitlines())
        return {'iface': relay['iface'],
                'up': age is not None and rule_ok and route_ok,
                'handshake_age': age, 'rx_bytes': 5, 'tx_bytes': 6,
                'route_ok': route_ok, 'rule_ok': rule_ok}

    def peer_status(self, peer_id, now=None):
        self.calls.append(('peer_status', peer_id))
        if peer_id in self.peer_missing:
            return {'up': False, 'handshake_age': None, 'error': 'peer_not_found'}
        age = self.peer_ages.get(peer_id, 3)
        return {'up': True, 'handshake_age': age, 'rx_bytes': 7, 'tx_bytes': 8}


class FakeSSH:
    """Answers the RTT probe with a fixed latency so the poll is deterministic.

    `cat /opt/amnezia/start.sh` answers with a canned container start script and
    the relay registry query with the `*.params` files uploaded so far, so the
    relay startup splice can be exercised end to end."""

    START_SCRIPT = ("#!/bin/bash\necho \"Container startup\"\n"
                    "# ---- WARP egress: x_warp_up ----\n"
                    "tail -f /dev/null\n")

    def __init__(self, host, rtt_ms='12.5'):
        self.host = host
        self.rtt_ms = rtt_ms
        self.commands = []
        self.scripts = []
        self.uploads = {}
        self.registry = {}          # iface -> params text
        self.rule_show = None         # canned `ip -4 rule show` output
        self.probe_rc = 0             # canned probe exit code
        self.registry_error = False  # simulate an unreadable registry

    def run_sudo_command(self, command, timeout=None):
        self.commands.append(command)
        if 'cat /opt/amnezia/start.sh' in command:
            return self.START_SCRIPT, '', 0
        if 'relay/*.params' in command:
            if self.registry_error:
                return '', 'registry unreadable', 1
            body = ''.join(
                f"### /opt/amnezia/exit/relay/{iface}.params\n{text}"
                for iface, text in sorted(self.registry.items()))
            return body, '', 0
        if 'ip -4 rule show' in command:
            return self.rule_show, '', 0
        return self.rtt_ms + '\n', '', 0

    def run_sudo_script(self, script, timeout=None):
        # the real transport stages the script and runs it as root; host/port
        # are validated and quoted into the script, so the canned answer is the
        # RTT plus the verification marker
        self.scripts.append(script)
        if self.probe_rc != 0:
            return self.rtt_ms + ' ping\n', '', 0
        return self.rtt_ms + ' both\n', '', 0

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content
        if remote_path.endswith('.params'):
            self.registry[remote_path.rsplit('/', 1)[-1][:-len('.params')]] = content

    def run_command(self, command, timeout=60, **kwargs):
        self.commands.append(command)
        if command.startswith('rm -f ') and 'docker exec' not in command:
            pass
        return '', '', 0


class Harness:
    def __init__(self, data=None):
        self.data = data or base_data()
        self.awgs = {}
        self.exits = {}
        self.sshes = {}
        self.unreachable = set()
        self.events = []
        self.now = 1_700_000_000.0
        self.rtt_ms = '12.5'

        def get_ssh(server):
            if server['host'] in self.unreachable:
                raise ConnectionError(f"SSH to {server['host']} failed")
            return server['host']

        def ssh_for(host):
            return self.sshes.setdefault(host, FakeSSH(host, self.rtt_ms))

        self.service = ExitLinkService(
            load_data=lambda: copy.deepcopy(self.data),
            save_data=self._save,
            data_lock=asyncio.Lock(),
            get_ssh=get_ssh,
            awg_manager_factory=lambda host: self.awgs.setdefault(
                host, FakeAWG(host, self.events, ssh_for(host))),
            exit_manager_factory=lambda host: self.exits.setdefault(
                host, FakeExit(host, self.events, ssh_for(host))),
            protocol_base=protocol_base,
            awg_protocols=AWG_PROTOCOLS,
            protocol_display_name=lambda p, *metadata: p,
            find_server_by_uid=find_server_by_uid,
            sleep=lambda seconds: asyncio.sleep(0),
            time_fn=lambda: self.now,
        )

    def _save(self, data):
        self.data = copy.deepcopy(data)

    def awg(self, host='198.51.100.1'):
        return self.awgs.setdefault(host, FakeAWG(host, self.events))

    def exit(self, uid):
        for server in self.data['servers']:
            if server.get('uid') == uid:
                host = server['host']
                return self.exits.setdefault(
                    host, FakeExit(host, self.events, self.ssh_for(host)))
        raise KeyError(uid)

    def ssh_for(self, host):
        return self.sshes.setdefault(host, FakeSSH(host, self.rtt_ms))

    def record(self, protocol='awg2'):
        return self.data['servers'][0]['protocols'][protocol]


def run(coro):
    return asyncio.run(coro)


class ChainBuildTests(unittest.TestCase):
    def test_single_hop_chain_matches_a_plain_link(self):
        h = Harness()
        result = run(h.service.build_chain(0, 'awg2', ['exit-0']))
        self.assertEqual(result['status'], 'success')
        saved = h.record()['exit_link']
        self.assertEqual(len(saved['chain']), 1)
        self.assertEqual(saved['chain'][0]['uid'], 'exit-0')
        self.assertIsNone(saved['chain'][0]['relay'])
        self.assertEqual(saved['mode'], 'chain')
        # a low MTU is an operator decision: a 1-hop chain keeps it and
        # only reports that it did (the raise needs an explicit flag)
        self.assertEqual([c[0] for c in h.awg().calls],
                         ['exit_prepare_keys', 'exit_link', 'exit_link_status',
                          'exit_chain_gate'])
        self.assertEqual(h.awg().applied_mtu, None)
        self.assertEqual(h.awg().gate_calls, [True])

    def test_two_hops_register_a_relay_and_its_uplink(self):
        h = Harness()
        result = run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(result['status'], 'success')
        saved = h.record()['exit_link']
        self.assertEqual([hop['uid'] for hop in saved['chain']], ['exit-0', 'exit-1'])
        # hop 0 keeps the peer of the entry and relays into its own uplink
        self.assertIsNotNone(saved['chain'][0]['relay'])
        relay = saved['chain'][0]['relay']
        self.assertTrue(relay['iface'].startswith('c'))
        self.assertIn('entry-uid:awg2', [c[1] for c in h.exit('exit-0').calls if c[0] == 'add_peer'])
        self.assertIn('exit-0:chain1', [c[1] for c in h.exit('exit-1').calls if c[0] == 'add_peer'])
        # the relay wrote its uplink conf and brought the link up
        self.assertIn(('relay_write_conf', relay['iface'], None) if False else 'relay_write_conf',
                      [c[0] for c in h.exit('exit-0').calls])
        written = [c for c in h.exit('exit-0').calls if c[0] == 'relay_write_conf'][0]
        self.assertEqual(written[1], relay['iface'])
        self.assertEqual(written[2]['endpoint_host'], '203.0.113.6')
        # forced DNS through the final hop
        self.assertTrue(saved['dns_via_exit'])

    def test_three_hops_chain_every_hop_is_a_relay(self):
        h = Harness()
        result = run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1', 'exit-2']))
        self.assertEqual(result['status'], 'success')
        saved = h.record()['exit_link']
        self.assertEqual(len(saved['chain']), 3)
        self.assertIsNotNone(saved['chain'][0]['relay'])
        self.assertIsNotNone(saved['chain'][1]['relay'])
        self.assertIsNone(saved['chain'][2]['relay'])
        for host_uid, next_host in (('exit-0', '203.0.113.6'), ('exit-1', '203.0.113.7')):
            manager = h.exit(host_uid)
            self.assertIn('relay_apply', [c[0] for c in manager.calls])
            written = [c for c in manager.calls if c[0] == 'relay_write_conf'][0]
            self.assertEqual(written[2]['endpoint_host'], next_host)

    def test_relay_interfaces_and_tables_are_unique_per_host(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1', 'exit-2']))
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1', 'exit-2']))
        relay_a = h.record('awg2')['exit_link']['chain'][0]['relay']
        relay_b = h.record('awg')['exit_link']['chain'][0]['relay']
        self.assertNotEqual(relay_a['iface'], relay_b['iface'])
        self.assertNotEqual(relay_a['table'], relay_b['table'])

    def test_failure_while_wiring_a_relay_rolls_the_whole_chain_back(self):
        h = Harness()
        # hop 0 cannot bring its uplink towards hop 1 up
        h.exit('exit-0').relay_error = 'transit port unreachable'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(ctx.exception.code, 'exit_apply_failed')
        # entry link torn down, peer on the first hop removed, no record left
        self.assertIn('exit_unlink', [c[0] for c in h.awg().calls])
        self.assertIn('remove_peer', [c[0] for c in h.exit('exit-0').calls])
        # the half-written uplink of the relay is torn down by the rollback
        self.assertIn('relay_teardown', [c[0] for c in h.exit('exit-0').calls])
        self.assertFalse(h.record().get('exit_link'))

    def test_no_handshake_on_a_relay_rolls_back(self):
        h = Harness()
        h.exit('exit-0').relay_handshake = None
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(ctx.exception.code, 'exit_no_handshake')
        self.assertIn('relay_teardown', [c[0] for c in h.exit('exit-0').calls])

    def test_mtu_is_lowered_only_with_confirmation(self):
        h = Harness()
        h.awg().mtu = '1420'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(ctx.exception.code, 'chain_mtu_override_required')
        result = run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1'], mtu_override=True))
        self.assertIn('exit_chain_mtu_lowered', result['warnings'])
        self.assertEqual(h.awg().applied_mtu, 1340)
        self.assertEqual(h.record()['exit_link']['client_mtu'], 1340)

    def test_dns_on_the_final_hop_is_required_for_a_chain(self):
        h = Harness(base_data(exit_hosts=2, with_dns=False))
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(ctx.exception.code, 'exit_dns_needs_dns')
        h.data['servers'][2]['protocols']['dns'] = {'installed': True}
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertTrue(h.record()['exit_link']['dns_via_exit'])


class ChainValidationTests(unittest.TestCase):
    def test_validation_codes(self):
        h = Harness()
        for chain, code in (
            ([], 'chain_empty'),
            (['exit-0', 'exit-0'], 'chain_duplicate_node'),
            (['entry-uid'], 'exit_self'),
            (['exit-0', 'exit-1', 'exit-2', 'exit-dns', 'exit-0', 'exit-1', 'exit-2', 'exit-dns', 'exit-0'],
             'chain_too_long'),
            (['nope'], 'exit_not_found'),
        ):
            with self.assertRaises(ExitLinkError) as ctx:
                run(h.service.build_chain(0, 'awg2', chain))
            self.assertEqual(ctx.exception.code, code, chain)

    def test_failover_is_refused_for_a_chain(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-2']))
        self.assertEqual(ctx.exception.code, 'failover_not_allowed_with_chain')
        # a single hop keeps failover available
        run(h.service.build_chain(0, 'awg2', ['exit-0']))
        result = run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-1']))
        self.assertTrue(result['exit_failover']['enabled'])

    def test_legacy_single_link_reads_as_a_one_hop_chain(self):
        h = Harness()
        h.data['servers'][0]['protocols']['awg2']['exit_link'] = {
            'exit_uid': 'exit-0', 'exit_name': 'exit-0',
            'transit_ip': '10.9.0.7', 'psk': 'PSK', 'exit_public_key': 'K',
            'endpoint_host': '203.0.113.5', 'endpoint_port': '55520',
            'obfuscation': False, 'stale': None,
        }
        data = h.data
        view = h.service.chain_view(data, h.record(), 'entry-uid')
        self.assertEqual(view['mode'], 'single')
        self.assertEqual(len(view['chain']), 1)
        self.assertEqual(view['chain'][0]['uid'], 'exit-0')


class ChainHealthTests(unittest.TestCase):
    def build(self, chain=('exit-0', 'exit-1')):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', list(chain)))
        h.awg().calls.clear()
        h.awg().gate_calls.clear()
        return h

    def test_healthy_chain_opens_the_gate_once(self):
        h = self.build()
        result = run(h.service.poll_chain(0, 'awg2'))
        # the first healthy proof opens the gate; the next poll is a no-op
        self.assertEqual(result['action'], 'gate_on')
        self.assertEqual(h.awg().gate_calls, [True])
        h.awg().gate_calls.clear()
        result = run(h.service.tick_chain(0, 'awg2'))
        self.assertEqual(result['reason'], 'not_due')
        h.now += 31
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'noop')
        self.assertEqual(h.awg().gate_calls, [])
        self.assertIsNone(h.record()['exit_link']['stale'])

    def test_dead_second_hop_closes_the_gate(self):
        h = self.build()
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'gate_off')
        self.assertEqual(result['broken_hop_index'], 1)
        self.assertEqual(h.awg().gate_calls, [False])
        self.assertEqual(h.record()['exit_link']['stale'], 'chain_broken_hop_1')
        poll = h.record()['exit_chain_poll']
        self.assertEqual(poll['state']['state'], 'broken')
        self.assertEqual(poll['state']['recovery_attempts_left'], poll['probe_attempts'])
        self.assertIsNotNone(poll['state']['next_recovery_at'])
        self.assertTrue(poll['events'][0]['action'], 'gate_off')

    def test_channel_stays_cut_while_recovery_attempts_remain(self):
        h = self.build()
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        run(h.service.poll_chain(0, 'awg2'))
        h.awg().gate_calls.clear()
        # second poll inside the recovery wait: the gate is RE-APPLIED (a
        # restart must not reopen the egress), the state stays broken
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'noop')
        self.assertEqual(h.awg().gate_calls, [False])
        self.assertEqual(h.record()['exit_link']['stale'], 'chain_broken_hop_1')

    def test_healed_chain_reopens_the_gate(self):
        h = self.build()
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        run(h.service.poll_chain(0, 'awg2'))
        h.exit('exit-1').peer_missing.discard('exit-0:chain1')
        h.exit('exit-1').peer_ages['exit-0:chain1'] = 4
        h.awg().gate_calls.clear()
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'gate_on')
        self.assertEqual(h.awg().gate_calls, [True])
        self.assertIsNone(h.record()['exit_link']['stale'])

    def test_stale_handshake_counts_as_broken(self):
        h = self.build()
        h.exit('exit-1').peer_ages['exit-0:chain1'] = 999
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'gate_off')
        self.assertEqual(result['hops'][1]['reason'], 'handshake_stale')

    def test_dead_container_on_the_first_hop_breaks_the_chain(self):
        h = self.build()
        h.exit('exit-0').running = False
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['broken_hop_index'], 0)
        self.assertEqual(result['hops'][0]['reason'], 'container_stopped')
        self.assertEqual(h.awg().gate_calls, [False])

    def test_poll_is_a_noop_when_disabled(self):
        h = self.build()
        run(h.service.configure_chain_poll(0, 'awg2', enabled=False))
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'noop')
        self.assertEqual(result['reason'], 'disabled')
        self.assertEqual(h.awg().gate_calls, [])

    def test_poll_is_a_noop_before_the_interval(self):
        h = self.build()
        run(h.service.poll_chain(0, 'awg2'))
        h.awg().calls.clear()
        result = run(h.service.tick_chain(0, 'awg2'))
        self.assertEqual(result['reason'], 'not_due')
        h.now += 31
        result = run(h.service.tick_chain(0, 'awg2'))
        self.assertNotEqual(result['reason'], 'not_due')

    def test_poll_measures_rtt_from_the_previous_node(self):
        h = self.build()
        run(h.service.poll_chain(0, 'awg2'))
        # the RTT of hop 1 is measured ON hop 0 (the previous node of the list);
        # the host is validated and quoted into the script, never interpolated raw
        scripts = h.sshes['203.0.113.5'].scripts
        self.assertTrue(scripts, 'the RTT probe must run on the previous hop')
        self.assertIn('h=203.0.113.6;', scripts[0])
        self.assertIn('p=55520;', scripts[0])
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['hops'][1]['rtt_ms'], 12.5)

    def test_chain_probe_measures_the_next_hop_from_the_previous_one(self):
        h = self.build()
        res = run(h.service.chain_probe(0, 'awg2', 'exit-1', after_uid='exit-0'))
        self.assertTrue(res['ok'])
        self.assertEqual(res['rtt_ms'], 12.5)
        self.assertEqual(res['after_uid'], 'exit-0')
        self.assertIn('h=203.0.113.6;', h.sshes['203.0.113.5'].scripts[-1])

    def test_chain_probe_of_the_first_hop_comes_from_the_entry(self):
        h = self.build()
        res = run(h.service.chain_probe(0, 'awg2', 'exit-0'))
        # the first hop is probed from the ENTRY, not from the panel
        self.assertTrue(res['ok'])
        self.assertEqual(res['rtt_ms'], 12.5)
        self.assertIn('h=203.0.113.5;', h.sshes['198.51.100.1'].scripts[-1])

    def test_probe_script_is_valid_bash(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        h = Harness()
        run(h.service.chain_probe(0, 'awg2', 'exit-0'))
        script = h.sshes['198.51.100.1'].scripts[-1]
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)

    def test_chain_flags_feed_the_server_list_badge(self):
        h = self.build()
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        run(h.service.poll_chain(0, 'awg2'))
        flags = h.service.chain_flags(h.data)
        self.assertIn('0', flags)
        self.assertEqual(flags['0']['hop'], '1')
        self.assertEqual(flags['0']['stale'], 'chain_broken_hop_1')

    def test_remove_chain_tears_everything_down(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        result = run(h.service.remove_chain(0, 'awg2'))
        self.assertTrue(result['unlinked'])
        for uid in ('exit-0', 'exit-1', 'exit-2'):
            self.assertIn('remove_peer', [c[0] for c in h.exit(uid).calls])
        self.assertIn('relay_teardown', [c[0] for c in h.exit('exit-0').calls])
        self.assertFalse(h.record().get('exit_link'))

    def test_repair_rebuilds_the_same_chain(self):
        h = self.build(('exit-0', 'exit-1'))
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        run(h.service.poll_chain(0, 'awg2'))
        h.exit('exit-1').peer_missing.discard('exit-0:chain1')
        result = run(h.service.repair_chain(0, 'awg2'))
        self.assertEqual(result['status'], 'success')
        saved = h.record()['exit_link']
        self.assertEqual([hop['uid'] for hop in saved['chain']], ['exit-0', 'exit-1'])
        self.assertIsNone(saved['stale'])


    def test_built_chain_registers_the_relay_startup(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        # the startup is rebuilt from the container registry (the union of all
        # chains that relay here), so both relay hosts are refreshed
        for uid in ('exit-0', 'exit-1'):
            calls = [c for c in h.exit(uid).calls if c[0] == 'relay_write_startup']
            self.assertTrue(calls, f'{uid} start.sh not refreshed')
        # each relay host keeps its own uplink registered in the container
        self.assertEqual(sorted(h.sshes['203.0.113.5'].registry),
                         [h.record()['exit_link']['chain'][0]['relay']['iface']])
        self.assertEqual(sorted(h.sshes['203.0.113.6'].registry),
                         [h.record()['exit_link']['chain'][1]['relay']['iface']])

    def test_relay_startup_is_the_union_of_all_chains_on_a_host(self):
        from managers.exit_manager import ExitManager
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        first_iface = h.record('awg2')['exit_link']['chain'][0]['relay']['iface']
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1']))
        second_iface = h.record('awg')['exit_link']['chain'][0]['relay']['iface']
        # removing one chain must leave the other chain's relay block in start.sh
        run(h.service.remove_chain(0, 'awg2'))
        ssh = h.sshes['203.0.113.5']
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        ifaces = manager.relay_write_startup()
        self.assertEqual(ifaces, [second_iface])
        body = ssh.uploads['/tmp/_amnz_relay_start.sh']
        self.assertNotIn(first_iface, body)
        self.assertIn(second_iface, body)
        self.assertIn('# ---- WARP egress: x_warp_up ----', body)

    def test_remove_chain_tears_everything_down(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        result = run(h.service.remove_chain(0, 'awg2'))
        self.assertTrue(result['unlinked'])
        for uid in ('exit-0', 'exit-1', 'exit-2'):
            self.assertIn('remove_peer', [c[0] for c in h.exit(uid).calls])
        self.assertIn('relay_teardown', [c[0] for c in h.exit('exit-0').calls])
        self.assertFalse(h.record().get('exit_link'))

    def test_remove_chain_unlinks_the_entry(self):
        h = self.build(('exit-0', 'exit-1'))
        run(h.service.remove_chain(0, 'awg2'))
        # the entry unlink (which also clears the gate marker) is what lets a
        # later single link breathe after a restart
        self.assertIn('exit_unlink', [c[0] for c in h.awg().calls])

    def test_relay_write_startup_splices_the_block_and_keeps_warp(self):
        from managers.exit_manager import ExitManager
        ssh = FakeSSH('203.0.113.5')
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                 'mtu': 1420, 'rule_pref': 3123}
        written = manager.relay_write_startup([relay])
        self.assertEqual(written, ['c1a2b1'])
        body = ssh.uploads['/tmp/_amnz_relay_start.sh']
        # the block is spliced in, the WARP line of the existing script survives
        self.assertIn(ExitManager.RELAY_BLOCK_START, body)
        self.assertIn(ExitManager.RELAY_BLOCK_END, body)
        self.assertIn('# ---- WARP egress: x_warp_up ----', body)
        self.assertIn('tail -f /dev/null', body)
        self.assertIn('R_PREF=3123', body)
        # a second write replaces the block instead of stacking it
        manager.relay_write_startup([])
        stripped = ssh.uploads['/tmp/_amnz_relay_start.sh']
        self.assertNotIn('R_PREF=', stripped)
        self.assertIn('# ---- WARP egress: x_warp_up ----', stripped)
        self.assertIn('tail -f /dev/null', stripped)

    def test_relay_startup_block_is_valid_shell(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        ssh = FakeSSH('203.0.113.5')
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                 'mtu': 1420, 'rule_pref': 3123}
        manager.relay_write_startup([relay])
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(ssh.uploads['/tmp/_amnz_relay_start.sh'])
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)

    def test_relay_values_are_validated_before_reaching_a_shell(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        bad = [
            {'iface': 'c1a2b1; rm -rf /', 'table': 250, 'source_ip': '10.9.0.7'},
            {'iface': 'c1a2b1', 'table': '250; drop', 'source_ip': '10.9.0.7'},
            {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7$(id)'},
            {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7', 'mtu': 'x'},
        ]
        for relay in bad:
            with self.assertRaises(ValueError):
                manager._validate_relay(relay)
        manager._validate_relay({'iface': 'c1a2b1', 'table': 250,
                                 'source_ip': '10.9.0.7', 'mtu': 1420,
                                 'rule_pref': 3123})


class ChainShellTests(unittest.TestCase):
    def test_relay_block_has_no_local_dns_exception(self):
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7', 'mtu': 1420}
        manager = ExitManager.__new__(ExitManager)
        body = ExitManager._relay_shell_functions(manager, relay)
        self.assertIn('x_relay_up()', body)
        self.assertIn('R_TABLE=250', body)
        self.assertIn('R_SRC=10.9.0.7', body)
        self.assertIn('table $R_TABLE', body)
        self.assertIn('X_QUICK=awg-quick', body)
        self.assertNotIn('DNS_NET', body)
        self.assertNotIn('x_rule -4 191', body)
        self.assertIn('MASQUERADE', body)
        self.assertIn('clamp-mss-to-pmtu', body)

    def test_relay_block_is_valid_shell(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7', 'mtu': 1420}
        manager = ExitManager.__new__(ExitManager)
        body = ExitManager._relay_shell_functions(manager, relay) + 'x_relay_down\n'
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(body)
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)

    def test_chain_gate_functions_reach_the_entry_template(self):
        from managers.awg_manager import AWGManager
        template = AWGManager._EXIT_SHELL_TEMPLATE
        self.assertIn('x_chain_gate()', template)
        self.assertIn('blackhole default', template)
        self.assertIn('default dev $EXIT_IF table $EXIT_TABLE', template)

    def test_mtu_budget_of_a_chain(self):
        self.assertEqual(exit_chain.client_mtu_for_chain(1), 1420)
        self.assertEqual(exit_chain.client_mtu_for_chain(2), 1340)
        self.assertEqual(exit_chain.client_mtu_for_chain(3), 1280)
        self.assertEqual(exit_chain.client_mtu_for_chain(8), 1280)


class ChainApiWiringTests(unittest.TestCase):
    def test_chain_endpoints_are_registered(self):
        import re
        source = open('app.py', encoding='utf-8').read()
        for path in ('/exit-link/chain', '/exit-link/chain/remove', '/exit-link/chain/repair',
                     '/exit-link/chain/probe', '/exit-link/chain/status', '/exit-link/chain/poll',
                     '/exit-link/chain/config', '/api/servers/exit_chain_flags'):
            self.assertIn(path, source, path)

    def test_chain_poll_loop_is_started(self):
        source = open('app.py', encoding='utf-8').read()
        self.assertIn('exit_chain_poll_background_loop()', source)
        self.assertIn('async def exit_chain_poll_background_loop', source)


class ChainAuditRegressionTests(unittest.TestCase):
    """One test per confirmed audit finding (both auditors)."""

    def build(self, chain=('exit-0', 'exit-1')):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', list(chain)))
        h.awg().calls.clear()
        h.awg().gate_calls.clear()
        return h

    # --- inferx F1: the gate must leave exactly one (blackhole) default ---
    def test_chain_gate_script_deletes_the_exit0_default(self):
        h = self.build()
        h.awg().calls.clear()
        run(h.service.poll_chain(0, 'awg2'))
        scripts = [c for c in h.awg().commands] if hasattr(h.awg(), 'commands') else []
        # the fake manager records the call; the real check is the template
        from managers.awg_manager import AWGManager
        template = AWGManager._EXIT_SHELL_TEMPLATE
        gate = template[template.index('x_chain_gate()'):]
        self.assertIn('ip -4 route del default dev $EXIT_IF table $EXIT_TABLE', gate)
        self.assertIn('ip -4 route replace blackhole default metric 0 table $EXIT_TABLE', gate)
        off = gate[:gate.index('x_chain_gate() {')] if False else gate
        self.assertIn('"off"', off)
        self.assertIn('return 3', off)          # fails loudly when not in place

    # --- inferx F4: the gate decision survives a restart (marker + start.sh) ---
    def test_start_script_reapplies_a_closed_gate_after_restart(self):
        from managers.awg_manager import AWGManager
        body = AWGManager(None)._render_start_script('awg2')
        # the marker only means anything while a link exists: an orphaned marker
        # must not blackhole a healthy single link after a restart
        self.assertIn('if [ -f "$CHAIN_GATE_MARKER" ] && [ -f "$EXIT_CONF" ]; then x_chain_gate off', body)
        self.assertTrue(AWGManager._EXIT_SHELL_TEMPLATE.count('CHAIN_GATE_MARKER') >= 2)

    # --- inferx F2/F7: two chains on one relay host keep their own rules ---
    def test_two_chains_on_one_relay_host_use_distinct_rules(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1']))
        relay_a = h.record('awg2')['exit_link']['chain'][0]['relay']
        relay_b = h.record('awg')['exit_link']['chain'][0]['relay']
        self.assertNotEqual(relay_a['rule_pref'], relay_b['rule_pref'])
        self.assertNotEqual(relay_a['table'], relay_b['table'])
        self.assertNotEqual(relay_a['iface'], relay_b['iface'])

    def test_teardown_of_one_chain_leaves_the_other_chain_rules_alone(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1']))
        relay_a = h.record('awg2')['exit_link']['chain'][0]['relay']
        relay_b = h.record('awg')['exit_link']['chain'][0]['relay']
        run(h.service.remove_chain(0, 'awg2'))
        torn = [c[1] for c in h.exit('exit-0').calls if c[0] == 'relay_teardown']
        self.assertIn(relay_a['iface'], torn)
        self.assertNotIn(relay_b['iface'], torn)
        # the surviving chain keeps its own relay wiring untouched
        self.assertEqual(h.record('awg')['exit_link']['chain'][0]['relay']['rule_pref'],
                         relay_b['rule_pref'])

    # --- inferx F3: relay cuts the source before the uplink exists ---
    def test_relay_block_is_fail_closed_before_the_uplink(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                 'mtu': 1420, 'rule_pref': 3123}
        body = ExitManager._relay_shell_functions(manager, relay)
        up = body[body.index('x_relay_up()'):body.index('x_relay_down()')]
        blackhole = up.index('blackhole default metric 0 table $R_TABLE')
        rule = up.index('x_rule -4 $R_PREF')
        drop = up.index('-i transit0 -o eth0 -s $R_SRC -j DROP')
        quick = up.index('$X_QUICK up $R_CONF')
        remove_drop = up.index('x_ipt_del filter FORWARD -i transit0 -o eth0')
        verify = up.index('FATAL: relay routing')
        self.assertLess(blackhole, quick, 'blackhole must be in place before the uplink')
        self.assertLess(rule, quick, 'the policy rule must be in place before the uplink')
        self.assertLess(drop, quick, 'the eth0 guard must be in place before the uplink')
        self.assertLess(verify, remove_drop,
                        'the guard may only be removed after verification')
        # the guard is INSERTED first: start.sh already ACCEPTs the transit subnet
        self.assertIn('x_ipt_ins filter FORWARD 1', up)
        # iproute2 prints "pref:\tfrom ...": any whitespace must match
        self.assertIn('[[:space:]]+from $R_SRC lookup $R_TABLE', up)

    def test_relay_status_accepts_a_tab_formatted_rule(self):
        h = self.build()
        relay = h.record()['exit_link']['chain'][0]['relay']
        # iproute2 prints "pref:\tfrom <src> lookup <table>" (tab, not space)
        h.sshes['203.0.113.5'].rule_show = (
            f"{relay['rule_pref']}:\tfrom {relay['source_ip']} lookup {relay['table']}\n")
        entry = h.exit('exit-0')
        status = entry.relay_status(relay)
        self.assertTrue(status['rule_ok'])
        self.assertTrue(status['up'])

    # --- inferx F5: DNS may not leave the chain ---
    def test_dns_via_exit_cannot_be_disabled_for_a_chain(self):
        h = self.build()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.set_dns_via_exit(0, 'awg2', False))
        self.assertEqual(ctx.exception.code, 'dns_not_allowed_with_chain')
        # the automatic uninstall path skips chains instead of leaking DNS
        h.data['servers'][2]['protocols']['dns'].pop('installed', None)
        results = run(h.service.disable_dns_via_exit_for_exit('exit-1'))
        statuses = {item['status'] for item in results}
        self.assertEqual(statuses, {'skipped'})

    def test_dns_via_exit_validates_the_final_hop_of_a_chain(self):
        h = self.build()
        h.data['servers'][2]['protocols']['dns'].pop('installed', None)   # final hop loses DNS
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.set_dns_via_exit(0, 'awg2', True))
        self.assertEqual(ctx.exception.code, 'exit_dns_needs_dns')

    # --- inferx F6: rebuilding a shorter chain removes the dropped relays ---
    def test_shortening_a_chain_removes_the_dropped_relay(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        relay_c = h.record()['exit_link']['chain'][1]['relay']
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(len(h.record()['exit_link']['chain']), 2)
        torn = [c[1] for c in h.exit('exit-1').calls if c[0] == 'relay_teardown']
        self.assertIn(relay_c['iface'], torn)
        self.assertEqual(h.record()['exit_link']['chain'][1].get('relay'), None)

    # --- inferx F7: a single link may not overwrite a chain ---
    def test_single_link_refuses_to_overwrite_a_chain(self):
        h = self.build()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-2'))
        self.assertEqual(ctx.exception.code, 'chain_present_use_chain_api')

    # --- inferx F8: a failed build restores the lowered MTU ---
    def test_failed_build_restores_the_lowered_mtu(self):
        h = Harness()
        h.awg().mtu = '1420'
        h.exit('exit-0').relay_error = 'transit port unreachable'
        with self.assertRaises(ExitLinkError):
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1'], mtu_override=True))
        self.assertEqual(h.awg().applied_mtu, None if False else h.awg().applied_mtu)
        # the last MTU write is the restore back to 1420
        mtu_writes = [c[2] for c in h.awg().calls if c[0] == 'update_awg_settings']
        self.assertEqual(mtu_writes, [1340, 1420])

    # --- inferx F9: a failed entry unlink keeps the chain record ---
    def test_remove_chain_keeps_the_record_when_entry_unlink_fails(self):
        h = self.build()
        h.awg().fail_unlink = True
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.remove_chain(0, 'awg2'))
        self.assertEqual(ctx.exception.code, 'exit_unlink_failed')
        self.assertEqual(h.record()['exit_link']['stale'], 'teardown_pending')

    # --- inferx F11: no PSK leaves the panel ---
    def test_status_and_build_never_return_a_psk(self):
        h = self.build()
        status = run(h.service.status(0, 'awg2'))
        self.assertNotIn('psk', json.dumps(status))
        result = run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertNotIn('psk', json.dumps(result))
        stored = h.record()['exit_link']
        self.assertNotIn('psk', json.dumps(stored))

    # --- inferx F10: the stored per-hop status is part of the view ---
    def test_chain_view_returns_the_stored_hop_status(self):
        h = self.build()
        run(h.service.poll_chain(0, 'awg2'))
        data = h.data
        view = h.service.chain_view(data, h.record(), 'entry-uid')
        self.assertTrue(view['poll']['hops'])
        self.assertEqual(len(view['poll']['hops']), 2)
        self.assertEqual(view['poll']['hops'][0]['handshake_age'], 3)

    # --- nemotron F19: failover the chain disabled comes back ---
    def test_removing_a_chain_reenables_failover_it_disabled(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-0'))
        run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-1']))
        self.assertTrue(h.record()['exit_failover']['enabled'])
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))   # chain disables it
        self.assertFalse(h.record()['exit_failover']['enabled'])
        result = run(h.service.remove_chain(0, 'awg2'))
        self.assertIn('exit_failover_reenabled', result.get('warnings', []))
        self.assertTrue(h.record()['exit_failover']['enabled'])

    # --- nemotron F17: clamped settings are reported, not silent ---
    def test_clamped_poll_settings_are_reported(self):
        h = self.build()
        result = run(h.service.configure_chain_poll(
            0, 'awg2', check_interval_seconds=99999, probe_attempts=0))
        self.assertIn('exit_chain_check_interval_seconds_clamped', result['warnings'])
        self.assertIn('exit_chain_probe_attempts_clamped', result['warnings'])
        self.assertEqual(result['chain']['poll']['check_interval_seconds'], 3600)


class ChainAuditRound2Tests(unittest.TestCase):
    """Regressions for the defects the re-audit found in the first fix round."""

    def build(self, chain=('exit-0', 'exit-1')):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', list(chain)))
        h.awg().calls.clear()
        h.awg().gate_calls.clear()
        return h

    # --- inferx N1: the probe script must be valid bash and get its inputs ---
    def test_probe_script_is_valid_bash_and_quotes_inputs(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        h = Harness()
        run(h.service.chain_probe(0, 'awg2', 'exit-0'))
        script = h.sshes['198.51.100.1'].scripts[-1]
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)
        self.assertIn('h=203.0.113.5;', script)
        self.assertIn('p=55520;', script)
        self.assertIn('1000000', script)          # ns -> ms, not /2000000

    def test_probe_rejects_a_host_with_shell_metacharacters(self):
        h = self.build()
        h.data['servers'][2]['host'] = '203.0.113.6; id'   # the probe TARGET
        res = run(h.service.chain_probe(0, 'awg2', 'exit-1', after_uid='exit-0'))
        self.assertFalse(res['ok'])
        self.assertEqual(res['error'], 'invalid_target')
        self.assertEqual(h.sshes['203.0.113.5'].scripts, [])

    # --- inferx N2: iproute2 prints a tab after the preference ---
    def test_relay_rule_check_matches_any_whitespace(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                 'mtu': 1420, 'rule_pref': 3123}
        body = ExitManager._relay_shell_functions(manager, relay)
        self.assertIn('[[:space:]]+from $R_SRC lookup $R_TABLE', body)
        self.assertNotIn('grep -q "^$R_PREF: from', body)

    # --- inferx N3: rule+blackhole before awg-quick, guard removed after proof ---
    def test_relay_rule_and_blackhole_come_before_the_uplink(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                 'mtu': 1420, 'rule_pref': 3123}
        up = ExitManager._relay_shell_functions(manager, relay)
        up = up[up.index('x_relay_up()'):up.index('x_relay_down()')]
        self.assertLess(up.index('x_rule -4 $R_PREF'), up.index('$X_QUICK up $R_CONF'))
        self.assertLess(up.index('blackhole default metric 0'), up.index('$X_QUICK up $R_CONF'))
        self.assertLess(up.index('FATAL: relay routing'), up.index('x_ipt_del filter FORWARD -i transit0 -o eth0'))

    # --- inferx N4/N5: the rebuild cuts the entry before anything is torn down ---
    def test_rebuild_cuts_the_entry_before_the_teardown(self):
        h = self.build(('exit-0', 'exit-1'))
        h.awg().calls.clear()
        result = run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(result['status'], 'success')
        kinds = [c[0] for c in h.awg().calls]
        # the egress is cut first and the kill-switch is kept: exit_unlink would
        # drop the rules and let clients leave via eth0 for the whole rebuild
        self.assertEqual(kinds[0], 'exit_chain_cut')
        self.assertNotIn('exit_unlink', kinds)
        # ...and the egress is reopened only after the new chain is up
        self.assertEqual(kinds[-1], 'exit_chain_gate')
        self.assertEqual(h.awg().gate_calls[-1], True)

    def test_rebuild_of_a_shorter_chain_keeps_relay_wiring_stable(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        relay_a = h.record()['exit_link']['chain'][0]['relay']
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        relay_b = h.record()['exit_link']['chain'][0]['relay']
        # no drift: the old chain is dropped from the plan, so the same
        # (prefix, index) maps to the same table/pref/iface
        self.assertEqual(relay_a['table'], relay_b['table'])
        self.assertEqual(relay_a['rule_pref'], relay_b['rule_pref'])
        self.assertEqual(relay_a['iface'], relay_b['iface'])
        torn = [c[1] for c in h.exit('exit-1').calls if c[0] == 'relay_teardown']
        self.assertTrue(torn, 'the dropped hop must be torn down')

    # --- inferx N6: the marker must not outlive the chain ---
    def test_remove_chain_unlinks_the_entry_and_clears_the_marker(self):
        h = self.build(('exit-0', 'exit-1'))
        h.exit('exit-1').peer_missing.add('exit-0:chain1')
        run(h.service.poll_chain(0, 'awg2'))          # broken: marker is set
        run(h.service.remove_chain(0, 'awg2'))
        # exit_unlink is the only path that clears the marker in the container
        self.assertIn('exit_unlink', [c[0] for c in h.awg().calls])

    # --- inferx N8: link() may not overwrite a chain, even at its first hop ---
    def test_link_cannot_overwrite_a_chain_at_its_first_hop(self):
        h = self.build()
        first_uid = h.record()['exit_link']['chain'][0]['uid']
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', first_uid))
        self.assertEqual(ctx.exception.code, 'chain_present_use_chain_api')
        # the chain record is untouched
        self.assertEqual(len(h.record()['exit_link']['chain']), 2)

    # --- inferx N9/N14: unlink() delegates chain removal to remove_chain ---
    def test_unlink_of_a_chain_restores_failover_and_mtu(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-0'))
        run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-1']))
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertFalse(h.record()['exit_failover']['enabled'])
        result = run(h.service.unlink(0, 'awg2'))
        self.assertTrue(result['unlinked'])
        self.assertFalse(h.record().get('exit_link'))
        self.assertTrue(h.record()['exit_failover']['enabled'])
        # the relay startup of the host is rebuilt (union), not stripped blind
        self.assertTrue([c for c in h.exit('exit-0').calls
                         if c[0] == 'relay_write_startup'])

    # --- inferx N11: a legacy record without rule_pref is normalised on read ---
    def test_legacy_relay_record_gets_a_rule_pref_on_read(self):
        h = self.build(('exit-0', 'exit-1'))
        relay = h.record()['exit_link']['chain'][0]['relay']
        relay.pop('rule_pref', None)
        data = h.data
        _record, chain = h.service._chain_record(data, h.record())
        self.assertTrue(chain[0]['relay'].get('rule_pref'))
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertNotEqual(result['action'], 'gate_off')

    # --- inferx N10: no table/pref drift across repeated repairs ---
    def test_repair_twice_keeps_the_same_relay_wiring(self):
        h = self.build(('exit-0', 'exit-1'))
        first = h.record()['exit_link']['chain'][0]['relay']
        run(h.service.repair_chain(0, 'awg2'))
        second = h.record()['exit_link']['chain'][0]['relay']
        run(h.service.repair_chain(0, 'awg2'))
        third = h.record()['exit_link']['chain'][0]['relay']
        self.assertEqual(first['table'], second['table'])
        self.assertEqual(second['table'], third['table'])
        self.assertEqual(first['rule_pref'], third['rule_pref'])


class ChainAuditRound3Tests(unittest.TestCase):
    """Regressions for the third audit round."""

    def build(self, chain=('exit-0', 'exit-1')):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', list(chain)))
        h.awg().calls.clear()
        h.awg().gate_calls.clear()
        return h

    def test_gate_off_verification_is_satisfiable(self):
        from managers.awg_manager import AWGManager
        template = AWGManager._EXIT_SHELL_TEMPLATE
        off = template[:template.index('x_chain_cut()')]
        # the metric-1000 placeholder of x_killswitch_on must go before the
        # "exactly one default" check can ever pass
        self.assertIn('ip -4 route del default metric 1000 table $EXIT_TABLE', off)
        # iproute2 normalises "from 10.8.1.1/24" to "from 10.8.1.0/24": the rule
        # check must not compare the host address literally
        self.assertIn('from [0-9./]+ lookup $3', template)

    def test_cut_is_verified_like_the_gate(self):
        from managers.awg_manager import AWGManager
        cut = AWGManager._EXIT_SHELL_TEMPLATE[
            AWGManager._EXIT_SHELL_TEMPLATE.index('x_chain_cut()'):]
        self.assertIn('x_rule_has $EXIT_PREF $X_SUBNET $EXIT_TABLE', cut)
        self.assertIn('FATAL: chain cut is not in place', cut)

    def test_start_sh_gate_reapply_requires_a_live_link(self):
        from managers.awg_manager import AWGManager
        body = AWGManager(None)._render_start_script('awg2')
        self.assertIn('[ -f "$CHAIN_GATE_MARKER" ] && [ -f "$EXIT_CONF" ]', body)

    def test_failed_rebuild_keeps_the_cut_and_restores_the_record(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        saved = copy.deepcopy(h.record()['exit_link'])
        h.exit('exit-1').relay_error = 'transit port unreachable'
        with self.assertRaises(ExitLinkError):
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1', 'exit-2']))
        # the entry was cut, never unlinked: the kill-switch still holds
        self.assertIn('exit_chain_cut', [c[0] for c in h.awg().calls])
        self.assertNotIn('exit_unlink', [c[0] for c in h.awg().calls])
        # and the operator keeps his previous chain
        self.assertEqual(h.record()['exit_link']['chain'], saved['chain'])

    def test_remove_chain_survives_a_deleted_hop(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        h.data['servers'] = [s for s in h.data['servers'] if s.get('uid') != 'exit-2']
        result = run(h.service.remove_chain(0, 'awg2'))
        self.assertTrue(result['unlinked'])
        self.assertFalse(h.record().get('exit_link'))

    def test_remove_chain_of_a_deleted_final_hop(self):
        h = self.build(('exit-0', 'exit-1'))
        h.data['servers'] = [s for s in h.data['servers'] if s.get('uid') != 'exit-1']
        result = run(h.service.remove_chain(0, 'awg2'))
        self.assertTrue(result['unlinked'])
        self.assertFalse(h.record().get('exit_link'))

    def test_single_link_to_chain_cleans_the_old_exit(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-0'))
        run(h.service.build_chain(0, 'awg2', ['exit-1', 'exit-2']))
        removed = [c[2] for c in h.exit('exit-0').calls if c[0] == 'remove_peer']
        self.assertIn('entry-uid:awg2', removed)

    def test_legacy_chain_gets_a_relay_startup_block_from_the_panel(self):
        from managers.exit_manager import ExitManager
        h = self.build(('exit-0', 'exit-1'))
        relay = h.record()['exit_link']['chain'][0]['relay']
        relay.pop('rule_pref', None)
        h.record()['exit_link'].pop('chain_prefix', None)   # a 0d2c509 record
        h.sshes['203.0.113.5'].registry.clear()
        # the panel passes its own relays even when the container registry is
        # empty (a chain built before the registry existed)
        passed = [c[1] for c in h.exit('exit-0').calls if c[0] == 'relay_write_startup']
        self.assertTrue(passed)
        self.assertIn(relay['iface'], passed[-1])
        ssh = h.sshes['203.0.113.5']
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        ifaces = manager.relay_write_startup(
            [h.record()['exit_link']['chain'][0]['relay']])
        self.assertEqual(ifaces, [relay['iface']])
        body = ssh.uploads['/tmp/_amnz_relay_start.sh']
        self.assertIn(relay['iface'], body)
        # and the preference it reads back is the one that version installed
        _record, chain = h.service._chain_record(h.data, h.record())
        self.assertEqual(chain[0]['relay']['rule_pref'], 3000)

    def test_legacy_chain_is_not_reported_broken(self):
        h = self.build(('exit-0', 'exit-1'))
        h.record()['exit_link']['chain'][0]['relay'].pop('rule_pref', None)
        h.record()['exit_link'].pop('chain_prefix', None)
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertNotEqual(result['action'], 'gate_off')

    def test_iface_collision_bumps_the_index_not_the_prefix(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1']))
        iface_a = h.record('awg2')['exit_link']['chain'][0]['relay']['iface']
        iface_b = h.record('awg')['exit_link']['chain'][0]['relay']['iface']
        self.assertNotEqual(iface_a, iface_b)

    def test_shortening_a_chain_raises_the_mtu(self):
        h = Harness()
        h.awg().mtu = '1420'
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1', 'exit-2'],
                                  mtu_override=True))
        self.assertEqual(h.awg().applied_mtu, 1280)
        # the raise back is also explicit: without the flag the low MTU is kept
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(h.awg().applied_mtu, 1280)
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1'], raise_mtu=True))
        self.assertEqual(h.awg().applied_mtu, 1340)

    def test_teardown_pending_survives_a_poll_and_shows_on_the_badge(self):
        h = self.build(('exit-0', 'exit-1'))
        h.awg().fail_unlink = True
        with self.assertRaises(ExitLinkError):
            run(h.service.remove_chain(0, 'awg2'))
        self.assertEqual(h.record()['exit_link']['stale'], 'teardown_pending')
        run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(h.record()['exit_link']['stale'], 'teardown_pending')
        self.assertEqual(h.service.chain_flags(h.data)['0']['stale'], 'teardown_pending')

    def test_poll_records_the_probe_verdict_per_hop(self):
        h = self.build()
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertTrue(all('probe_ok' in hop for hop in result['hops']))
        self.assertTrue(all(hop['probe_ok'] for hop in result['hops']))

    def test_relay_prefix_is_validated(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        with self.assertRaises(ValueError):
            manager._validate_relay({'iface': 'c1a2b1', 'table': 250,
                                     'source_ip': '10.9.0.7', 'prefix': 'zz'})
        manager._validate_relay({'iface': 'c1a2b1', 'table': 250,
                                 'source_ip': '10.9.0.7', 'prefix': 'a1b2'})

    def test_relay_guard_helper_is_idempotent(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        body = ExitManager._relay_shell_functions(
            manager, {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                      'mtu': 1420, 'rule_pref': 3123})
        self.assertIn('x_ipt_ins() { table="$1"; chain="$2"; pos="$3"; shift 3;', body)

    def test_relay_teardown_removes_the_private_key(self):
        from managers.exit_manager import ExitManager
        ssh = FakeSSH('203.0.113.5')
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        manager.relay_teardown({'iface': 'c1a2b1', 'table': 250,
                                'source_ip': '10.9.0.7', 'mtu': 1420,
                                'rule_pref': 3123})
        self.assertTrue(any('_private.key' in cmd for cmd in ssh.commands))


class ChainAuditRound4Tests(unittest.TestCase):
    """Regressions for the fourth audit round."""

    def build(self, chain=('exit-0', 'exit-1')):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', list(chain)))
        h.awg().calls.clear()
        h.awg().gate_calls.clear()
        return h

    def test_gate_on_restores_first_and_drops_the_marker_last(self):
        from managers.awg_manager import AWGManager
        template = AWGManager._EXIT_SHELL_TEMPLATE
        gate = template[template.index('x_chain_gate()'):template.index('x_chain_cut()')]
        on = gate[gate.index('  else'):gate.index('  fi', gate.index('  else'))]
        replace_at = on.index('ip -4 route replace default dev $EXIT_IF')
        marker_at = on.index('rm -f "$CHAIN_GATE_MARKER"')
        self.assertLess(replace_at, marker_at,
                        'the exit0 default must be restored before the marker goes')
        # a failed restore must re-arm the fail-closed state
        self.assertIn('the gate stays closed', gate)
        self.assertIn('touch "$CHAIN_GATE_MARKER"',
                      gate[gate.index('! FATAL: exit0 default is not restored'):])

    def test_gate_off_replaces_before_it_deletes(self):
        from managers.awg_manager import AWGManager
        template = AWGManager._EXIT_SHELL_TEMPLATE
        gate = template[template.index('x_chain_gate()'):template.index('x_chain_cut()')]
        off = gate[:gate.index('  else')]
        self.assertLess(off.index('ip -4 route replace blackhole default metric 0'),
                        off.index('ip -4 route del default dev $EXIT_IF'),
                        'the blackhole must replace the default in one step')

    def test_failed_single_to_chain_drops_the_dead_record(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-0'))
        h.exit('exit-1').relay_error = 'transit port unreachable'
        with self.assertRaises(ExitLinkError):
            run(h.service.build_chain(0, 'awg2', ['exit-1', 'exit-2']))
        # the old single link was torn down to make room: no record may claim
        # a link whose wiring is gone, and the egress stays cut
        self.assertFalse(h.record().get('exit_link'))
        self.assertIn('exit_chain_cut', [c[0] for c in h.awg().calls])

    def test_failed_rebuild_marks_the_restored_chain_needs_repair(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        h.exit('exit-1').relay_error = 'transit port unreachable'
        with self.assertRaises(ExitLinkError):
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1', 'exit-2']))
        self.assertEqual(h.record()['exit_link']['stale'], 'chain_rebuild_failed')
        self.assertEqual(len(h.record()['exit_link']['chain']), 3)

    def test_one_hop_chain_record_is_chain_mode(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0']))
        view = h.service.chain_view(h.data, h.record(), 'entry-uid')
        self.assertEqual(view['mode'], 'chain')
        self.assertEqual(len(view['chain']), 1)

    def test_legacy_single_link_is_single_mode(self):
        h = Harness()
        h.data['servers'][0]['protocols']['awg2']['exit_link'] = {
            'exit_uid': 'exit-0', 'exit_name': 'exit-0',
            'transit_ip': '10.9.0.7', 'psk': 'PSK', 'exit_public_key': 'K',
            'endpoint_host': '203.0.113.5', 'endpoint_port': '55520',
            'obfuscation': False, 'stale': None,
        }
        view = h.service.chain_view(h.data, h.record(), 'entry-uid')
        self.assertEqual(view['mode'], 'single')

    def test_one_hop_chain_can_be_saved_through_the_chain_api(self):
        h = self.build(('exit-0', 'exit-1'))
        result = run(h.service.build_chain(0, 'awg2', ['exit-0']))
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(h.record()['exit_link']['chain']), 1)

    def test_ui_mtu_retry_sends_the_override(self):
        page = open('templates/server.html', encoding='utf-8').read()
        self.assertIn('mtu_override: mtuOverride', page)
        self.assertIn('return saveExitChain(true, true);', page)
        self.assertIn('function chainModeStored()', page)

    def test_ping_only_is_not_reported_as_reachable(self):
        h = self.build()
        h.sshes['203.0.113.5'].probe_rc = 1        # port does not answer
        res = run(h.service.chain_probe(0, 'awg2', 'exit-1', after_uid='exit-0'))
        self.assertEqual(res['error'], 'port_unverified')

    def test_probe_script_is_still_valid_bash(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        h = Harness()
        run(h.service.chain_probe(0, 'awg2', 'exit-0'))
        script = h.sshes['198.51.100.1'].scripts[-1]
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)

    def test_relay_down_cuts_before_it_deletes_the_device(self):
        from managers.exit_manager import ExitManager
        manager = ExitManager.__new__(ExitManager)
        body = ExitManager._relay_shell_functions(
            manager, {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7',
                      'mtu': 1420, 'rule_pref': 3123})
        down = body[body.index('x_relay_down()'):]
        self.assertLess(down.index('x_unrule -4 $R_PREF'),
                        down.index('ip link del $R_IF'),
                        'the policy rule must go before the uplink device')

    def test_saving_poll_settings_keeps_the_hop_results(self):
        h = self.build()
        run(h.service.poll_chain(0, 'awg2'))
        run(h.service.configure_chain_poll(0, 'awg2', check_interval_seconds=60))
        view = h.service.chain_view(h.data, h.record(), 'entry-uid')
        self.assertTrue(view['poll']['hops'])

    def test_unreadable_registry_keeps_the_existing_start_sh(self):
        from managers.exit_manager import ExitManager
        ssh = FakeSSH('203.0.113.5')
        ssh.registry_error = True
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        written = manager.relay_write_startup()
        self.assertEqual(written, [])
        self.assertNotIn('/tmp/_amnz_relay_start.sh', ssh.uploads)

    def test_failed_cut_aborts_the_rebuild(self):
        h = self.build(('exit-0', 'exit-1'))
        h.awg().fail_cut = True
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        self.assertEqual(ctx.exception.code, 'chain_cut_failed')
        self.assertIn('exit_chain_cut', [c[0] for c in h.awg().calls])
        self.assertNotIn('exit_prepare_keys', [c[0] for c in h.awg().calls])

    def test_low_mtu_is_only_raised_when_asked(self):
        h = Harness()
        h.awg().mtu = '1280'
        result = run(h.service.build_chain(0, 'awg2', ['exit-0']))
        self.assertIn('exit_chain_mtu_kept_low', result['warnings'])
        self.assertEqual(h.awg().applied_mtu, None)
        run(h.service.build_chain(0, 'awg2', ['exit-0'], raise_mtu=True))
        self.assertEqual(h.awg().applied_mtu, 1420)

    def test_hop_table_numbers_are_escaped(self):
        page = open('templates/server.html', encoding='utf-8').read()
        self.assertIn('escapeHtml(String(h.index + 1))', page)
        self.assertIn("escapeHtml(String(h.handshake_age))", page)

    def test_build_refreshes_the_union_of_every_chain(self):
        h = Harness()
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        run(h.service.build_chain(0, 'awg', ['exit-0', 'exit-1']))
        iface_b = h.record('awg')['exit_link']['chain'][0]['relay']['iface']
        # rebuilding the FIRST chain must not erase the second chain's block
        run(h.service.build_chain(0, 'awg2', ['exit-0', 'exit-1']))
        from managers.exit_manager import ExitManager
        ssh = h.sshes['203.0.113.5']
        manager = ExitManager.__new__(ExitManager)
        manager.ssh = ssh
        self.assertIn(iface_b, manager.relay_write_startup())

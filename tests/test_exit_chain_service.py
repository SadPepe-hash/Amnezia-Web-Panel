"""Exit-node chain (multi-hop egress): build, teardown, fail-closed health.

The fakes mirror tests/test_exit_link_service.py: in-memory data.json plus one
fake manager per host, so the whole flow is checked without SSH.
"""

import asyncio
import copy
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
        return ''

    def exit_chain_gate(self, protocol, enabled):
        self.calls.append(('exit_chain_gate', protocol, enabled))
        self.gate_calls.append(enabled)
        return f'chain gate {enabled}'


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

    def relay_apply(self, relay, teardown=False):
        self.calls.append(('relay_apply', relay['iface'], teardown))
        if teardown:
            self.relay_confs.pop(relay['iface'], None)
            return 'relay down'
        if self.relay_error:
            raise RuntimeError(self.relay_error)
        return 'relay up'

    def relay_teardown(self, relay):
        self.calls.append(('relay_teardown', relay['iface']))
        self.relay_confs.pop(relay['iface'], None)
        return True

    def relay_write_startup(self, relays):
        self.calls.append(('relay_write_startup',
                           tuple(relay['iface'] for relay in relays or [])))
        return [relay['iface'] for relay in relays or []]

    def relay_status(self, relay, now=None):
        age = self.relay_handshake
        self.calls.append(('relay_status', relay['iface']))
        return {'iface': relay['iface'], 'up': age is not None,
                'handshake_age': age, 'rx_bytes': 5, 'tx_bytes': 6}

    def peer_status(self, peer_id, now=None):
        self.calls.append(('peer_status', peer_id))
        if peer_id in self.peer_missing:
            return {'up': False, 'handshake_age': None, 'error': 'peer_not_found'}
        age = self.peer_ages.get(peer_id, 3)
        return {'up': True, 'handshake_age': age, 'rx_bytes': 7, 'tx_bytes': 8}


class FakeSSH:
    """Answers the RTT probe with a fixed latency so the poll is deterministic."""

    def __init__(self, host, rtt_ms='12.5'):
        self.host = host
        self.rtt_ms = rtt_ms
        self.commands = []
        self.scripts = []

    def run_sudo_command(self, command, timeout=None):
        self.commands.append(command)
        return self.rtt_ms + '\n', '', 0

    def run_sudo_script(self, script, timeout=None):
        # the real transport stages the script and runs it as root
        self.scripts.append(script)
        return self.rtt_ms + '\n', '', 0


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
                return self.exits.setdefault(server['host'], FakeExit(server['host'], self.events))
        raise KeyError(uid)

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
        self.assertEqual([c[0] for c in h.awg().calls],
                         ['exit_prepare_keys', 'exit_link', 'exit_link_status'])

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
        # second poll inside the recovery wait: no new gate action
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['action'], 'noop')
        self.assertEqual(h.awg().gate_calls, [])
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
        # the RTT of hop 1 is measured ON hop 0 (the previous node of the list)
        scripts = h.sshes['203.0.113.5'].scripts
        self.assertTrue(scripts, 'the RTT probe must run on the previous hop')
        self.assertIn('203.0.113.6', scripts[0])
        result = run(h.service.poll_chain(0, 'awg2'))
        self.assertEqual(result['hops'][1]['rtt_ms'], 12.5)

    def test_chain_probe_measures_the_next_hop_from_the_previous_one(self):
        h = self.build()
        res = run(h.service.chain_probe(0, 'awg2', 'exit-1', after_uid='exit-0'))
        self.assertTrue(res['ok'])
        self.assertEqual(res['rtt_ms'], 12.5)
        self.assertEqual(res['after_uid'], 'exit-0')
        self.assertIn('203.0.113.6', h.sshes['203.0.113.5'].scripts[-1])

    def test_chain_probe_of_the_first_hop_comes_from_the_entry(self):
        h = self.build()
        res = run(h.service.chain_probe(0, 'awg2', 'exit-0'))
        # the entry has no exit container, so the panel probes directly; the
        # TEST-NET address of the fixture is unreachable and must read as a
        # clean failure, not as an exception.
        self.assertFalse(res['ok'])
        self.assertEqual(res['error'], 'probe_failed')
        # and no probe script was staged on any hop for this first hop
        self.assertEqual([s for s in h.sshes['203.0.113.5'].scripts], [])

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
        calls = [c for c in h.exit('exit-0').calls if c[0] == 'relay_write_startup']
        calls += [c for c in h.exit('exit-1').calls if c[0] == 'relay_write_startup']
        self.assertEqual(len(calls), 2, 'every relay host gets its start.sh refreshed')
        for call in calls:
            self.assertEqual(len(call[1]), 1)

    def test_remove_chain_strips_the_relay_startup(self):
        h = self.build(('exit-0', 'exit-1', 'exit-2'))
        h.exit('exit-0').calls.clear()
        h.exit('exit-1').calls.clear()
        run(h.service.remove_chain(0, 'awg2'))
        stripped = [c for c in h.exit('exit-0').calls if c[0] == 'relay_write_startup']
        stripped += [c for c in h.exit('exit-1').calls if c[0] == 'relay_write_startup']
        self.assertEqual(len(stripped), 2)
        for call in stripped:
            self.assertEqual(call[1], ())

    def test_relay_write_startup_block_is_valid_shell(self):
        import shutil
        import subprocess
        import tempfile
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash not available')
        relay = {'iface': 'c1a2b1', 'table': 250, 'source_ip': '10.9.0.7', 'mtu': 1420}
        manager = ExitManager.__new__(ExitManager)
        body = manager._render_start_script(relay_blocks=[
            '# ---- exit chain relay c1a2b1 (panel-managed) ----\n'
            'if [ -f /opt/amnezia/exit/relay/c1a2b1.conf ]; then\n'
            + ExitManager._relay_shell_functions(manager, relay)
            + '  x_relay_up || echo "! chain relay c1a2b1 not applied; hop stays cut"\n'
            + 'fi\n'])
        self.assertIn('x_relay_up ||', body)
        self.assertIn('if [ -f /opt/amnezia/exit/relay/c1a2b1.conf ]; then', body)
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(body)
            path = handle.name
        try:
            result = subprocess.run([bash, '-n', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)


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

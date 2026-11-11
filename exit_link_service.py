"""Orchestration of exit-node links between two panel servers.

An *entry* AWG instance is linked to an *exit* node in three SSH steps on two
servers: the entry generates its key pair, the exit registers it as a peer,
the entry writes exit0.conf and reroutes its clients. Every step is idempotent
and a failed link is rolled back, so a link is recorded in data.json only
when the tunnel is really up (or the caller insisted with force=True).

Dependencies are injected (like ConnectionService) so the whole flow is unit
tested with fake managers and an in-memory data.json.
"""

import asyncio
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime

import exit_chain as chain_policy
import exit_failover as failover_policy

logger = logging.getLogger(__name__)

EXIT_MTU_LIMIT = 1420          # exit0 MTU; client MTU must not exceed it
HANDSHAKE_WAIT_SECONDS = 15
HANDSHAKE_POLL_SECONDS = 2


class ExitLinkError(Exception):
    """A user-facing failure: `code` is a stable identifier for the UI/i18n."""

    def __init__(self, code, message, status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def peer_id_for(entry_uid, protocol):
    """Identity of an entry instance on the exit: one link per AWG instance."""
    return f"{entry_uid}:{protocol}"


class ExitLinkService:
    def __init__(self, *, load_data, save_data, data_lock, get_ssh,
                 awg_manager_factory, exit_manager_factory,
                 protocol_base, awg_protocols, protocol_display_name,
                 find_server_by_uid, sleep=None, time_fn=None):
        self.load_data = load_data
        self.save_data = save_data
        self.data_lock = data_lock
        self.get_ssh = get_ssh
        self.awg_manager_factory = awg_manager_factory
        self.exit_manager_factory = exit_manager_factory
        self.protocol_base = protocol_base
        self.awg_protocols = awg_protocols
        self.protocol_display_name = protocol_display_name
        self.find_server_by_uid = find_server_by_uid
        self._sleep = sleep or asyncio.sleep
        self._time = time_fn or time.time
        # Two SSH sessions and no cross-server lock: serialize per (entry, protocol)
        self._locks = defaultdict(asyncio.Lock)
        # Automatic switches of different entries still go one at a time so a
        # failed apply can restore the previous conf without overlapping writes.
        self._failover_switch_lock = asyncio.Lock()

    # ----- read-only helpers (no SSH) -----

    def list_exit_nodes(self, data):
        nodes = []
        for idx, server in enumerate(data.get('servers', [])):
            rec = (server.get('protocols') or {}).get('exit') or {}
            if not rec.get('installed'):
                continue
            nodes.append({
                'uid': server.get('uid', ''),
                'server_id': idx,
                'name': server.get('name') or server.get('host', ''),
                'host': server.get('host', ''),
                'port': rec.get('port'),
                'subnet': rec.get('subnet'),
                'obfuscation': bool(rec.get('obfuscation')),
            })
        return nodes

    def linked_entries(self, data, exit_uid):
        """Every (server, protocol) whose exit_link points at `exit_uid`."""
        entries = []
        if not exit_uid:
            return entries
        for idx, server in enumerate(data.get('servers', [])):
            for proto, rec in (server.get('protocols') or {}).items():
                link = (rec or {}).get('exit_link') or {}
                if link.get('exit_uid') == exit_uid:
                    entries.append({
                        'server_id': idx,
                        'server_uid': server.get('uid', ''),
                        'name': server.get('name') or server.get('host', ''),
                        'protocol': proto,
                        'stale': link.get('stale'),
                    })
        return entries

    # ----- validation -----

    def _entry(self, data, server_id, protocol):
        servers = data.get('servers', [])
        if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
            raise ExitLinkError('server_not_found', 'Server not found', 404)
        server = servers[server_id]
        if self.protocol_base(protocol) not in self.awg_protocols:
            raise ExitLinkError('protocol_not_awg', 'Only AmneziaWG instances can be linked to an exit node')
        rec = (server.get('protocols') or {}).get(protocol)
        if not rec or not rec.get('installed'):
            raise ExitLinkError('protocol_not_installed', f'{protocol} is not installed on this server')
        if not server.get('uid'):
            raise ExitLinkError('entry_no_uid', 'This server has no uid yet; restart the panel once', 500)
        return server, rec

    def _exit(self, data, exit_uid):
        _, server = self.find_server_by_uid(data, exit_uid)
        rec = ((server or {}).get('protocols') or {}).get('exit') or {}
        if not server or not rec.get('installed'):
            raise ExitLinkError('exit_not_found', 'Exit node not found or not installed', 404)
        return server, rec

    def _entry_by_uid(self, data, uid, protocol):
        index, _ = self.find_server_by_uid(data, uid)
        if index is None:
            raise ExitLinkError('server_not_found', 'Entry server no longer exists', 404)
        return self._entry(data, index, protocol)

    async def _awg(self, server):
        # get_ssh() blocks on ensure_connected (TCP+SSH handshake, up to the
        # connect timeout) — never run it inside the event loop.
        return self.awg_manager_factory(await asyncio.to_thread(self.get_ssh, server))

    async def _exit_manager(self, server):
        return self.exit_manager_factory(await asyncio.to_thread(self.get_ssh, server))

    # ----- persistence under the lock, resolved by uid (indices may shift) -----

    async def _update_record(self, entry_uid, protocol, mutate):
        async with self.data_lock:
            data = self.load_data()
            _, server = self.find_server_by_uid(data, entry_uid)
            rec = ((server or {}).get('protocols') or {}).get(protocol)
            if rec is None:
                return None
            mutate(rec)
            self.save_data(data)
            return rec

    async def _record_link(self, entry, exit_server, protocol, record, source='manual'):
        """Publish only while both endpoints still describe the SSH targets."""
        async with self.data_lock:
            data = self.load_data()
            current_entry, rec = self._entry_by_uid(data, entry['uid'], protocol)
            current_exit, _ = self._exit(data, exit_server['uid'])
            for current, expected in ((current_entry, entry), (current_exit, exit_server)):
                if any(current.get(key) != expected.get(key) for key in ('host', 'ssh_port', 'username')):
                    raise ExitLinkError('server_changed', 'Server endpoint changed during link setup', 409)
            self._persist_link_record(rec, record, source, record.get('exit_uid'))
            self.save_data(data)

    # ----- link / unlink -----

    async def _wait_handshake(self, awg, protocol):
        polls = max(1, HANDSHAKE_WAIT_SECONDS // HANDSHAKE_POLL_SECONDS)
        for attempt in range(polls):
            status = await asyncio.to_thread(awg.exit_link_status, protocol)
            if status and status.get('handshake_age') is not None:
                return status
            if attempt < polls - 1:
                await self._sleep(HANDSHAKE_POLL_SECONDS)
        return None

    async def _rollback(self, awg, protocol, exit_manager, peer_id):
        for what, call in (('entry unlink', lambda: awg.exit_unlink(protocol)),
                           ('exit remove_peer', lambda: exit_manager.remove_peer(peer_id=peer_id))):
            try:
                await asyncio.to_thread(call)
            except Exception as err:  # the original error is what the user must see
                logger.warning("exit link rollback: %s failed: %s", what, err)

    @staticmethod
    def _require_exit_dns(exit_srv):
        """DNS via the exit only works when that node runs AmneziaDNS: the
        clients keep resolving 172.29.172.254, which is answered on whichever
        node the query comes out of."""
        dns_rec = (exit_srv.get('protocols') or {}).get('dns') or {}
        if not dns_rec.get('installed'):
            raise ExitLinkError('exit_dns_needs_dns',
                                'Install AmneziaDNS on the exit node before routing client DNS through it')

    async def set_dns_via_exit(self, entry_server_id, protocol, enabled):
        """Turn client DNS resolution at the exit node on or off for a linked
        instance. Off (the default) keeps DNS on the entry node."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        enabled = bool(enabled)
        if enabled:
            exit_srv, _ = self._exit(data, link.get('exit_uid'))
            self._require_exit_dns(exit_srv)
        async with self._locks[(entry['uid'], protocol)]:
            awg = await self._awg(entry)
            try:
                log = await asyncio.to_thread(awg.exit_set_dns_via_exit, protocol, enabled)
            except Exception as err:
                raise ExitLinkError('exit_apply_failed', str(err))
            await self._update_record(
                entry['uid'], protocol,
                lambda r: (r.get('exit_link') or {}).__setitem__('dns_via_exit', enabled))
        return {'status': 'success', 'dns_via_exit': enabled, 'log': [log]}

    async def disable_dns_via_exit_for_exit(self, exit_uid):
        """AmneziaDNS is gone from an exit node: bring the DNS of every entry
        linked to it back home instead of leaving queries in a black hole."""
        results = []
        data = self.load_data()
        for item in self.linked_entries(data, exit_uid):
            _, rec = self._entry(data, item['server_id'], item['protocol'])
            if not (rec.get('exit_link') or {}).get('dns_via_exit'):
                continue
            try:
                await self.set_dns_via_exit(item['server_id'], item['protocol'], False)
                results.append({**item, 'status': 'success'})
            except Exception as err:
                logger.warning("could not bring DNS back to entry %s/%s: %s",
                               item['server_id'], item['protocol'], err)
                results.append({**item, 'status': 'error', 'error': str(err)})
        return results

    async def link(self, entry_server_id, protocol, exit_uid, force=False, dns_via_exit=None,
                   *, restore_on_failure=False, source='manual', _locked=False):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        entry_uid = entry['uid']
        requested_dns = dns_via_exit

        async def _go():
            data = self.load_data()
            entry, rec = self._entry_by_uid(data, entry_uid, protocol)
            exit_srv, exit_rec = self._exit(data, exit_uid)
            if exit_srv.get('uid') == entry['uid']:
                raise ExitLinkError('exit_self', 'A server cannot be its own exit node')
            if self.protocol_base(protocol) == 'awg_legacy' and exit_rec.get('obfuscation'):
                raise ExitLinkError('exit_legacy_obfuscation',
                                    'AmneziaWG Legacy can only link to a non-obfuscated exit node')
            previous = rec.get('exit_link') or {}
            explicit_dns = requested_dns is not None
            dns_via_exit = bool(previous.get('dns_via_exit') if requested_dns is None else requested_dns)
            peer_id = peer_id_for(entry['uid'], protocol)
            warnings, log = [], []
            if dns_via_exit:
                try:
                    self._require_exit_dns(exit_srv)
                except ExitLinkError:
                    # Repairing a link must not fail over an option the caller did
                    # not ask for; the flag inherited from the saved link is dropped
                    # so DNS comes back to this node instead of a black hole.
                    if explicit_dns:
                        raise
                    dns_via_exit = False
                    warnings.append('exit_dns_disabled_no_dns')
            if restore_on_failure and not previous.get('exit_uid'):
                raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')

            awg = await self._awg(entry)
            entry_pub = await asyncio.to_thread(awg.exit_prepare_keys, protocol)
            try:
                mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
            except (TypeError, ValueError):
                mtu = 0
            try:
                entry_config = await asyncio.to_thread(
                    awg._get_server_config, protocol)
            except Exception:
                raise ExitLinkError(
                    'state_unreadable',
                    'Cannot read the instance config; retry')
            if not (entry_config or '').strip():
                raise ExitLinkError(
                    'state_unreadable',
                    'Cannot read the instance config; retry')
            ipv6 = False
            for line in entry_config.splitlines():
                stripped = line.strip()
                if not stripped.startswith('Address'):
                    continue
                if '=' in stripped:
                    tokens = stripped.split('=', 1)[1].split(',')
                    ipv6 = any(':' in token for token in tokens)
                break
            if ipv6:
                # The exit node publishes only IPv4: a dual-stack tunnel would
                # send IPv6 into a black hole. Refuse at any peer count.
                raise ExitLinkError(
                    'exit_link_ipv6',
                    'Instance has IPv6 enabled; disable IPv6 before linking '
                    'to an exit node')
            if mtu > EXIT_MTU_LIMIT and not force:
                raise ExitLinkError('exit_mtu_too_big',
                                    f'Client MTU {mtu} exceeds the link MTU {EXIT_MTU_LIMIT}; '
                                    f'lower it in the AWG settings or link anyway')

            # The peer on a previous exit is dropped only after the new link is
            # confirmed (below): until then the old exit is what Repair falls
            # back to if this attempt has to be rolled back.
            switching = bool(previous.get('exit_uid')) and previous['exit_uid'] != exit_uid

            if restore_on_failure:
                try:
                    await asyncio.to_thread(awg.exit_backup_conf, protocol)
                except Exception as err:
                    raise ExitLinkError('exit_apply_failed',
                                        f'Could not snapshot the current exit link: {err}')

            exit_manager = await self._exit_manager(exit_srv)

            async def rolled_back():
                # Manual link: teardown so a half-applied conf cannot leak.
                # Failover switch: restore the previous conf so clients keep
                # the last working (or last known) exit instead of a hole.
                if restore_on_failure:
                    restored = False
                    try:
                        await asyncio.to_thread(awg.exit_restore_conf, protocol)
                        restored = True
                    except Exception as err:
                        logger.warning("exit failover restore failed, falling back to unlink: %s", err)
                    try:
                        await asyncio.to_thread(exit_manager.remove_peer, None, peer_id)
                    except Exception as err:
                        logger.warning("exit link rollback: exit remove_peer failed: %s", err)
                    if restored:
                        return True
                await self._rollback(awg, protocol, exit_manager, peer_id)
                if previous.get('exit_uid'):
                    reason = 'switch_failed' if switching else 'relink_failed'
                    await self._update_record(entry['uid'], protocol,
                                              lambda r: (r.get('exit_link') or {}).__setitem__('stale', reason))
                return False

            record = (entry.get('protocols') or {}).get(protocol, {})
            label = self.protocol_display_name(protocol, record.get('header_protection'), record.get('protocol_version'))
            name = f"{entry.get('name') or entry.get('host', '')} / {label}"
            peer = await asyncio.to_thread(exit_manager.add_peer, peer_id, name, entry_pub)
            link = {
                'exit_uid': exit_uid,
                'exit_name': exit_srv.get('name') or exit_srv.get('host', ''),
                'transit_ip': peer['transit_ip'],
                'subnet_cidr': str(peer.get('subnet') or '10.9.0.0/24').split('/')[1],
                'exit_public_key': peer['public_key'],
                'psk': peer['psk'],
                'endpoint_host': exit_srv['host'],
                'endpoint_port': peer['port'] or exit_rec.get('port'),
                'obfuscation': bool(peer.get('obfuscation')),
                'awg_params': peer.get('awg_params') or {},
                'dns_via_exit': dns_via_exit,
            }
            try:
                log.append(await asyncio.to_thread(awg.exit_link, protocol, link))
            except Exception as err:
                await rolled_back()
                raise ExitLinkError('exit_apply_failed', str(err))

            handshake = await self._wait_handshake(awg, protocol)
            if not handshake:
                if not force:
                    await rolled_back()
                    raise ExitLinkError('exit_no_handshake',
                                        f"No handshake from the exit node within {HANDSHAKE_WAIT_SECONDS} s "
                                        f"(is {link['endpoint_port']}/udp reachable on {link['endpoint_host']}?). "
                                        f"The link was rolled back")
                warnings.append('no_handshake_yet')

            if switching:
                # New link confirmed: drop our peer on the previous exit, best effort.
                try:
                    old_exit, _ = self._exit(data, previous['exit_uid'])
                    old_exit_manager = await self._exit_manager(old_exit)
                    await asyncio.to_thread(old_exit_manager.remove_peer, None, peer_id)
                except Exception as err:
                    logger.warning("previous exit %s unreachable, peer left behind: %s", previous['exit_uid'], err)
                    warnings.append('old_exit_unreachable_orphan_peer')

            record = {
                'exit_uid': exit_uid,
                'exit_name': link['exit_name'],
                'transit_ip': link['transit_ip'],
                'exit_public_key': link['exit_public_key'],
                'endpoint_host': link['endpoint_host'],
                'endpoint_port': link['endpoint_port'],
                'obfuscation': link['obfuscation'],
                'dns_via_exit': dns_via_exit,
                'linked_at': datetime.now().isoformat(),
                'stale': None,
            }
            # Smart Route preferences live inside exit_link. A relink replaces
            # that record; dropping them silently disables an already split
            # instance while the host marker keeps applying throw routes.
            for key in ('smart_route', 'smart_route_lost', 'smart_route_prev_dns'):
                if key in previous:
                    record[key] = previous[key]
            try:
                await self._record_link(entry, exit_srv, protocol, record, source=source)
            except Exception:
                await rolled_back()
                raise
            return {'status': 'success', 'exit_link': record, 'ipv6_refused': ipv6,
                    'warnings': warnings, 'log': log}

        if _locked:
            return await _go()
        async with self._locks[(entry_uid, protocol)]:
            return await _go()


    async def unlink(self, entry_server_id, protocol):
        data = self.load_data()
        entry, _ = self._entry(data, entry_server_id, protocol)
        entry_uid = entry['uid']
        warnings = []
        async with self._locks[(entry_uid, protocol)]:
            data = self.load_data()
            entry, rec = self._entry_by_uid(data, entry_uid, protocol)
            link = rec.get('exit_link')
            if not link:
                return {'status': 'success', 'warnings': [], 'unlinked': False}
            if link.get('chain'):
                # a chain owns peers and interfaces on every hop: unwind them
                await self._teardown_chain(entry, protocol)
            else:
                # Entry first: direct egress must come back even when the exit is dead.
                awg = await self._awg(entry)
                await asyncio.to_thread(awg.exit_unlink, protocol)
                try:
                    exit_srv, _ = self._exit(data, link.get('exit_uid'))
                    exit_manager = await self._exit_manager(exit_srv)
                    await asyncio.to_thread(exit_manager.remove_peer, None,
                                            peer_id_for(entry_uid, protocol))
                except Exception as err:
                    logger.warning("exit %s unreachable on unlink, peer left behind: %s", link.get('exit_uid'), err)
                    warnings.append('exit_unreachable_orphan_peer')
            await self._update_record(entry_uid, protocol, lambda r: self._drop_link_keep_failover(r))

        return {'status': 'success', 'warnings': warnings, 'unlinked': True}

    async def relink_entry(self, entry_server_id, protocol):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        if link.get('chain'):
            # repair of a chain is a full rebuild (operator action)
            return await self.repair_chain(entry_server_id, protocol)
        return await self.link(entry_server_id, protocol, link['exit_uid'], force=True)

    async def relink_entries_for_exit(self, exit_uid):
        """After an exit node was reinstalled: re-register every linked entry."""
        results = []
        for item in self.linked_entries(self.load_data(), exit_uid):
            try:
                await self.relink_entry(item['server_id'], item['protocol'])
                results.append({**item, 'status': 'success', 'error': None})
            except Exception as err:
                logger.warning("re-link %s/%s failed: %s", item['name'], item['protocol'], err)
                results.append({**item, 'status': 'error', 'error': str(err)})
        return results

    async def reconcile_after_restore(self, server_id, protocol):
        """A protocol restore overwrites the very files a link lives in: the
        entry keeps exit0.conf inside its AWG config directory, the exit keeps
        its peer table. So an archive can bring back a link the panel does not
        know about, drop the one it does, or restore a peer list that no longer
        matches the entries. Called after a successful restore to make the two
        sides agree again."""
        data = self.load_data()
        base = self.protocol_base(protocol)

        if base == 'exit':
            servers = data.get('servers', [])
            if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
                return {}
            uid = servers[server_id].get('uid')
            entries = await self.relink_entries_for_exit(uid) if uid else []
            return {'exit_entries_relinked': entries} if entries else {}

        if base not in self.awg_protocols:
            return {}
        try:
            entry, rec = self._entry(data, server_id, protocol)
        except ExitLinkError:
            return {}

        if rec.get('exit_link'):
            try:
                await self.relink_entry(server_id, protocol)
                return {'exit_link_restored': 'relinked'}
            except Exception as err:
                logger.warning("re-link after restore failed for %s/%s: %s",
                               entry.get('name'), protocol, err)
                await self._update_record(
                    entry['uid'], protocol,
                    lambda r: (r.get('exit_link') or {}).__setitem__('stale', 'restore_relink_failed'))
                return {'exit_link_restored': 'stale', 'exit_link_error': str(err)}

        # The panel knows of no link, so a link file coming out of the archive
        # would silently route clients through an exit nobody is tracking.
        try:
            awg = await self._awg(entry)
            info = await asyncio.to_thread(awg.exit_link_info, protocol)
        except Exception as err:
            logger.warning("could not read the link state after restore: %s", err)
            return {}
        if not info:
            return {}
        try:
            await asyncio.to_thread(awg.exit_unlink, protocol)
            return {'exit_link_restored': 'removed', 'exit_name': info.get('exit_name', '')}
        except Exception as err:
            logger.warning("could not remove the restored link file: %s", err)
            return {'exit_link_restored': 'orphan', 'exit_name': info.get('exit_name', '')}

    async def detach_entries_for_exit(self, exit_uid, reason):
        """Restore direct egress without clearing a concurrently replaced link."""
        results = []
        for item in self.linked_entries(self.load_data(), exit_uid):
            entry_uid, protocol = item['server_uid'], item['protocol']
            async with self._locks[(entry_uid, protocol)]:
                data = self.load_data()
                _, entry = self.find_server_by_uid(data, entry_uid)
                rec = ((entry or {}).get('protocols') or {}).get(protocol) or {}
                link = dict(rec.get('exit_link') or {})
                if link.get('exit_uid') != exit_uid:
                    # A queued link switch/removal won. Its route and peer belong
                    # to the current link, not to the exit being removed.
                    continue
                try:
                    awg = await self._awg(entry)
                    await asyncio.to_thread(awg.exit_unlink, protocol)
                    def remove_current(record):
                        if record.get('exit_link') != link:
                            raise ExitLinkError('exit_link_changed', 'Link changed during exit cleanup', 409)
                        self._drop_link_keep_failover(record)
                    await self._update_record(entry_uid, protocol, remove_current)
                    results.append({**item, 'status': 'success', 'error': None})
                except Exception as err:
                    logger.warning("detach %s/%s failed, marking matching link stale: %s", item['name'], protocol, err)
                    def mark_current(record):
                        if record.get('exit_link') == link:
                            record['exit_link']['stale'] = reason
                    await self._update_record(entry_uid, protocol, mark_current)
                    results.append({**item, 'status': 'error', 'error': str(err)})

        return results

    async def forget_entry_peers(self, server):
        """Drop this entry's current peers, serialized with link/unlink."""
        results = []
        entry_uid = server.get('uid')
        _, current = self.find_server_by_uid(self.load_data(), entry_uid)
        for proto in ((current or {}).get('protocols') or {}):
            async with self._locks[(entry_uid, proto)]:
                data = self.load_data()
                _, entry = self.find_server_by_uid(data, entry_uid)
                rec = ((entry or {}).get('protocols') or {}).get(proto) or {}
                link = rec.get('exit_link') or {}
                if not link.get('exit_uid'):
                    continue
                try:
                    exit_srv, _ = self._exit(data, link['exit_uid'])
                    exit_manager = await self._exit_manager(exit_srv)
                    await asyncio.to_thread(exit_manager.remove_peer, None,
                                            peer_id_for(entry_uid, proto))
                    results.append({'protocol': proto, 'exit_uid': link['exit_uid'], 'status': 'success'})
                except Exception as err:
                    logger.warning("could not drop peer for %s on exit %s: %s", proto, link['exit_uid'], err)
                    results.append({'protocol': proto, 'exit_uid': link['exit_uid'], 'status': 'error', 'error': str(err)})
        return results

    @staticmethod
    def _endpoint_ip(status):
        """IPv4 of the live `host:port` endpoint of the link, or '' (an IPv6
        endpoint has no bearing on the IPv4-only egress probe)."""
        endpoint = (status or {}).get('endpoint') or ''
        host = endpoint.rsplit(':', 1)[0]
        return host if IPV4_RE.match(host) else ''

    async def check_egress(self, entry_server_id, protocol):
        """Ask the entry container which public IP its clients leave from and
        compare it with the exit node's address. `leaks` means the clients
        still leave from the entry node itself."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        awg = await self._awg(entry)
        try:
            probe = await asyncio.to_thread(awg.exit_check_egress, protocol)
        except RuntimeError as err:
            raise ExitLinkError('exit_egress_failed', str(err))
        via, direct = probe.get('via_exit', ''), probe.get('direct', '')
        expected = link.get('endpoint_host', '')
        # `endpoint_host` is whatever the admin typed when adding the server and
        # is often a hostname; the probe always answers with an address. The
        # live WireGuard endpoint is the resolved form of that same host, so it
        # is what the comparison uses when available.
        status = await asyncio.to_thread(awg.exit_link_status, protocol)
        expected_ip = self._endpoint_ip(status) or (expected if IPV4_RE.match(expected or '') else '')
        return {
            'status': 'success',
            'via_exit': via,
            'direct': direct,
            'expected': expected,
            'expected_ip': expected_ip,
            'exit_name': link.get('exit_name', ''),
            # A NATed exit answers from another address, so a mismatch is a
            # warning, not a failure; leaving from the entry address is not.
            'matches': bool(via) and bool(expected_ip) and via == expected_ip,
            'leaks': bool(via) and via == direct,
        }

    async def status(self, entry_server_id, protocol):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        awg = await self._awg(entry)
        link_status = await asyncio.to_thread(awg.exit_link_status, protocol)
        try:
            mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
        except (TypeError, ValueError):
            mtu = 0
        ipv6 = bool(await asyncio.to_thread(awg._get_subnet_ipv6_ip, protocol))
        return {
            'status': 'success',
            'exit_link': rec.get('exit_link'),
            'exit_link_status': link_status,
            'exit_failover': self.failover_view(data, rec, entry.get('uid')),
            'ipv6': ipv6,
            'mtu': mtu,
            'exit_mtu': EXIT_MTU_LIMIT,
        }

    # ----- automatic exit failover (opt-in, disabled by default) -----

    @staticmethod
    def _persist_link_record(rec, record, source, exit_uid):
        rec['exit_link'] = record
        fo = rec.get('exit_failover')
        if not isinstance(fo, dict):
            return
        state = failover_policy.normalize_state(fo.get('state'))
        state['active_uid'] = exit_uid
        if source != 'failover':
            # A manual (un)link is operator intent: that exit becomes primary.
            state['primary_uid'] = exit_uid
            state['consecutive_failures'] = 0
            state['consecutive_successes'] = 0
            state['primary_healthy_since'] = None
            fo['backup_uids'] = [uid for uid in (fo.get('backup_uids') or []) if uid != exit_uid]
        fo['state'] = state
        rec['exit_failover'] = fo

    @staticmethod
    def _drop_link_keep_failover(rec):
        rec.pop('exit_link', None)
        fo = rec.get('exit_failover')
        if not isinstance(fo, dict):
            return
        # Unlink must not keep probing: disable, keep the backup list so the
        # operator can re-enable after linking again.
        fo['enabled'] = False
        state = failover_policy.normalize_state(fo.get('state'))
        state['active_uid'] = ''
        state['consecutive_failures'] = 0
        state['consecutive_successes'] = 0
        state['primary_healthy_since'] = None
        state['last_ok'] = None
        state['last_reason'] = 'not_linked'
        fo['state'] = state
        rec['exit_failover'] = fo

    def failover_view(self, data, rec, entry_uid):
        """JSON-safe failover config + state for the API/UI (no SSH)."""
        raw = rec.get('exit_failover') if isinstance(rec, dict) else None
        cfg = failover_policy.normalize_config(raw)
        state = failover_policy.normalize_state((raw or {}).get('state') if isinstance(raw, dict) else None)
        events = list((raw or {}).get('events') or []) if isinstance(raw, dict) else []
        nodes = {n['uid']: n for n in self.list_exit_nodes(data) if n.get('uid')}
        link = (rec or {}).get('exit_link') or {}
        if not state.get('primary_uid'):
            state['primary_uid'] = link.get('exit_uid') or ''
        if not state.get('active_uid'):
            state['active_uid'] = link.get('exit_uid') or ''
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry_uid,
            primary_uid=state.get('primary_uid'),
            known_exit_uids=nodes.keys(),
        )

        def named(uid):
            node = nodes.get(uid) or {}
            return {
                'uid': uid or '',
                'name': node.get('name') or '',
                'host': node.get('host') or '',
                'installed': uid in nodes,
            }

        return {
            **cfg,
            'state': state,
            'events': events[:failover_policy.MAX_EVENTS],
            'primary': named(state.get('primary_uid')),
            'active': named(state.get('active_uid') or link.get('exit_uid')),
            'backups': [named(uid) for uid in cfg['backup_uids']],
        }

    async def configure_failover(self, entry_server_id, protocol, **fields):
        """Opt-in per AWG instance. Missing/disabled is a no-op for existing
        single-exit setups. Backups are stored by server uid, never index."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link') or {}
        enabled = bool(fields.get('enabled'))
        _record, chain = self._chain_record(data, rec)
        if len(chain) > 1:
            # Failover would substitute a hop of the chain: anonymity breaks.
            raise ExitLinkError('failover_not_allowed_with_chain',
                                'Automatic failover cannot be used while this instance '
                                'follows an exit-node chain')
        if enabled and not link.get('exit_uid'):
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')

        known = {n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')}
        stored = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        previous_state = failover_policy.normalize_state(stored.get('state'))
        primary_uid = (previous_state.get('primary_uid') or link.get('exit_uid') or '').strip()
        if enabled and primary_uid and primary_uid not in known:
            raise ExitLinkError('exit_not_found', 'Primary exit node not found or not installed', 404)
        if enabled and primary_uid == entry.get('uid'):
            raise ExitLinkError('exit_self', 'A server cannot be its own exit node')

        backups = failover_policy.sanitize_backup_uids(
            fields.get('backup_uids', stored.get('backup_uids')),
            entry_uid=entry.get('uid'),
            primary_uid=primary_uid,
            known_exit_uids=known,
        )
        if enabled and not backups:
            raise ExitLinkError('failover_no_backups',
                                'Add at least one backup exit node before enabling failover')

        merged = failover_policy.normalize_config({**stored, **{
            key: fields[key] for key in (
                'enabled', 'backup_uids', 'check_interval_seconds', 'failure_threshold',
                'failback_stable_seconds', 'handshake_max_age_seconds',
                'auto_failback', 'probe_egress',
            ) if key in fields
        }})
        merged['enabled'] = enabled
        merged['backup_uids'] = backups
        state = previous_state
        state['primary_uid'] = primary_uid
        state['active_uid'] = link.get('exit_uid') or state.get('active_uid') or primary_uid
        if not enabled:
            state['consecutive_failures'] = 0
            state['consecutive_successes'] = 0
            state['primary_healthy_since'] = None
        events = list(stored.get('events') or [])

        def mutate(r):
            payload = dict(merged)
            payload['state'] = state
            payload['events'] = events
            r['exit_failover'] = payload

        await self._update_record(entry['uid'], protocol, mutate)
        data = self.load_data()
        _, server = self.find_server_by_uid(data, entry['uid'])
        rec = ((server or {}).get('protocols') or {}).get(protocol) or {}
        return {
            'status': 'success',
            'exit_failover': self.failover_view(data, rec, entry['uid']),
        }

    async def _probe_active(self, entry, protocol, cfg):
        awg = await self._awg(entry)
        status = None
        status_missing = False
        handshake_error = None
        try:
            status = await asyncio.to_thread(awg.exit_link_status, protocol)
        except Exception as err:
            handshake_error = str(err)
        if status is None and not handshake_error:
            status_missing = True
        elif isinstance(status, dict) and status.get('error') and status.get('handshake_age') is None:
            handshake_error = status.get('error')
        egress = None
        if cfg['probe_egress']:
            try:
                probe = await asyncio.to_thread(awg.exit_check_egress, protocol)
                via, direct = probe.get('via_exit', ''), probe.get('direct', '')
                egress = {
                    'via_exit': via,
                    'direct': direct,
                    'leaks': bool(via) and via == direct,
                }
            except Exception as err:
                egress = {'error': str(err)}
        ok, reason = failover_policy.evaluate_active_health(
            handshake_age=None if not status else status.get('handshake_age'),
            handshake_error=handshake_error,
            status_missing=status_missing,
            egress=egress,
            probe_egress=cfg['probe_egress'],
            handshake_max_age=cfg['handshake_max_age_seconds'],
        )
        return ok, reason, {'status': status, 'egress': egress}

    async def _probe_candidate(self, exit_uid):
        data = self.load_data()
        try:
            exit_srv, rec = self._exit(data, exit_uid)
        except ExitLinkError:
            return False, failover_policy.REASON_EXIT_NOT_FOUND
        if not rec.get('installed'):
            return False, failover_policy.REASON_EXIT_NOT_FOUND
        try:
            manager = await self._exit_manager(exit_srv)
            running = await asyncio.to_thread(manager.check_container_running, 'exit')
        except Exception as err:
            logger.warning("failover candidate probe %s failed: %s", exit_uid, err)
            return False, failover_policy.REASON_SSH_ERROR
        ok, reason = failover_policy.evaluate_candidate_health(
            installed=True, container_running=bool(running), ssh_error=None)
        return ok, reason

    async def _persist_failover(self, entry_uid, protocol, cfg, state, events):
        def mutate(r):
            payload = failover_policy.normalize_config(r.get('exit_failover'))
            payload.update({
                'enabled': cfg.get('enabled', payload['enabled']),
                'backup_uids': cfg.get('backup_uids', payload['backup_uids']),
                'check_interval_seconds': cfg.get('check_interval_seconds', payload['check_interval_seconds']),
                'failure_threshold': cfg.get('failure_threshold', payload['failure_threshold']),
                'failback_stable_seconds': cfg.get('failback_stable_seconds', payload['failback_stable_seconds']),
                'handshake_max_age_seconds': cfg.get('handshake_max_age_seconds', payload['handshake_max_age_seconds']),
                'auto_failback': cfg.get('auto_failback', payload['auto_failback']),
                'probe_egress': cfg.get('probe_egress', payload['probe_egress']),
            })
            payload['state'] = state
            payload['events'] = events
            r['exit_failover'] = payload
        await self._update_record(entry_uid, protocol, mutate)

    async def tick_failover(self, entry_server_id, protocol):
        """One health-check of a single instance. No-op when disabled."""
        data = self.load_data()
        try:
            entry, rec = self._entry(data, entry_server_id, protocol)
        except ExitLinkError as err:
            return {'action': failover_policy.ACTION_NOOP, 'reason': err.code}

        raw = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        cfg = failover_policy.normalize_config(raw)
        if not cfg['enabled']:
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_DISABLED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        link = rec.get('exit_link') or {}
        if not link.get('exit_uid'):
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_NOT_LINKED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        now = self._time()
        state = failover_policy.normalize_state(raw.get('state'))
        if not state.get('primary_uid'):
            state['primary_uid'] = link['exit_uid']
        if not state.get('active_uid'):
            state['active_uid'] = link['exit_uid']
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry.get('uid'),
            primary_uid=state.get('primary_uid'),
            known_exit_uids={n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')},
        )
        if not failover_policy.due_for_check(state, cfg['check_interval_seconds'], now):
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_NOT_DUE,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        lock = self._locks[(entry['uid'], protocol)]
        if lock.locked():
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_BUSY,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        async with lock:
            return await self._tick_failover_locked(entry['uid'], protocol, now)

    async def _tick_failover_locked(self, entry_uid, protocol, now):
        data = self.load_data()
        _, entry = self.find_server_by_uid(data, entry_uid)
        rec = ((entry or {}).get('protocols') or {}).get(protocol)
        if not entry or not rec:
            return {'action': failover_policy.ACTION_NOOP, 'reason': 'entry_gone',
                    'entry_uid': entry_uid, 'protocol': protocol}

        raw = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        cfg = failover_policy.normalize_config(raw)
        link = rec.get('exit_link') or {}
        if not cfg['enabled'] or not link.get('exit_uid'):
            reason = (failover_policy.REASON_DISABLED if not cfg['enabled']
                      else failover_policy.REASON_NOT_LINKED)
            return {'action': failover_policy.ACTION_NOOP, 'reason': reason,
                    'entry_uid': entry_uid, 'protocol': protocol}

        state = failover_policy.normalize_state(raw.get('state'))
        if not state.get('primary_uid'):
            state['primary_uid'] = link['exit_uid']
        state['active_uid'] = link['exit_uid']
        events = list(raw.get('events') or [])
        known = {n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')}
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry_uid,
            primary_uid=state.get('primary_uid'),
            known_exit_uids=known,
        )

        active_ok, active_reason, _probe = await self._probe_active(entry, protocol, cfg)
        healthy = set()
        if active_ok:
            healthy.add(link['exit_uid'])

        primary_uid = state.get('primary_uid') or ''
        primary_ok = False
        if primary_uid:
            if primary_uid == link['exit_uid']:
                primary_ok = active_ok
            elif cfg['auto_failback'] or not active_ok:
                primary_ok, _primary_reason = await self._probe_candidate(primary_uid)
            if primary_ok:
                healthy.add(primary_uid)

        if not active_ok:
            for uid in cfg['backup_uids']:
                if uid == link['exit_uid'] or uid in healthy:
                    continue
                ok, _reason = await self._probe_candidate(uid)
                if ok:
                    healthy.add(uid)

        decision = failover_policy.decide(
            config=cfg,
            state=state,
            now=now,
            active_ok=active_ok,
            active_reason=active_reason,
            primary_ok=primary_ok,
            healthy_uids=healthy,
        )
        state = decision['state']
        action = decision['action']
        target = decision['target_uid']

        if action in (failover_policy.ACTION_FAILOVER, failover_policy.ACTION_FAILBACK) and target:
            from_uid = link['exit_uid']
            switch_ok = False
            switch_error = None
            async with self._failover_switch_lock:
                try:
                    # Re-resolve the entry by uid: indices may have shifted
                    # while we were probing.
                    data = self.load_data()
                    idx, current = self.find_server_by_uid(data, entry_uid)
                    if idx is None or current is None:
                        raise ExitLinkError('server_not_found', 'Server not found', 404)
                    await self.link(
                        idx, protocol, target, force=False,
                        restore_on_failure=True, source='failover', _locked=True)
                    switch_ok = True
                except Exception as err:
                    switch_error = str(err)
                    logger.warning("exit failover switch %s/%s %s -> %s failed: %s",
                                   entry_uid, protocol, from_uid, target, err)

            if switch_ok:
                state = failover_policy.record_switch(
                    state, now=now, from_uid=from_uid, to_uid=target,
                    action=action, reason=decision['reason'])
                events = failover_policy.append_event(
                    events, now=now, action=action, from_uid=from_uid,
                    to_uid=target, reason=decision['reason'])
                await self._persist_failover(entry_uid, protocol, cfg, state, events)
                return {
                    'action': action,
                    'reason': decision['reason'],
                    'from_uid': from_uid,
                    'to_uid': target,
                    'entry_uid': entry_uid,
                    'protocol': protocol,
                }

            events = failover_policy.append_event(
                events, now=now, action='switch_failed', from_uid=from_uid,
                to_uid=target, reason=switch_error or decision['reason'])
            await self._persist_failover(entry_uid, protocol, cfg, state, events)
            return {
                'action': 'switch_failed',
                'reason': switch_error or decision['reason'],
                'from_uid': from_uid,
                'to_uid': target,
                'entry_uid': entry_uid,
                'protocol': protocol,
            }

        if not active_ok and state['consecutive_failures'] == cfg['failure_threshold']:
            events = failover_policy.append_event(
                events, now=now, action='check_failed', from_uid=link['exit_uid'],
                to_uid='', reason=active_reason)

        await self._persist_failover(entry_uid, protocol, cfg, state, events)
        return {
            'action': action,
            'reason': decision['reason'],
            'from_uid': link.get('exit_uid'),
            'to_uid': None,
            'entry_uid': entry_uid,
            'protocol': protocol,
            'consecutive_failures': state['consecutive_failures'],
        }

    def list_failover_targets(self, data):
        """(server_id, protocol, entry_uid) for every instance with failover on."""
        targets = []
        for idx, server in enumerate(data.get('servers', [])):
            uid = server.get('uid')
            if not uid:
                continue
            for proto, rec in (server.get('protocols') or {}).items():
                fo = (rec or {}).get('exit_failover') or {}
                if not fo.get('enabled'):
                    continue
                if not ((rec or {}).get('exit_link') or {}).get('exit_uid'):
                    continue
                targets.append((idx, proto, uid))
        return targets

    async def run_failover_pass(self):
        """Scheduler entry: tick every instance that opted in. Disabled-by-default
        single-exit setups never appear here."""
        data = self.load_data()
        results = []
        for idx, proto, uid in self.list_failover_targets(data):
            try:
                results.append(await self.tick_failover(idx, proto))
            except Exception as err:
                logger.warning("exit failover tick %s/%s failed: %s", uid, proto, err)
                results.append({
                    'action': 'error',
                    'reason': str(err),
                    'entry_uid': uid,
                    'protocol': proto,
                })
        return results


    # ----- exit-node chain (multi-hop egress) -----

    @staticmethod
    def _chain_poll(rec):
        """(config, state, events) of the chain poll of one instance."""
        raw = rec.get('exit_chain_poll') if isinstance(rec, dict) else None
        cfg = chain_policy.normalize_config(raw)
        state = chain_policy.normalize_state((raw or {}).get('state') if isinstance(raw, dict) else None)
        events = list((raw or {}).get('events') or []) if isinstance(raw, dict) else []
        return cfg, state, events

    def _tables_in_use(self, data, host_uid):
        """Relay routing tables already taken on `host_uid` by other chains."""
        taken = set()
        for server in data.get('servers', []):
            if server.get('uid') != host_uid:
                continue
            for rec in (server.get('protocols') or {}).values():
                for hop in (rec.get('exit_link') or {}).get('chain') or []:
                    relay = hop.get('relay') if isinstance(hop, dict) else None
                    if isinstance(relay, dict) and relay.get('table'):
                        taken.add(int(relay['table']))
        return taken

    def _relay_plan(self, data, hop_srv, prefix, index, source_ip):
        """Local wiring of one relay hop: interface name, table, MTU."""
        from managers.exit_manager import ExitManager
        taken = self._tables_in_use(data, hop_srv.get('uid'))
        return {
            'iface': ExitManager.relay_iface_for(prefix, index),
            'table': ExitManager.relay_table_for(prefix, index, taken),
            'source_ip': source_ip,
            'mtu': EXIT_MTU_LIMIT,
        }

    async def _await_relay_handshake(self, exit_manager, relay):
        polls = max(1, HANDSHAKE_WAIT_SECONDS // HANDSHAKE_POLL_SECONDS)
        for attempt in range(polls):
            status = await asyncio.to_thread(exit_manager.relay_status, relay)
            if status.get('handshake_age') is not None:
                return status
            if attempt < polls - 1:
                await self._sleep(HANDSHAKE_POLL_SECONDS)
        return None

    async def _rollback_chain(self, built):
        """Undo every step of a half-built chain, newest hop first."""
        for step in reversed(built or []):
            try:
                if step['kind'] == 'entry':
                    await asyncio.to_thread(step['awg'].exit_unlink, step['protocol'])
                    await asyncio.to_thread(step['exit'].remove_peer, None,
                                            peer_id_for(step['entry_uid'], step['protocol']))
                elif step['kind'] == 'relay':
                    await asyncio.to_thread(step['exit'].relay_teardown, step['relay'])
                    await asyncio.to_thread(step['next_exit'].remove_peer, None, step['peer_id'])
                elif step['kind'] == 'final':
                    await asyncio.to_thread(step['exit'].remove_peer, None, step['peer_id'])
            except Exception as err:
                logger.warning("chain rollback %s failed: %s", step['kind'], err)

    async def _teardown_chain(self, entry, protocol):
        """Remove every interface and peer of a stored chain (newest first)."""
        data = self.load_data()
        _, rec = self._entry_by_uid(data, entry['uid'], protocol)
        record = rec.get('exit_link') or {}
        chain = record.get('chain') or []
        awg = await self._awg(entry)
        peers = []
        for index in range(len(chain) - 1, -1, -1):
            hop = chain[index]
            hop_srv, _ = self._exit(data, hop.get('uid'))
            exit_manager = await self._exit_manager(hop_srv)
            # the peer every hop holds for the node in front of it
            peers.append((exit_manager,
                          peer_id_for(entry['uid'], protocol) if index == 0
                          else f"{chain[index - 1].get('uid')}:chain{index}"))
            if index < len(chain) - 1:
                relay = hop.get('relay')
                if relay:
                    try:
                        await asyncio.to_thread(exit_manager.relay_teardown, relay)
                    except Exception as err:
                        logger.warning("relay teardown %s failed: %s", relay.get('iface'), err)
        try:
            await asyncio.to_thread(awg.exit_unlink, protocol)
        except Exception as err:
            logger.warning("entry unlink during chain teardown failed: %s", err)
        for exit_manager, peer_id in peers:
            try:
                await asyncio.to_thread(exit_manager.remove_peer, None, peer_id)
            except Exception as err:
                logger.warning("peer removal %s failed: %s", peer_id, err)

    async def _record_chain(self, entry, first_hop_srv, protocol, record, source):
        """Publish the chain only while both endpoints still describe SSH targets."""
        async with self.data_lock:
            data = self.load_data()
            current_entry, rec = self._entry_by_uid(data, entry['uid'], protocol)
            current_exit, _ = self._exit(data, first_hop_srv['uid'])
            for current, expected in ((current_entry, entry), (current_exit, first_hop_srv)):
                if any(current.get(key) != expected.get(key)
                       for key in ('host', 'ssh_port', 'username')):
                    raise ExitLinkError('server_changed',
                                        'Server endpoint changed during link setup', 409)
            rec['exit_link'] = record
            if len(record.get('chain') or []) > 1:
                # A chain may never be silently repaired by failover: a hop
                # substitution breaks the anonymity contract.
                fo = rec.get('exit_failover')
                if isinstance(fo, dict) and fo.get('enabled'):
                    fo = dict(fo)
                    fo['enabled'] = False
                    state = failover_policy.normalize_state(fo.get('state'))
                    state['last_reason'] = 'chain_mode'
                    fo['state'] = state
                    rec['exit_failover'] = fo
                existing = rec.get('exit_chain_poll') if isinstance(rec.get('exit_chain_poll'), dict) else {}
                cfg = chain_policy.normalize_config(existing)
                state = chain_policy.normalize_state((existing or {}).get('state'))
                events = list(existing.get('events') or [])
                rec['exit_chain_poll'] = {
                    **cfg,
                    'enabled': True,
                    'state': state,
                    'events': events,
                }
            self.save_data(data)

    async def build_chain(self, entry_server_id, protocol, chain_uids, *, force=False,
                          mtu_override=False, source='manual'):
        """Build (or rebuild) an ordered chain of exit nodes on one instance.

        The entry links to hop 0 exactly like a single exit link; every hop in
        the middle additionally runs its own uplink towards the next hop. One
        failure anywhere tears the whole attempt down: a half-applied chain
        would silently leak or blackhole client traffic.
        """
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        entry_uid = entry['uid']
        chain_uids = [str(uid).strip() for uid in (chain_uids or []) if str(uid or '').strip()]
        known = {n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')}
        try:
            chain_policy.validate_chain(chain_uids, entry_uid, known)
        except chain_policy.ChainError as err:
            raise ExitLinkError(err.code, err.message)
        hops = len(chain_uids)

        async with self._locks[(entry_uid, protocol)]:
            data = self.load_data()
            entry, rec = self._entry_by_uid(data, entry_uid, protocol)
            previous = rec.get('exit_link') or {}
            prefix = previous.get('chain_prefix') if previous.get('chain') else None
            if hops > 1 and not prefix:
                prefix = uuid.uuid4().hex[:4]
            if self.protocol_base(protocol) == 'awg_legacy':
                first_srv, first_rec = self._exit(data, chain_uids[0])
                if first_rec.get('obfuscation'):
                    raise ExitLinkError('exit_legacy_obfuscation',
                                        'AmneziaWG Legacy can only link to a non-obfuscated exit node')
            hops_count = hops
            dns_via_exit = True if hops_count > 1 else bool(previous.get('dns_via_exit'))
            if hops_count > 1:
                final_srv, _ = self._exit(data, chain_uids[-1])
                self._require_exit_dns(final_srv)

            awg = await self._awg(entry)
            try:
                mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
            except (TypeError, ValueError):
                mtu = 0
            try:
                entry_config = await asyncio.to_thread(awg._get_server_config, protocol)
            except Exception:
                raise ExitLinkError('state_unreadable', 'Cannot read the instance config; retry')
            if not (entry_config or '').strip():
                raise ExitLinkError('state_unreadable', 'Cannot read the instance config; retry')
            ipv6 = False
            for line in entry_config.splitlines():
                stripped = line.strip()
                if not stripped.startswith('Address'):
                    continue
                if '=' in stripped:
                    tokens = stripped.split('=', 1)[1].split(',')
                    ipv6 = any(':' in token for token in tokens)
                break
            if ipv6:
                raise ExitLinkError(
                    'exit_link_ipv6',
                    'Instance has IPv6 enabled; disable IPv6 before linking '
                    'to an exit node')
            target_mtu = chain_policy.client_mtu_for_chain(hops_count)
            warnings = []
            if hops_count > 1 and mtu and mtu > target_mtu:
                if not mtu_override:
                    raise ExitLinkError(
                        'chain_mtu_override_required',
                        f'Client MTU {mtu} cannot survive {hops_count} hops; '
                        f'it must be lowered to {target_mtu}. Apply the new MTU?')
                try:
                    await asyncio.to_thread(awg.update_awg_settings, protocol, mtu=target_mtu)
                except Exception as err:
                    raise ExitLinkError('exit_apply_failed',
                                        f'Could not lower the client MTU: {err}')
                warnings.append('exit_chain_mtu_lowered')

            built, hop_records = [], []
            prev_uplink_pub = None
            try:
                for index, uid in enumerate(chain_uids):
                    hop_srv, hop_rec = self._exit(data, uid)
                    if hop_srv.get('uid') == entry['uid']:
                        raise ExitLinkError('exit_self', 'A server cannot be its own exit node')
                    exit_manager = await self._exit_manager(hop_srv)
                    hop_name = hop_srv.get('name') or hop_srv.get('host', '')

                    # ---- incoming link: the previous node (or the entry) ----
                    if index == 0:
                        incoming_pub = await asyncio.to_thread(awg.exit_prepare_keys, protocol)
                        peer_id = peer_id_for(entry_uid, protocol)
                        peer_name = entry.get('name') or entry.get('host', '')
                    else:
                        incoming_pub = prev_uplink_pub
                        peer_id = f"{chain_uids[index - 1]}:chain{index}"
                        peer_name = f"{chain_uids[index - 1]} chain hop"
                    if not incoming_pub:
                        raise ExitLinkError('exit_apply_failed',
                                            'Previous hop has no link key; rebuild the chain')
                    peer = await asyncio.to_thread(exit_manager.add_peer, peer_id, peer_name,
                                                   incoming_pub)
                    if index == 0:
                        link = {
                            'exit_uid': uid,
                            'transit_ip': peer['transit_ip'],
                            'subnet_cidr': str(peer.get('subnet') or '10.9.0.0/24').split('/')[1],
                            'exit_public_key': peer['public_key'],
                            'psk': peer['psk'],
                            'endpoint_host': hop_srv['host'],
                            'endpoint_port': peer['port'] or hop_rec.get('port'),
                            'obfuscation': bool(peer.get('obfuscation')),
                            'awg_params': peer.get('awg_params') or {},
                            'dns_via_exit': dns_via_exit,
                        }
                        await asyncio.to_thread(awg.exit_link, protocol, link)
                        built.append({'kind': 'entry', 'awg': awg, 'exit': exit_manager,
                                      'protocol': protocol, 'entry_uid': entry_uid})
                        handshake = await self._wait_handshake(awg, protocol)
                        if not handshake and not force:
                            raise ExitLinkError('exit_no_handshake',
                                                f'No handshake from {link["endpoint_host"]} '
                                                f'within {HANDSHAKE_WAIT_SECONDS}s; the chain '
                                                f'was rolled back')
                    if index == hops_count - 1:
                        built.append({'kind': 'final', 'exit': exit_manager, 'peer_id': peer_id})

                    hop_records.append({
                        'uid': uid,
                        'name': hop_name,
                        'host': hop_srv.get('host', ''),
                        'port': hop_rec.get('port'),
                        'subnet': hop_rec.get('subnet'),
                        'transit_ip': peer['transit_ip'],
                        'psk': peer['psk'],
                        'exit_public_key': peer['public_key'],
                        'endpoint_host': hop_srv['host'],
                        'endpoint_port': peer['port'] or hop_rec.get('port'),
                        'obfuscation': bool(hop_rec.get('obfuscation')),
                        'awg_params': hop_rec.get('awg_params') or {},
                        'relay': None,
                    })

                    # ---- this hop's own uplink towards the next one ----
                    if index < hops_count - 1:
                        relay = self._relay_plan(data, hop_srv, prefix, index + 1,
                                                 peer['transit_ip'])
                        uplink_pub = await asyncio.to_thread(exit_manager.relay_prepare_keys, relay)
                        next_srv, next_rec = self._exit(data, chain_uids[index + 1])
                        next_manager = await self._exit_manager(next_srv)
                        next_peer_id = f"{uid}:chain{index + 1}"
                        next_name = f'{hop_name} / chain hop {index + 1}'
                        up_peer = await asyncio.to_thread(next_manager.add_peer, next_peer_id,
                                                          next_name, uplink_pub)
                        uplink = {
                            'transit_ip': up_peer['transit_ip'],
                            'subnet_cidr': str(up_peer.get('subnet') or '10.9.0.0/24').split('/')[1],
                            'exit_public_key': up_peer['public_key'],
                            'psk': up_peer['psk'],
                            'endpoint_host': next_srv['host'],
                            'endpoint_port': up_peer['port'] or next_rec.get('port'),
                        }
                        built.append({'kind': 'relay', 'exit': exit_manager,
                                      'next_exit': next_manager, 'relay': relay,
                                      'peer_id': next_peer_id})
                        try:
                            await asyncio.to_thread(exit_manager.relay_write_conf, relay, uplink)
                            await asyncio.to_thread(exit_manager.relay_apply, relay)
                        except Exception as err:
                            raise ExitLinkError('exit_apply_failed',
                                                f'Chain hop {index + 1} could not be brought up: {err}')
                        status = await self._await_relay_handshake(exit_manager, relay)
                        if not status and not force:
                            raise ExitLinkError('exit_no_handshake',
                                                f'No handshake on chain hop {index + 1} within '
                                                f'{HANDSHAKE_WAIT_SECONDS}s; the chain was rolled back')
                        hop_records[-1]['relay'] = relay
                        prev_uplink_pub = uplink_pub
            except Exception:
                await self._rollback_chain(built)
                raise

            record = {
                'mode': 'chain',
                'chain_prefix': prefix,
                'chain': hop_records,
                'exit_uid': chain_uids[0],
                'exit_name': hop_records[0]['name'],
                'transit_ip': hop_records[0]['transit_ip'],
                'exit_public_key': hop_records[0]['exit_public_key'],
                'endpoint_host': hop_records[0]['endpoint_host'],
                'endpoint_port': hop_records[0]['endpoint_port'],
                'obfuscation': hop_records[0]['obfuscation'],
                'client_mtu': target_mtu,
                'dns_via_exit': dns_via_exit,
                'linked_at': datetime.now().isoformat(),
                'stale': None,
            }
            first_srv, _ = self._exit(data, chain_uids[0])
            try:
                await self._record_chain(entry, first_srv, protocol, record, source)
            except Exception:
                await self._rollback_chain(built)
                raise
            await self._refresh_relay_startup(self._relay_hosts(hop_records))
            return {'status': 'success', 'exit_link': record,
                    'ipv6_refused': ipv6, 'warnings': warnings}

    async def _refresh_relay_startup(self, relays_by_host):
        """Make every relay hop come back after a container/host restart.
        `relays_by_host` maps a server uid to its relay list; an empty list
        strips that host's block from start.sh."""
        data = self.load_data()
        for uid, relays in (relays_by_host or {}).items():
            _, srv = self.find_server_by_uid(data, uid)
            if not srv:
                continue
            try:
                manager = await self._exit_manager(srv)
                await asyncio.to_thread(manager.relay_write_startup, relays)
            except Exception as err:
                logger.warning("could not refresh the relay startup of %s: %s",
                               srv.get('name'), err)

    @staticmethod
    def _relay_hosts(chain):
        """{server_uid: [relay, ...]} of a stored chain."""
        hosts = {}
        for hop in chain or []:
            if hop.get('relay'):
                hosts.setdefault(hop.get('uid'), []).append(hop['relay'])
        return hosts

    # ----- chain lifecycle: remove / repair -----

    async def remove_chain(self, entry_server_id, protocol):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        record = rec.get('exit_link') or {}
        if not record.get('chain'):
            return {'status': 'success', 'unlinked': False}
        async with self._locks[(entry['uid'], protocol)]:
            data = self.load_data()
            entry, rec = self._entry_by_uid(data, entry['uid'], protocol)
            record = rec.get('exit_link') or {}
            if not record.get('chain'):
                return {'status': 'success', 'unlinked': False}
            relay_hosts = self._relay_hosts(record.get('chain'))
            await self._teardown_chain(entry, protocol)
            await self._update_record(entry['uid'], protocol, self._drop_link_keep_failover)
            # strip the relay blocks from start.sh of every hop that had one
            await self._refresh_relay_startup({uid: [] for uid in relay_hosts})
            # bring the client MTU back to the single-hop budget
            try:
                awg = await self._awg(entry)
                target = chain_policy.client_mtu_for_chain(1)
                mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
                if mtu and mtu < target:
                    await asyncio.to_thread(awg.update_awg_settings, protocol, mtu=target)
            except Exception as err:
                logger.warning("could not restore the client MTU after chain removal: %s", err)
        return {'status': 'success', 'unlinked': True}

    async def repair_chain(self, entry_server_id, protocol):
        """Full rebuild of the stored chain (operator action, never automatic)."""
        data = self.load_data()
        _, rec = self._entry(data, entry_server_id, protocol)
        record = rec.get('exit_link') or {}
        uids = chain_policy.chain_uids(record)
        if not uids:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        await self._teardown_chain(self._entry(data, entry_server_id, protocol)[0], protocol)
        return await self.build_chain(entry_server_id, protocol, uids, force=True,
                                      mtu_override=True, source='repair')

    # ----- chain health: probe, poll, fail-closed gate -----

    async def _probe_rtt(self, after_srv, target_srv, target_port):
        """Reachability + latency of `target` as seen FROM `after_srv`.

        The chain only works if each hop can reach the next one, so the check
        is performed on the previous node of the list, not from the panel.
        Returns (ok, rtt_ms, error_code).
        """
        target_host = target_srv.get('host', '')
        if after_srv is None:
            return self._probe_from_panel(target_host, target_port)
        try:
            manager = await self._exit_manager(after_srv) if after_srv.get('protocols', {}).get(
                'exit', {}).get('installed') else await self._awg(after_srv)
        except Exception as err:
            logger.warning("chain probe: cannot reach %s: %s", after_srv.get('name'), err)
            return False, None, 'ssh_error'
        script = (
            "h=%s; p=%s; rtt=\"\"; "
            "if command -v ping >/dev/null 2>&1; then "
            "rtt=$(ping -c1 -W2 -n $h 2>/dev/null | sed -n 's/.*time=\\([0-9.]*\\).*/\\1/p' | head -1); fi; "
            "if [ -z \"$rtt\" ]; then "
            "s=$(date +%%s%%N); timeout 3 bash -c \"exec 3<>/dev/tcp/$h/$p\" 2>/dev/null; rc=$?; "
            "e=$(date +%%s%%N); if [ $rc -eq 0 ]; then rtt=$(( (e-s)/2000000 )); fi; fi; "
            "echo \"$rtt\"" % (target_host, target_port))
        try:
            # a compound script: sudo covers only the first command of a plain
            # string, so the probe is staged and run as one root script.
            out, err, code = await asyncio.to_thread(manager.ssh.run_sudo_script, script)
        except Exception as err:
            logger.warning("chain probe rtt failed on %s: %s", after_srv.get('name'), err)
            return False, None, 'ssh_error'
        value = (out or '').strip()
        if code == 0 and value:
            try:
                return True, float(value), None
            except ValueError:
                return True, None, None
        return False, None, 'probe_failed'

    def _probe_from_panel(self, target_host, target_port):
        """Panel-side fallback: TCP connect time to the transit port."""
        import socket
        started = time.time()
        try:
            with socket.create_connection((target_host, int(target_port)), timeout=3):
                return True, round((time.time() - started) * 1000, 1), None
        except Exception:
            return False, None, 'probe_failed'

    async def chain_probe(self, entry_server_id, protocol, uid, after_uid=None):
        """Availability + latency of one candidate hop, measured from the
        previous node of the list (the entry when it is the first hop)."""
        data = self.load_data()
        entry, _ = self._entry(data, entry_server_id, protocol)
        _, hop_srv = self.find_server_by_uid(data, uid)
        if not hop_srv:
            raise ExitLinkError('exit_not_found', 'Exit node not found or not installed', 404)
        after_srv = None
        if after_uid:
            _, after_srv = self.find_server_by_uid(data, after_uid)
        hop_rec = ((hop_srv.get('protocols') or {}).get('exit') or {})
        ok, rtt_ms, error = await self._probe_rtt(after_srv, hop_srv, hop_rec.get('port'))
        return {
            'status': 'success',
            'uid': uid,
            'ok': bool(ok),
            'rtt_ms': rtt_ms,
            'error': error,
            'checked_at': datetime.now().isoformat(),
            'after_uid': after_uid or entry.get('uid'),
        }

    def _chain_record(self, data, rec):
        """Stored chain, normalised: a legacy single link reads as one hop."""
        record = rec.get('exit_link') or {}
        chain = record.get('chain')
        if isinstance(chain, list) and chain:
            return record, chain
        if record.get('exit_uid'):
            hop = {
                'uid': record.get('exit_uid'),
                'name': record.get('exit_name', ''),
                'host': record.get('endpoint_host', ''),
                'port': record.get('endpoint_port'),
                'subnet': None,
                'transit_ip': record.get('transit_ip'),
                'psk': record.get('psk'),
                'exit_public_key': record.get('exit_public_key'),
                'endpoint_host': record.get('endpoint_host'),
                'endpoint_port': record.get('endpoint_port'),
                'obfuscation': bool(record.get('obfuscation')),
                'awg_params': {},
                'relay': None,
            }
            normalised = dict(record)
            normalised['mode'] = 'single'
            normalised['chain'] = [hop]
            return normalised, [hop]
        return record, []

    def chain_view(self, data, rec, entry_uid):
        """JSON-safe chain + poll state for the API/UI (no SSH)."""
        record, chain = self._chain_record(data, rec)
        cfg, state, events = self._chain_poll(rec)
        link = rec.get('exit_link') or {}
        nodes = {}
        for node in self.list_exit_nodes(data):
            if node.get('uid'):
                nodes[node['uid']] = node

        def named(uid):
            node = nodes.get(uid) or {}
            hop = next((h for h in chain if h.get('uid') == uid), {})
            return {
                'uid': uid or '',
                'name': node.get('name') or hop.get('name') or '',
                'host': node.get('host') or hop.get('host') or '',
                'port': node.get('port') or hop.get('port'),
                'subnet': node.get('subnet') or hop.get('subnet'),
                'installed': uid in nodes,
            }

        hops_view = []
        for index, hop in enumerate(chain):
            hops_view.append({
                'index': index,
                **named(hop.get('uid')),
                'relay': hop.get('relay'),
            })
        fo = rec.get('exit_failover') if isinstance(rec, dict) else None
        failover_blocked = len(chain) > 1 and bool((fo or {}).get('enabled') is False)
        return {
            'mode': 'chain' if len(chain) > 1 else 'single',
            'chain': hops_view,
            'chain_prefix': record.get('chain_prefix'),
            'client_mtu': record.get('client_mtu'),
            'dns_via_exit': bool(link.get('dns_via_exit')),
            'stale': link.get('stale'),
            'linked_at': link.get('linked_at'),
            'poll': {**cfg, 'state': state, 'events': events},
            'failover_blocked': failover_blocked,
        }

    async def poll_chain(self, entry_server_id, protocol, now=None):
        """One health pass over the whole chain. Fail-closed: any dead hop
        blackholes the entry egress until the operator repairs the chain."""
        now = now if now is not None else self._time()
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        record, chain = self._chain_record(data, rec)
        if not chain:
            return {'action': chain_policy.ACTION_NOOP,
                    'reason': chain_policy.REASON_NOT_LINKED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}
        cfg, state, events = self._chain_poll(rec)
        if not cfg.get('enabled'):
            return {'action': chain_policy.ACTION_NOOP,
                    'reason': chain_policy.REASON_DISABLED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        lock = self._locks[(entry['uid'], protocol)]
        if lock.locked():
            return {'action': chain_policy.ACTION_NOOP,
                    'reason': chain_policy.REASON_BUSY,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}
        async with lock:
            return await self._poll_chain_locked(entry['uid'], protocol, now)

    async def _poll_chain_locked(self, entry_uid, protocol, now):
        data = self.load_data()
        _, entry = self.find_server_by_uid(data, entry_uid)
        rec = ((entry or {}).get('protocols') or {}).get(protocol) or {}
        if not entry or not rec:
            return {'action': chain_policy.ACTION_NOOP, 'reason': 'entry_gone',
                    'entry_uid': entry_uid, 'protocol': protocol}
        record, chain = self._chain_record(data, rec)
        cfg, state, events = self._chain_poll(rec)
        awg = await self._awg(entry)
        hops_result = []
        for index, hop in enumerate(chain):
            uid = hop.get('uid')
            item = {'index': index, 'uid': uid, 'name': hop.get('name', ''),
                    'ok': False, 'reason': None, 'rtt_ms': None,
                    'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0}
            try:
                _, hop_srv = self.find_server_by_uid(data, uid)
                if not hop_srv:
                    item['reason'] = chain_policy.REASON_EXIT_NOT_FOUND
                    hops_result.append(item)
                    continue
                exit_manager = await self._exit_manager(hop_srv)
                running = await asyncio.to_thread(exit_manager.check_container_running)
                if not running:
                    item['reason'] = chain_policy.REASON_CONTAINER_STOPPED
                    hops_result.append(item)
                    continue
                if index == 0:
                    status = await asyncio.to_thread(awg.exit_link_status, protocol) or {}
                else:
                    status = await asyncio.to_thread(
                        exit_manager.peer_status,
                        f"{chain[index - 1].get('uid')}:chain{index}")
                item['handshake_age'] = status.get('handshake_age')
                item['rx_bytes'] = status.get('rx_bytes') or 0
                item['tx_bytes'] = status.get('tx_bytes') or 0
                if status.get('handshake_age') is None:
                    item['reason'] = (chain_policy.REASON_HANDSHAKE_ERROR
                                      if status.get('error') else chain_policy.REASON_NO_HANDSHAKE)
                    hops_result.append(item)
                    continue
                if item['handshake_age'] > cfg['handshake_max_age_seconds']:
                    item['reason'] = chain_policy.REASON_HANDSHAKE_STALE
                    hops_result.append(item)
                    continue
                relay = hop.get('relay')
                if relay:
                    relay_status = await asyncio.to_thread(exit_manager.relay_status, relay)
                    if not relay_status.get('up'):
                        item['reason'] = relay_status.get('error') or chain_policy.REASON_NO_HANDSHAKE
                        hops_result.append(item)
                        continue
                item['ok'] = True
                item['reason'] = chain_policy.REASON_OK
            except Exception as err:
                logger.warning("chain poll hop %s failed: %s", uid, err)
                item['reason'] = chain_policy.REASON_SSH_ERROR
            hops_result.append(item)

        # latency of every hop as seen from the previous node of the list
        for index, item in enumerate(hops_result):
            after = entry if index == 0 else None
            try:
                _, hop_srv = self.find_server_by_uid(data, item['uid'])
                if index > 0:
                    _, after = self.find_server_by_uid(data, chain[index - 1].get('uid'))
                hop_rec = ((hop_srv.get('protocols') or {}).get('exit') or {})
                ok, rtt_ms, _err = await self._probe_rtt(after, hop_srv, hop_rec.get('port'))
                item['rtt_ms'] = rtt_ms
            except Exception as err:
                logger.warning("chain rtt probe %s failed: %s", item.get('uid'), err)

        decision = chain_policy.decide(cfg, state, now, hops_result)
        state = decision['state']
        action = decision['action']

        if action == chain_policy.ACTION_GATE_OFF:
            try:
                await asyncio.to_thread(awg.exit_chain_gate, protocol, False)
            except Exception as err:
                logger.warning("chain gate off failed for %s/%s: %s", entry_uid, protocol, err)
        elif action == chain_policy.ACTION_GATE_ON:
            try:
                await asyncio.to_thread(awg.exit_chain_gate, protocol, True)
            except Exception as err:
                logger.warning("chain gate on failed for %s/%s: %s", entry_uid, protocol, err)

        stale = None
        if state.get('state') == chain_policy.STATE_BROKEN and state.get('broken_hop_index') is not None:
            stale = f"chain_broken_hop_{state['broken_hop_index']}"

        def mutate(r):
            link = r.get('exit_link')
            if isinstance(link, dict):
                link['stale'] = stale
            payload = chain_policy.normalize_config(r.get('exit_chain_poll'))
            payload.update({
                'enabled': cfg.get('enabled', payload['enabled']),
                'check_interval_seconds': cfg['check_interval_seconds'],
                'probe_attempts': cfg['probe_attempts'],
                'probe_interval_seconds': cfg['probe_interval_seconds'],
                'handshake_max_age_seconds': cfg['handshake_max_age_seconds'],
                'state': state,
                'hops': hops_result,
            })
            logged = chain_policy.append_event(events, now, action, decision.get('reason'),
                                               state.get('broken_hop_index'))
            payload['events'] = logged
            r['exit_chain_poll'] = payload

        await self._update_record(entry_uid, protocol, mutate)
        return {
            'action': action,
            'reason': decision.get('reason'),
            'state': state.get('state'),
            'broken_hop_index': state.get('broken_hop_index'),
            'hops': hops_result,
            'entry_uid': entry_uid,
            'protocol': protocol,
        }

    async def tick_chain(self, entry_server_id, protocol):
        """Scheduler tick: no-op unless the poll is due."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        record, chain = self._chain_record(data, rec)
        if not chain:
            return {'action': chain_policy.ACTION_NOOP,
                    'reason': chain_policy.REASON_NOT_LINKED}
        cfg, state, _events = self._chain_poll(rec)
        if not cfg.get('enabled'):
            return {'action': chain_policy.ACTION_NOOP, 'reason': chain_policy.REASON_DISABLED}
        now = self._time()
        if not chain_policy.due_for_check(state, cfg['check_interval_seconds'], now):
            return {'action': chain_policy.ACTION_NOOP, 'reason': chain_policy.REASON_NOT_DUE}
        return await self.poll_chain(entry_server_id, protocol, now=now)

    def list_chain_targets(self, data):
        """(server_id, protocol, entry_uid) for every instance with a chain."""
        targets = []
        for idx, server in enumerate(data.get('servers', [])):
            uid = server.get('uid')
            if not uid:
                continue
            for proto, rec in (server.get('protocols') or {}).items():
                record = rec.get('exit_link') if isinstance(rec, dict) else None
                if not record or not record.get('chain'):
                    continue
                poll = rec.get('exit_chain_poll') if isinstance(rec, dict) else None
                if not (poll or {}).get('enabled', True):
                    continue
                targets.append((idx, proto, uid))
        return targets

    async def run_chain_poll_pass(self):
        """Scheduler entry: poll every chain that opted in."""
        data = self.load_data()
        results = []
        for idx, proto, uid in self.list_chain_targets(data):
            try:
                results.append(await self.tick_chain(idx, proto))
            except Exception as err:
                logger.warning("exit chain poll %s/%s failed: %s", uid, proto, err)
                results.append({'action': 'error', 'reason': str(err),
                                'entry_uid': uid, 'protocol': proto})
        return results

    def chain_flags(self, data):
        """Derived flags for the server list: one badge per broken chain."""
        flags = {}
        for idx, server in enumerate(data.get('servers', [])):
            broken = None
            for proto, rec in (server.get('protocols') or {}).items():
                link = (rec or {}).get('exit_link') or {}
                if not link.get('stale'):
                    continue
                if not str(link['stale']).startswith('chain_broken_hop_'):
                    continue
                broken = {
                    'protocol': proto,
                    'stale': link.get('stale'),
                    'hop': str(link.get('stale')).rsplit('_', 1)[-1],
                    'server_name': server.get('name') or server.get('host', ''),
                }
                break
            if broken:
                flags[str(idx)] = broken
        return flags

    async def configure_chain_poll(self, entry_server_id, protocol, **fields):
        """Poll settings of a chain: interval, recovery attempts and wait."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        record, chain = self._chain_record(data, rec)
        if not chain:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        stored = rec.get('exit_chain_poll') if isinstance(rec.get('exit_chain_poll'), dict) else {}
        merged = chain_policy.normalize_config({**stored, **{
            key: fields[key] for key in (
                'enabled', 'check_interval_seconds', 'probe_attempts',
                'probe_interval_seconds', 'handshake_max_age_seconds',
            ) if key in fields
        }})
        state = chain_policy.normalize_state(stored.get('state'))
        events = list(stored.get('events') or [])

        def mutate(r):
            payload = dict(merged)
            payload['state'] = state
            payload['events'] = events
            r['exit_chain_poll'] = payload

        await self._update_record(entry['uid'], protocol, mutate)
        data = self.load_data()
        _, server = self.find_server_by_uid(data, entry['uid'])
        rec = ((server or {}).get('protocols') or {}).get(protocol) or {}
        return {'status': 'success',
                'chain': self.chain_view(data, rec, entry['uid'])}

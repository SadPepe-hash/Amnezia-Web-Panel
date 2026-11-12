# Exit node chain (multi-hop egress)

Status: implemented on `feat/exit-node-chain` (stacked on `deploy/ovh-current`).

## What it does

Instead of picking ONE exit node for an AWG instance, the operator builds an
ordered list:

```
entry (AWG instance) --exit0--> hop1 (exit) --exit1--> hop2 (exit) --...--> final exit --> internet
```

Client traffic leaves only through the last node of the chain. Every hop in the
middle relays the previous node into its own uplink, so the entry sees a single
next hop exactly like a plain exit link.

## Why not one tunnel

AmneziaWG/WireGuard cannot say "send this packet to the next hop": one interface
has one endpoint and one AllowedIPs set. A chain therefore means one interface
per hop, built by the panel.

## Roles

| Node | Protocols | Interfaces in the exit container |
|---|---|---|
| entry | any AWG instance | `exit0` (as today) |
| hop 1..N-1 (relay) | `exit` | `transit0` (accepts the previous node) + `c<prefix><i>` (its uplink) |
| hop N (final) | `exit` | `transit0` only, NAT to the internet |

The relay runs inside the SAME `amnezia-exit` container (same image, `awg` /
`awg-quick` already inside) - no extra container, no extra UDP port.

## Wiring on a relay (managers/exit_manager.py)

* `c<prefix><i>` — interface name; `<prefix>` is a 4-hex chain id from
  `exit_link.chain_prefix`, `<i>` the hop index, so several chains can share one
  relay host without name clashes.
* Routing table `200 + crc32("<prefix>:<i>") % 500` (bumped on clash, stored in
  the hop record) with `default dev c<prefix><i>`, a rule from the previous
  hop's /32 and MASQUERADE — the container has its own namespace, so no host
  tables are touched.
* NAT is per peer /32 (`peer.transit_ip`), never per subnet, so two chains with
  the same default transit subnet cannot collide.
* `rp_filter=2` on the uplink, MSS clamp in both directions, conntrack flush of
  the relayed source so flows opened before the link reopen.
* The relay block carries NO DNS exception: DNS follows the chain.

## Data model (data.json)

```
protocols['<awg>'].exit_link = {
  mode: 'chain',
  chain_prefix: 'a1b2',
  chain: [ {uid, name, host, port, subnet,
            transit_ip, psk, exit_public_key,          # link INTO this hop
            endpoint_host, endpoint_port, obfuscation, awg_params,
            relay: {iface, table, source_ip, mtu} | null} ],
  client_mtu: 1340,
  dns_via_exit: true,        # forced true when len(chain) > 1
  linked_at, stale
}
protocols['<awg>'].exit_chain_poll = {
  enabled, check_interval_seconds (30), probe_attempts (3),
  probe_interval_seconds (300), handshake_max_age_seconds (240),
  state: {...}, hops: [...], events: [...]
}
```

A legacy single-exit link reads as `mode='single'` with one hop - nothing is
migrated on read, `chain_view()` normalises on the fly.

## Health and the fail-closed gate

`poll_chain` checks, per hop: exit container running, handshake age of the peer
facing the previous node (for relays also the uplink route), and the RTT towards
the next node measured **on the previous node of the list** (never "in
principle"). Any dead hop:

* marks `exit_link.stale = chain_broken_hop_<k>`,
* runs `x_chain_gate off` on the entry: the policy table's default route becomes
  a blackhole, so clients keep their tunnel and have NO internet,
* writes an event; recovery probes run `probe_attempts` times every
  `probe_interval_seconds` while the channel stays cut,
* a healthy chain reopens the gate (`x_chain_gate on`) and clears `stale`.

There is NO automatic substitution: failover is refused outright while a chain
is set (`failover_not_allowed_with_chain`), because a substituted hop breaks the
anonymity contract.

## Repair

`Repair` is a FULL rebuild: teardown of every hop (entry first, then relays
newest-first, peers removed per hop) and a fresh build with handshake checks.
Manual only - the poll never repairs by itself.

## MTU

`client_mtu = 1420 - 80 * (hops - 1)`, floor 1280. The client MTU of the instance
is rewritten when the chain is saved (explicit confirmation in the UI) and
restored to the single-hop budget when the chain is removed.

## API

| Method | Path |
|---|---|
| POST | `/api/servers/{id}/exit-link/chain` |
| POST | `/api/servers/{id}/exit-link/chain/remove` |
| POST | `/api/servers/{id}/exit-link/chain/repair` |
| POST | `/api/servers/{id}/exit-link/chain/probe` |
| POST | `/api/servers/{id}/exit-link/chain/status` |
| POST | `/api/servers/{id}/exit-link/chain/poll` |
| POST | `/api/servers/{id}/exit-link/chain/config` |
| GET | `/api/servers/exit_chain_flags` |

## UI

* `templates/server.html`: the single `<select>` stays for one hop; for a chain
  the modal shows the ordered list with probe latency per added node, the
  per-hop status table (status, RTT, handshake age, rx/tx) and the poll
  settings.
* `templates/index.html`: red "chain broken" badge per server card, fed by
  `/api/servers/exit_chain_flags` (derived, no SSH).
* Background loop `exit_chain_poll_background_loop` ticks every chain on its own
  interval (scheduler 10 s).

## Tests

`tests/test_exit_chain_service.py` (31 tests): build 1/2/3 hops, unique relay
interfaces and tables, rollback of a half-built chain, MTU confirmation and
budget, DNS requirement on the final hop, validation codes, failover ban,
legacy-link normalisation, fail-closed gate open/close/stale handshake/dead
container, recovery wait, RTT from the previous node, teardown, repair,
relay shell content (`bash -n` + no DNS exception) and the API wiring.

## Fail-closed guarantees (after the audit fixes)

Two independent audits (inferx/deepseek-v4.1-flash, nvidia/nemotron-3-ultra)
found four critical defects in the first implementation; all are fixed and
covered by regression tests in `ChainAuditRegressionTests`:

1. **The gate must actually cut.** `x_chain_gate off` now DELETES the
   `default dev exit0` route and leaves exactly one default - a blackhole at
   metric 0 - and verifies the table before reporting success. A blackhole at a
   higher metric next to the real default changes nothing (the kernel picks the
   lower metric), which is what the first version did.
2. **The gate is durable.** The decision is persisted as a marker file
   (`/opt/amnezia/awg/exit/chain_gate_off`) and start.sh re-applies
   `x_chain_gate off` at boot, so restarting the container or the host cannot
   reopen a broken chain. The poll re-applies the gate on every pass while the
   chain is broken.
3. **A relay may never leak.** `x_relay_up` installs the table blackhole AND a
   `FORWARD -i transit0 -o eth0 -s <prev /32> -j DROP` before `awg-quick up`,
   and removes the guard only after the uplink is verified. Every relay owns its
   routing table, its policy-rule preference and its interface name
   (`c<prefix><i>`, table/pref = deterministic per (prefix, hop index), bumped
   on clash), so several chains can share one relay host and a teardown cannot
   delete another chain's rule. `relay_status` reports up only when the rule
   AND the uplink default are both present.
4. **DNS follows the chain.** `dns_via_exit` cannot be turned off while a chain
   is set (`dns_not_allowed_with_chain`), enabling it validates AmneziaDNS on
   the FINAL hop, and the automatic DNS-uninstall path skips chains.

Other confirmed findings: a previous chain is torn down before a rebuild
(shortening/reordering leaves no orphan interfaces, rules, peers or start.sh
blocks); the single-link endpoint refuses to overwrite a chain; a lowered client
MTU is restored when the build fails; a failed entry unlink keeps the record
(`stale=teardown_pending`) instead of reporting a silent success; PSKs are
never stored in the chain record nor returned by the API; relay values are
validated (iface regex, int table/pref, IPv4 source, MTU range) before they
reach a root shell and the RTT probe passes host/port as script arguments; the
relay startup block is spliced into the existing start.sh (WARP blocks survive);
the per-hop status is part of `chain_view`; failover that the chain disabled is
re-enabled when the chain is removed; clamped poll settings are reported; the
server-list badge refreshes every 60 s and clears itself.

## Second audit round (two auditors again)

The re-audit found that the first fix round was itself broken; all of it is
fixed in the second round, again with one regression test each:

1. **The RTT probe never ran** (inferx N1): the script had an `else` after a
   closed `if` (`bash -n` exit 2) and `run_sudo_script` has no argv, so `$1/$2`
   were empty. Now: host/port are validated (IPv4/hostname regex, port range)
   and `shlex.quote()`d into the script, the branch structure is fixed, and a
   test runs `bash -n` on the exact string.
2. **The rule verification could never match** (inferx N2): iproute2 prints
   `pref:\tfrom ...` with a tab, both checks used a literal space, so
   `x_relay_up` always returned 3 (a 2+ hop chain was unbuildable) and
   `relay_status.rule_ok` was always False (a built chain was gated off on the
   first poll). Now both match `[[:space:]]+`, `relay_status` parses fields.
3. **The relay still leaked** (inferx N3): the policy rule was installed AFTER
   `awg-quick up`, so the pre-installed blackhole was unreferenced and the
   previous hop kept using the main table; the eth0 DROP guard was appended
   behind the base start.sh ACCEPT (iptables is first-match) and was removed
   before the verification. Now: rule + blackhole + `x_ipt_ins` (insert at
   position 1) BEFORE `awg-quick up`, guard removed only after verification.
4. **A rebuild dropped the kill-switch** (inferx N4/N5): `exit_unlink` removes
   the rules and flushes table 200, so clients fell back to the entry's eth0
   for the whole rebuild (and the gate could not cut: nothing pointed at
   table 200). Now `_teardown_chain(entry_action='cut')` runs the new
   `x_chain_cut` (interface down, kill-switch and blackhole kept) as the FIRST
   step, and a successful build reopens the egress with `x_chain_gate on`.
5. **The gate marker outlived the chain** (inferx N6): nothing removed
   `chain_gate_off` when a chain was removed, so the next restart blackholed a
   healthy single link with no poll to reopen it. Now the teardown action
   removes the marker, and `remove_chain` unlinks the entry.
6. **`link()` could still overwrite a chain** (inferx N8): the guard only fired
   for a different `exit_uid`, and a chain's `exit_uid` is its first hop. Now
   any stored chain is rejected with `chain_present_use_chain_api`.
7. **`unlink()` bypassed the chain removal** (inferx N9/N14): it swallowed
   entry failures, never stripped relay startup blocks, never restored the MTU
   and left failover disabled. Now it delegates to `remove_chain` (outside its
   own lock, which `remove_chain` re-acquires).
8. **Relay wiring drifted on every rebuild** (inferx N10): `_relay_plan` read a
   stale snapshot that still contained the chain being replaced, bumping
   table/pref by one each time. Now the rebuild drops the record and re-reads
   the store before planning, so `crc32(prefix:index)` is stable.
9. **Legacy records had no `rule_pref`** (inferx N11): `_chain_record` fills it
   on read, so a chain built by the first commit is not read as broken.
10. **Cross-chain startup interference** (nemotron N1 + inferx N13): the relay
    block was written per chain and any exit start.sh re-render dropped it. Now
    each uplink registers `KEY=VALUE` params inside the container, the startup
    block is spliced from that registry (the union of all chains on the host)
    on every build/remove AND after any start.sh re-render, teardown removes
    the entry, and the splice uses `count=1`.
11. **Interface-name collisions** (inferx N12): `_tables_in_use` also collects
    ifaces and `_relay_plan` regenerates the chain prefix on collision.
12. **ping-only probes claimed success** (inferx N15): a hop whose transit port
    never answered now reads as not reachable.

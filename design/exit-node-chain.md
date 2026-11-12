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

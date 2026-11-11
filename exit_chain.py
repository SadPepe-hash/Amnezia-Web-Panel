"""Chain (multi-hop) policy for exit-node links: validation, MTU budget and
fail-closed health decisions.

Pure module, no SSH/asyncio: everything that decides *what* a chain looks like
and *when* it is considered broken lives here and is unit-tested without a
panel. ExitLinkService applies the decisions over the existing link primitives.

A chain is an ordered list of exit-node server uids:

    entry --hop0--> hop1 --hop1--> hop2 ... --hopN--> final exit

Hop 0 receives a peer from the entry. Hops 1..N-1 additionally run a link of
their own towards hop i+1 (the "relay" role). Hop N is a plain exit.
"""

MAX_CHAIN_HOPS = 8
CLIENT_MTU_LIMIT = 1420        # one hop of overhead budget (EXIT_MTU_LIMIT)
HOP_OVERHEAD_BYTES = 80        # conservative WG+AWG+obfuscation overhead per hop
MIN_CLIENT_MTU = 1280

DEFAULT_CHECK_INTERVAL_SECONDS = 30
DEFAULT_PROBE_ATTEMPTS = 3
DEFAULT_PROBE_INTERVAL_SECONDS = 300
HANDSHAKE_MAX_AGE_SECONDS_MIN = 60
HANDSHAKE_MAX_AGE_SECONDS_MAX = 900
CHECK_INTERVAL_MIN, CHECK_INTERVAL_MAX = 10, 3600
PROBE_ATTEMPTS_MIN, PROBE_ATTEMPTS_MAX = 1, 20
PROBE_INTERVAL_MIN, PROBE_INTERVAL_MAX = 30, 86400
FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX = 1, 20
MAX_EVENTS = 50

ACTION_NOOP = 'noop'
ACTION_GATE_OFF = 'gate_off'      # fail-closed: clients get no internet
ACTION_GATE_ON = 'gate_on'        # chain healthy again
ACTION_RETRY = 'retry'            # recovery probe while the chain stays cut

REASON_DISABLED = 'disabled'
REASON_NOT_LINKED = 'not_linked'
REASON_NOT_DUE = 'not_due'
REASON_BUSY = 'skipped_busy'
REASON_OK = 'ok'
REASON_NO_HANDSHAKE = 'no_handshake'
REASON_HANDSHAKE_ERROR = 'handshake_error'
REASON_HANDSHAKE_STALE = 'handshake_stale'
REASON_CONTAINER_STOPPED = 'container_stopped'
REASON_EXIT_NOT_FOUND = 'exit_not_found'
REASON_SSH_ERROR = 'ssh_error'
REASON_PROBE_ERROR = 'probe_error'
REASON_PROBE_FAILED = 'probe_failed'

STATE_BROKEN = 'broken'
STATE_HEALTHY = 'healthy'
STATE_UNKNOWN = 'unknown'


class ChainError(ValueError):
    """User-facing chain validation failure: `code` is stable for the UI/i18n."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def is_chain(record):
    return bool(record) and bool(record.get('chain'))


def chain_uids(record):
    """Ordered uids of a single or chain exit_link record."""
    record = record or {}
    chain = record.get('chain')
    if isinstance(chain, list) and chain:
        return [str(h.get('uid') or '') for h in chain if isinstance(h, dict)]
    uid = record.get('exit_uid')
    return [str(uid)] if uid else []


def chain_length(record):
    return len(chain_uids(record))


def validate_chain(uids, entry_uid, known_exit_uids):
    """Validate an ordered chain before anything is built.

    Raises ChainError with a stable code: chain_empty, chain_self,
    chain_duplicate_node, chain_too_long, exit_not_found.
    """
    if not uids:
        raise ChainError('chain_empty', 'Add at least one exit node to the chain')
    if len(uids) > MAX_CHAIN_HOPS:
        raise ChainError('chain_too_long',
                         f'A chain may hold at most {MAX_CHAIN_HOPS} exit nodes')
    seen = set()
    for uid in uids:
        if not isinstance(uid, str) or not uid.strip():
            raise ChainError('chain_empty', 'Invalid exit node in the chain')
        uid = uid.strip()
        if uid == entry_uid:
            raise ChainError('exit_self', 'A server cannot be its own exit node')
        if uid in seen:
            raise ChainError('chain_duplicate_node',
                             'The same exit node may not appear twice in one chain')
        if uid not in known_exit_uids:
            raise ChainError('exit_not_found', 'Exit node not found or not installed')
        seen.add(uid)


def client_mtu_for_chain(len_chain):
    """Client MTU that survives `len_chain` hops of tunnel encapsulation."""
    return max(MIN_CLIENT_MTU, CLIENT_MTU_LIMIT - HOP_OVERHEAD_BYTES * max(0, len_chain - 1))


# ----- stored config / state (mirrors exit_failover.py conventions) -----

def default_config():
    return {
        'enabled': True,
        'check_interval_seconds': DEFAULT_CHECK_INTERVAL_SECONDS,
        'failure_threshold': 1,
        'probe_attempts': DEFAULT_PROBE_ATTEMPTS,
        'probe_interval_seconds': DEFAULT_PROBE_INTERVAL_SECONDS,
        'handshake_max_age_seconds': 240,
    }


def default_state():
    return {
        'state': STATE_UNKNOWN,
        'gate': 'off',              # 'off' = blackhole, clients have no internet
        'broken_hop_index': None,
        'last_check_at': None,
        'last_ok': None,
        'last_reason': None,
        'consecutive_failures': 0,
        'consecutive_successes': 0,
        'recovery_attempts_left': 0,
        'next_recovery_at': None,
        'last_break_at': None,
        'last_restore_at': None,
    }


def _clamp_int(value, default, lo, hi):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def _as_bool(value, default):
    if value is None:
        return default
    return bool(value)


def normalize_config(raw):
    """Coerce a stored blob into a valid config. Unknown keys are ignored."""
    src = raw if isinstance(raw, dict) else {}
    cfg = default_config()
    cfg['enabled'] = _as_bool(src.get('enabled'), True)
    cfg['check_interval_seconds'] = _clamp_int(
        src.get('check_interval_seconds'), DEFAULT_CHECK_INTERVAL_SECONDS,
        CHECK_INTERVAL_MIN, CHECK_INTERVAL_MAX)
    cfg['failure_threshold'] = _clamp_int(
        src.get('failure_threshold'), 1,
        FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX)
    cfg['probe_attempts'] = _clamp_int(
        src.get('probe_attempts'), DEFAULT_PROBE_ATTEMPTS,
        PROBE_ATTEMPTS_MIN, PROBE_ATTEMPTS_MAX)
    cfg['probe_interval_seconds'] = _clamp_int(
        src.get('probe_interval_seconds'), DEFAULT_PROBE_INTERVAL_SECONDS,
        PROBE_INTERVAL_MIN, PROBE_INTERVAL_MAX)
    cfg['handshake_max_age_seconds'] = _clamp_int(
        src.get('handshake_max_age_seconds'), 240,
        HANDSHAKE_MAX_AGE_SECONDS_MIN, HANDSHAKE_MAX_AGE_SECONDS_MAX)
    return cfg


def normalize_state(raw):
    src = raw if isinstance(raw, dict) else {}
    state = default_state()
    for key in state:
        if key in src:
            state[key] = src[key]
    if state.get('gate') not in ('on', 'off'):
        state['gate'] = 'off'
    if state.get('state') not in (STATE_HEALTHY, STATE_BROKEN, STATE_UNKNOWN):
        state['state'] = STATE_UNKNOWN
    return state


# ----- fail-closed policy -----

def evaluate_chain_health(hops):
    """`hops` = list of per-hop probe results, in chain order.

    Each item: {'index': i, 'ok': bool, 'reason': str, 'handshake_age': int|None}.
    Returns (ok, reason, broken_index): the FIRST broken hop is the answer —
    upstream hops are irrelevant once a hole exists in front of them.
    """
    for hop in hops or []:
        if not hop.get('ok'):
            return False, hop.get('reason') or REASON_NO_HANDSHAKE, hop.get('index')
    if not hops:
        return False, REASON_EXIT_NOT_FOUND, None
    return True, REASON_OK, None


def decide(config, state, now, hops):
    """What the entry must do with its egress gate.

    Returns {'action': ..., 'reason': ..., 'state': <new state>}. The caller
    performs the gate change (blackhole / restore) — this function only decides.
    """
    cfg = config if isinstance(config, dict) else normalize_config(config)
    state = dict(state if isinstance(state, dict) else {})
    for key, value in default_state().items():
        state.setdefault(key, value)

    if not cfg.get('enabled'):
        state['last_check_at'] = now
        state['last_reason'] = REASON_DISABLED
        return {'action': ACTION_NOOP, 'reason': REASON_DISABLED, 'state': state}

    ok, reason, broken_index = evaluate_chain_health(hops)
    state['last_check_at'] = now

    if ok:
        was_broken = state.get('state') == STATE_BROKEN or state.get('gate') == 'off'
        state['state'] = STATE_HEALTHY
        state['gate'] = 'on'
        state['consecutive_failures'] = 0
        state['consecutive_successes'] = int(state.get('consecutive_successes') or 0) + 1
        state['broken_hop_index'] = None
        state['recovery_attempts_left'] = 0
        state['next_recovery_at'] = None
        state['last_ok'] = now
        state['last_reason'] = REASON_OK
        if was_broken:
            state['last_restore_at'] = now
            return {'action': ACTION_GATE_ON, 'reason': REASON_OK, 'state': state}
        return {'action': ACTION_NOOP, 'reason': REASON_OK, 'state': state}

    # broken: fail closed. No automatic substitution of another exit.
    state['consecutive_successes'] = 0
    state['consecutive_failures'] = int(state.get('consecutive_failures') or 0) + 1
    state['broken_hop_index'] = broken_index
    state['last_reason'] = reason
    already_broken = state.get('state') == STATE_BROKEN

    if not already_broken and state['consecutive_failures'] < cfg['failure_threshold']:
        return {'action': ACTION_RETRY, 'reason': REASON_NOT_DUE, 'state': state}

    if not already_broken:
        state['state'] = STATE_BROKEN
        state['gate'] = 'off'
        state['last_break_at'] = now
        state['recovery_attempts_left'] = cfg['probe_attempts']
        state['next_recovery_at'] = now + cfg['probe_interval_seconds']
        return {'action': ACTION_GATE_OFF, 'reason': reason, 'state': state}

    # already broken: spend a recovery attempt when the wait time has passed
    attempts_left = int(state.get('recovery_attempts_left') or 0)
    next_at = state.get('next_recovery_at')
    if attempts_left <= 0:
        return {'action': ACTION_NOOP, 'reason': REASON_BUSY, 'state': state}
    if next_at is not None and now < next_at:
        return {'action': ACTION_NOOP, 'reason': REASON_NOT_DUE, 'state': state}

    state['recovery_attempts_left'] = attempts_left - 1
    state['next_recovery_at'] = now + cfg['probe_interval_seconds']
    if state['recovery_attempts_left'] <= 0:
        # last attempt just spent: the next failed probe is the final word
        state['next_recovery_at'] = None
    return {'action': ACTION_RETRY, 'reason': reason, 'state': state}


def due_for_check(state, interval_seconds, now):
    last = (state or {}).get('last_check_at')
    if not last:
        return True
    try:
        return float(now) - float(last) >= float(interval_seconds)
    except (TypeError, ValueError):
        return True


def append_event(events, now, action, reason, hop_index=None):
    """Bounded event log; newest first, like exit_failover."""
    events = list(events or [])
    events.insert(0, {
        'ts': _iso(now),
        'action': action,
        'reason': reason,
        'hop_index': hop_index,
    })
    return events[:MAX_EVENTS]


def _iso(now):
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(now), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


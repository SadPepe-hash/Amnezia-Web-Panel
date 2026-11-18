"""Network diagnostics add-ons: Ookla Speedtest CLI and packet loss (ping/MTR).

Pure logic only: target validation, remote command builders, output parsers
and the state store. SSH wiring lives in app.py, so everything here is tested
without a panel, a server or a network.

Ookla licensing: the speedtest binary is proprietary and is never redistributed
by the panel. The add-on downloads Ookla's official static build directly from
https://install.speedtest.net into /usr/local/bin and every run passes
``--accept-license --accept-gdpr``, i.e. the operator accepts Ookla's terms for
their own server. No license accepted -> no install, no run. The
package-manager installer is not used: it rejects Debian 12+ hosts.

State layout (``<DATA_FILE>.diagnostics_state.json``)::

    {"version": 1,
     "servers": {"<server_uid>": {
         "apps": {"speedtest": {"installed": bool, "version": str, "at": int},
                  "loss": {"installed": bool, "mtr": str, "at": int}},
         "targets": ["1.1.1.1", ...],
         "speedtest": {download_mbps, upload_mbps, ping_ms, jitter_ms,
                       isp, server, url, at},
         "loss": {"<target>": {loss_pct, rtt_min, rtt_avg, rtt_max, at}}}},
     "updated_at": int}
"""
import ipaddress
import json
import os
import re
import shlex
import tempfile
import threading
import time

DEFAULT_TARGETS = ('1.1.1.1', '8.8.8.8', 'google.com', 'yandex.ru')
MAX_TARGETS = 8
PING_COUNT = 20
STATE_VERSION = 1

# Ookla's apt script only supports Debian <= 11, so the add-on uses the
# official static build instead: downloaded from Ookla at install time, never
# bundled with this repo. The binary is placed in PATH and verified by version.
SPEEDTEST_INSTALL = (
    'set -e; export DEBIAN_FRONTEND=noninteractive; '
    'command -v curl >/dev/null 2>&1 || apt-get install -y curl ca-certificates; '
    'ARCH=$(uname -m); case "$ARCH" in '
    'x86_64|amd64) PKG=linux-x86_64;; '
    'aarch64|arm64) PKG=linux-aarch64;; '
    'armv7l|armv7) PKG=linux-armhf;; '
    '*) echo "unsupported arch: $ARCH" >&2; exit 1;; esac; '
    'TMP=$(mktemp -d); '
    'curl -fsSL "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-$PKG.tgz" '
    '| tar xz -C "$TMP"; '
    'install -m 0755 "$TMP/speedtest" /usr/local/bin/speedtest; '
    'rm -rf "$TMP"; '
    '/usr/local/bin/speedtest --version | head -1; '
    '/usr/local/bin/speedtest --version | grep -q "Speedtest by Ookla"'
)
# ping ships with the base image; mtr adds per-hop loss for deeper diagnosis.
LOSS_INSTALL = (
    'set -e; export DEBIAN_FRONTEND=noninteractive; '
    'apt-get install -y iputils-ping mtr-tiny; '
    'command -v ping; command -v mtr'
)
PROBE_COMMAND = (
    'ST=$(command -v /usr/local/bin/speedtest 2>/dev/null || command -v speedtest 2>/dev/null || echo none); '
    "printf 'SPEEDTEST=%s\\n' \"$ST\"; "
    'if [ "$ST" != none ]; then '
    "printf 'SPEEDTEST_VERSION=%s\\n' \"$(\"$ST\" --version 2>/dev/null | head -1)\"; "
    "else printf 'SPEEDTEST_VERSION=\\n'; fi; "
    "printf 'MTR=%s\\n' \"$(command -v mtr || echo none)\"; "
    "printf 'PING=%s\\n' \"$(command -v ping || echo none)\""
)
DEFAULT_SPEEDTEST_BIN = '/usr/local/bin/speedtest'
SPEEDTEST_JOB_DIR = '/tmp/amnezia-diag-speedtest'
_BIN_RE = re.compile(r'^/[A-Za-z0-9._/@+-]{1,200}$')

_HOSTNAME_RE = re.compile(
    r'^(?!-)(?:[A-Za-z0-9-]{1,63})(?<!-)'
    r'(?:\.(?!-)(?:[A-Za-z0-9-]{1,63})(?<!-))*$'
)
_VERSION_RE = re.compile(r'Speedtest by Ookla\s+([0-9][0-9.]*)')
_LOSS_RE = re.compile(r'([0-9]+(?:\.[0-9]+)?)% packet loss')
_PACKETS_RE = re.compile(r'([0-9]+) packets transmitted, ([0-9]+) (?:packets )?received')
_RTT_RE = re.compile(
    r'(?:rtt|round-trip)[^=]*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)')


def normalize_target(raw):
    """Return a safe hostname/IPv4/IPv6 literal, or None.

    Targets are pasted into a shell command, so anything that is not a plain
    address is rejected here instead of being quoted and hoped for.
    """
    value = str(raw or '').strip()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if ':' in value or '/' in value:
        return None
    value = value.rstrip('.').lower()
    return value if _HOSTNAME_RE.match(value) else None


def add_target(targets, raw):
    """Append a validated target. Returns ``(targets, error_code)``."""
    current = list(targets) if isinstance(targets, list) else list(DEFAULT_TARGETS)
    value = normalize_target(raw)
    if not value:
        return current, 'invalid_target'
    if value in current:
        return current, 'duplicate_target'
    if len(current) >= MAX_TARGETS:
        return current, 'too_many_targets'
    return current + [value], None


def remove_target(targets, raw):
    """Drop one target. Defaults are seeds, not protected rows."""
    current = list(targets) if isinstance(targets, list) else list(DEFAULT_TARGETS)
    value = normalize_target(raw)
    if not value:
        return current, 'invalid_target'
    if value not in current:
        return current, 'target_not_found'
    return [item for item in current if item != value], None


def ping_command(target, count=PING_COUNT):
    """One ping run; -i 0.2 (fast) is root-only, hence the runtime guard."""
    safe = shlex.quote(normalize_target(target) or '')
    return (
        'LC_ALL=C; PING="ping -n -c %d -W 2"; '
        '[ "$(id -u)" = 0 ] && PING="$PING -i 0.2"; '
        '%s %s 2>&1' % (count, '$PING', safe)
    )


def speedtest_command(path=None):
    """Ookla run command for the inspected binary, never a look-alike."""
    binary = path if path and _BIN_RE.match(path) else DEFAULT_SPEEDTEST_BIN
    return '%s --accept-license --accept-gdpr -f json' % shlex.quote(binary)


def speedtest_job_start(path=None):
    """Start Ookla in the background and stream JSONL progress to a file.

    The panel cannot stream a 30-second SSH command, so the test runs detached
    on the host; the page polls the file and shows real numbers as they arrive.
    """
    binary = path if path and _BIN_RE.match(path) else DEFAULT_SPEEDTEST_BIN
    job = SPEEDTEST_JOB_DIR
    inner = ('%s --accept-license --accept-gdpr -f jsonl '
             '--progress-update-interval=200 > %s/out.jsonl 2> %s/err; '
             'echo $? > %s/rc') % (shlex.quote(binary), job, job, job)
    return ('mkdir -p %s; rm -f %s/out.jsonl %s/err %s/rc %s/pid; '
            'setsid sh -c %s </dev/null >/dev/null 2>&1 & echo $! > %s/pid'
            % (job, job, job, job, job, shlex.quote(inner), job))


def speedtest_stop_command():
    """Kill the detached test by its process group (start uses setsid)."""
    job = SPEEDTEST_JOB_DIR
    return (
        f'D={job}; if [ -f "$D/pid" ]; then '
        'PID=$(cat "$D/pid"); '
        'kill -TERM -"$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null; '
        'sleep 1; '
        'kill -KILL -"$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null; '
        'rm -f "$D/pid"; fi; echo stopped'
    )


def speedtest_progress_command():
    job = SPEEDTEST_JOB_DIR
    return (
        f'D={job}; tail -c 12000 "$D/out.jsonl" 2>/dev/null; '
        'printf \'\\n@@RC@@%s\\n\' "$(cat "$D/rc" 2>/dev/null)"; '
        'printf \'\\n@@ERR@@\'; tail -c 300 "$D/err" 2>/dev/null'
    )


def parse_speedtest_progress(text):
    """Turn the JSONL tail + rc marker into a live state for the gauge."""
    raw = text or ''
    state = {'state': 'running', 'phase': 'ping'}
    rc = None
    if '@@RC@@' in raw:
        tail = raw.split('@@RC@@', 1)[1]
        rc_line = tail.splitlines()[0].strip() if tail else ''
        rc = int(rc_line) if rc_line.lstrip('-').isdigit() else None
        if '@@ERR@@' in tail:
            err = tail.split('@@ERR@@', 1)[1].strip()
            if err:
                state['error'] = err[-300:]
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get('type')
        if kind == 'ping':
            ping = event.get('ping') or {}
            if ping.get('latency') is not None:
                state['ping_ms'] = round(float(ping['latency']), 1)
            if ping.get('jitter') is not None:
                state['jitter_ms'] = round(float(ping['jitter']), 1)
        elif kind == 'download':
            download = event.get('download') or {}
            if download.get('bandwidth'):
                state['download_mbps'] = round(float(download['bandwidth']) * 8 / 1e6, 1)
            state['phase'] = 'download'
        elif kind == 'upload':
            upload = event.get('upload') or {}
            if upload.get('bandwidth'):
                state['upload_mbps'] = round(float(upload['bandwidth']) * 8 / 1e6, 1)
            state['phase'] = 'upload'
        elif kind == 'result':
            try:
                state['result'] = parse_speedtest(json.dumps(event))
                state['phase'] = 'done'
            except ValueError:
                pass
    if rc is not None:
        if state.get('result'):
            state['state'] = 'done'
        else:
            state['state'] = 'failed'
    return state


def parse_ping(output):
    """Parse iputils ping output into loss/rtt numbers (None when unknown)."""
    text = output or ''
    result = {'loss_pct': None, 'rtt_min': None, 'rtt_avg': None, 'rtt_max': None,
              'sent': None, 'received': None}
    loss = _LOSS_RE.search(text)
    if loss:
        result['loss_pct'] = float(loss.group(1))
    packets = _PACKETS_RE.search(text)
    if packets:
        result['sent'] = int(packets.group(1))
        result['received'] = int(packets.group(2))
    rtt = _RTT_RE.search(text)
    if rtt:
        result['rtt_min'], result['rtt_avg'], result['rtt_max'] = (
            round(float(part), 1) for part in rtt.groups())
    return result


def parse_probe(output):
    """Parse PROBE_COMMAND output into per-app install state.

    A ``speedtest`` executable is not enough: the popular Python speedtest-cli
    answers --version with "speedtest-cli 2.1.3" and silently returns rc 0 with
    empty stdout for Ookla flags. Only the Ookla banner counts as installed.
    """
    values = {}
    for line in (output or '').splitlines():
        key, sep, value = line.strip().partition('=')
        if sep:
            values[key] = value.strip()
    path = values.get('SPEEDTEST', 'none')
    mtr_path = values.get('MTR', 'none')
    ping_path = values.get('PING', 'none')
    version = _VERSION_RE.search(values.get('SPEEDTEST_VERSION', ''))
    ookla = path not in ('', 'none') and bool(version)
    return {
        'speedtest': {
            'installed': ookla,
            'version': version.group(1) if version else '',
            'path': path if ookla else '',
        },
        'loss': {
            'installed': mtr_path not in ('', 'none') and ping_path not in ('', 'none'),
            'mtr': '' if mtr_path in ('', 'none') else mtr_path,
        },
    }


def parse_speedtest(text):
    """Parse ``speedtest -f json``; raises ValueError on anything else."""
    raw = (text or '').strip()
    start, end = raw.find('{'), raw.rfind('}')
    if start < 0 or end <= start:
        raise ValueError('invalid_json')
    try:
        payload = json.loads(raw[start:end + 1])
        download = payload['download']['bandwidth']
        upload = payload['upload']['bandwidth']
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError('invalid_json') from exc
    ping = payload.get('ping') or {}
    server = payload.get('server') or {}
    location = ', '.join(part for part in (server.get('location'), server.get('name')) if part)
    return {
        'download_mbps': round(float(download) * 8 / 1e6, 1),
        'upload_mbps': round(float(upload) * 8 / 1e6, 1),
        'ping_ms': round(float(ping.get('latency') or 0), 1),
        'jitter_ms': round(float(ping.get('jitter') or 0), 1),
        'isp': str(payload.get('isp') or ''),
        'server': location,
        'url': str((payload.get('result') or {}).get('url') or ''),
        'at': int(time.time()),
    }


def _server_record(state, server_uid):
    servers = state.setdefault('servers', {})
    record = servers.setdefault(str(server_uid), {})
    record.setdefault('apps', {})
    record.setdefault('targets', list(DEFAULT_TARGETS))
    record.setdefault('loss', {})
    return record


def state_view(record):
    """Public (JSON-safe) view of one server record."""
    record = record or {}
    targets = record.get('targets')
    if not isinstance(targets, list):
        targets = list(DEFAULT_TARGETS)
    return {
        'targets': targets,
        'apps': record.get('apps') or {},
        'speedtest': record.get('speedtest'),
        'loss': record.get('loss') or {},
    }


class DiagnosticsStore:
    """Atomic JSON store, same single-writer discipline as warp state."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()

    def load(self):
        with self._lock:
            try:
                with open(self.path, 'r', encoding='utf-8') as handle:
                    raw = json.load(handle)
            except (OSError, ValueError):
                return {'version': STATE_VERSION, 'servers': {}}
            if not isinstance(raw, dict) or raw.get('version') != STATE_VERSION:
                return {'version': STATE_VERSION, 'servers': {}}
            raw.setdefault('servers', {})
            return raw

    def save(self, state):
        directory = os.path.dirname(os.path.abspath(self.path))
        with self._lock:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=os.path.basename(self.path) + '.', suffix='.tmp',
                dir=directory)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    json.dump(state, handle, ensure_ascii=False, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def read(self, server_uid):
        with self._lock:
            return state_view((self.load().get('servers') or {}).get(str(server_uid)))

    def update(self, server_uid, mutate):
        """Load, mutate the server record in place, save atomically."""
        with self._lock:
            state = self.load()
            record = _server_record(state, server_uid)
            result = mutate(record)
            state['updated_at'] = int(time.time())
            self.save(state)
            return result

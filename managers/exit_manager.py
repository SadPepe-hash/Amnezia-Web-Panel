"""Exit node: an AmneziaWG transit endpoint whose peers are other panel servers.

An entry node routes its clients through the exit and SNATs them into its own
transit address, so the exit sees exactly one /32 per entry, NATs the transit
subnet to the internet and never carries end-user peers. The container is the
same image and start script as an AWG server (see AWGManager builders) with its
own paths, one fixed instance and a peers table instead of a clients table.
"""

import ipaddress
import logging
import re
import time
from datetime import datetime

from managers.awg_manager import (
    AWG_QUICK_FORCE_USERSPACE_PATCH,
    TRANSIT_PARAM_KEYS,
    AWGManager,
    generate_awg_params,
    generate_psk,
    _IP_RULE_HELPERS,
    IPV4_RE,
)
import warp_service as warp_logic

logger = logging.getLogger(__name__)

EXIT_DEFAULTS = {
    'port': '55520',
    'subnet': '10.9.0.0/24',
    'mtu': '1420',
}


class ExitManager(AWGManager):
    """Install and manage the `amnezia-exit` transit container."""

    PROTOCOL = 'exit'
    CONTAINER_NAME = 'amnezia-exit'
    DOCKER_IMAGE = 'amneziavpn/amneziawg-go:latest'
    CONFIG_DIR = '/opt/amnezia/exit'
    CONFIG_PATH = '/opt/amnezia/exit/transit0.conf'
    INTERFACE = 'transit0'
    PEERS_TABLE = '/opt/amnezia/exit/peersTable'
    PRIVATE_KEY_PATH = '/opt/amnezia/exit/wireguard_server_private_key.key'
    PUBLIC_KEY_PATH = '/opt/amnezia/exit/wireguard_server_public_key.key'

    def __init__(self, ssh, protocol='exit'):
        super().__init__(ssh)
        self.protocol = self.PROTOCOL
        # telegram_bot falls back to these attributes for docker inspect
        self.container_name = self.CONTAINER_NAME

    # ----- single fixed instance: every AWGManager lookup resolves here -----

    def _base_protocol(self, protocol_type=None):
        return self.PROTOCOL

    def _instance_index(self, protocol_type=None):
        return 1

    def _container_name(self, protocol_type=None):
        return self.CONTAINER_NAME

    def _config_path(self, protocol_type=None):
        return self.CONFIG_PATH

    def _config_path_candidates(self, protocol_type=None):
        return [self.CONFIG_PATH]

    def _resolve_config_path(self, protocol_type=None):
        # One fixed location, nothing to probe over SSH.
        return self.CONFIG_PATH

    def _interface_name(self, protocol_type=None, config_path=None):
        return self.INTERFACE

    def _docker_image(self, protocol_type=None):
        return self.DOCKER_IMAGE

    def _wg_binary(self, protocol_type=None):
        return 'awg'

    def _quick_binary(self, protocol_type=None):
        return 'awg-quick'

    def _userspace_guard(self, protocol_type=None):
        # The transit config carries no AWG 3.1 keys, so an old kernel module
        # accepts it; a missing module is caught by awg-quick's own fallback.
        return ''

    def _clients_table_path(self):
        return self.PEERS_TABLE

    def _bwlimits_path(self):
        return f'{self.CONFIG_DIR}/bwlimits'

    def _apply_bw_limits(self, protocol_type, clients_table):
        # No per-peer shaping on the transit link.
        return None

    def _get_server_public_key(self, protocol_type=None):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.PUBLIC_KEY_PATH}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get exit public key: {err}")
        return out.strip()

    def _get_server_psk(self, protocol_type=None):
        raise RuntimeError('Exit node uses a per-peer preshared key')

    # ----- no end users on an exit node: every client path is closed -----

    def _no_clients(self, *args, **kwargs):
        raise RuntimeError('Exit node has no clients; manage its peers instead')

    add_client = _no_clients
    get_client_config = _no_clients
    toggle_client = _no_clients
    rename_client = _no_clients
    save_client_config = _no_clients
    set_speed_limit = _no_clients

    # ===================== INSTALLATION =====================

    @staticmethod
    def _subnet_gateway(net):
        """Address line of the exit itself: first host of the transit subnet."""
        return f"{net.network_address + 1}/{net.prefixlen}"

    def _render_start_script(self, protocol_type=None, config_path=None,
                             warp_ctx=None):
        net = ipaddress.ip_network(EXIT_DEFAULTS['subnet'])
        pre_blocks = ()
        extra_blocks = (self._mss_clamp_body(self.INTERFACE),)
        if warp_ctx and warp_ctx.get('active'):
            functions = self._warp_shell_functions(
                warp_ctx,
                'awg-quick',
                'awg',
                '$SUBNET',
                '$IFACE',
                '$SUBNET6',
                pref_c2c=warp_logic.WARP_PREF_B_TRANSIT,
                transit_cidr=warp_ctx.get('transit_cidr') or '',
                marker='/opt/amnezia/exit/warp-link',
                include_helpers=True,
                userspace='amneziawg-go' in self._docker_image(protocol_type),
            )
            pre_blocks = (functions + 'x_warp_killswitch_on\n',)
            extra_blocks = (
                self._mss_clamp_body(self.INTERFACE),
                '# ---- WARP egress: bring it up now that the transit link exists ----\n'
                'x_warp_up || echo "! warp link not applied, transit stays on the kill-switch"\n',
            )
        return self._start_script_body(
            self.CONFIG_PATH,
            'awg-quick',
            '',
            self._subnet_gateway(net),
            self._bwlimits_path(),
            pre_blocks=pre_blocks,
            extra_blocks=extra_blocks,
        )

    def _transit_config(self, port, net, awg_params):
        """transit0.conf. Panel metadata lives inside [Interface] as comments
        (remove_client() splits the file on `[` and would drop anything before
        the first section)."""
        obfuscation_lines = ''.join(
            f"{config_key} = {awg_params[param_key]}\n"
            for param_key, config_key in TRANSIT_PARAM_KEYS
            if awg_params and awg_params.get(param_key)
        )
        return (
            "[Interface]\n"
            "# Managed by Amnezia Web Panel - exit node transit endpoint\n"
            f"# Subnet = {net}\n"
            f"# Obfuscation = {'on' if awg_params else 'off'}\n"
            "PrivateKey = $(cat wireguard_server_private_key.key)\n"
            f"Address = {self._subnet_gateway(net)}\n"
            f"ListenPort = {port}\n"
            f"MTU = {EXIT_DEFAULTS['mtu']}\n"
            f"{obfuscation_lines}"
        )

    def _configure_exit_container(self, port, net, awg_params):
        """Generate the key pair (kept if present) and write transit0.conf.

        The file is rewritten from scratch, but the [Peer] sections are carried
        over: they only exist in this file (the panel's peersTable has no PSKs),
        so dropping them would silently break every exit link on the next
        reinstall or settings change.

        The script body is embedded in ``bash -c '...'``, so it must not contain
        a single quote: only double quotes are safe in here.
        """
        script = f"""
set -e
mkdir -p {self.CONFIG_DIR} && cd {self.CONFIG_DIR} && umask 077
[ -s wireguard_server_private_key.key ] || awg genkey > wireguard_server_private_key.key
awg pubkey < wireguard_server_private_key.key > wireguard_server_public_key.key
PEERS=""
if [ -f {self.CONFIG_PATH} ]; then
  PEERS=$(awk "/^\\[Peer\\]/{{inside=1}} inside" {self.CONFIG_PATH})
fi
cat > {self.CONFIG_PATH} <<EOF
{self._transit_config(port, net, awg_params)}EOF
if [ -n "$PEERS" ]; then
  printf "%s\\n" "$PEERS" >> {self.CONFIG_PATH}
fi
"""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c '{script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure the transit endpoint: {err}")

    def install_protocol(self, protocol_type='exit', port=None, subnet=None,
                         obfuscation=False, warp_ctx=None, **_ignored):
        """Install the exit-node container.

        `subnet` is the transit subnet shared with the entry nodes (must be an
        IPv4 /24: the peer allocator hands out the last octet); `obfuscation`
        turns the transit link into AmneziaWG with junk/handshake obfuscation,
        otherwise it speaks plain WireGuard.
        """
        port = str(port or EXIT_DEFAULTS['port']).strip()
        try:
            net = ipaddress.ip_network(subnet or EXIT_DEFAULTS['subnet'], strict=False)
        except ValueError:
            return {'status': 'error', 'message': f'Invalid transit subnet: {subnet}'}
        if net.version != 4 or net.prefixlen != 24:
            return {'status': 'error',
                    'message': 'Transit subnet must be an IPv4 /24 (peers get the last octet)'}

        results = []
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        results.append("Preparing host...")
        docker_ipv6 = self.prepare_host(self.PROTOCOL)
        results.append("Host prepared")
        if docker_ipv6 == 'pending':
            results.append(
                "! Docker IPv6 was enabled in /etc/docker/daemon.json, but Docker "
                "was NOT restarted because other containers are running. The transit "
                "stays IPv4-only until you run: systemctl restart docker"
            )
        elif docker_ipv6 == 'restarted':
            results.append("Docker restarted to apply IPv6 config")

        if self.check_protocol_installed(self.PROTOCOL):
            results.append("Removing old container...")
            self.remove_container(self.PROTOCOL)
            results.append("Old container removed")

        results.append("Pulling Docker image...")
        dockerfile_folder = f"/opt/amnezia/{self.CONTAINER_NAME}"
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(
            self._dockerfile_content(self.DOCKER_IMAGE, AWG_QUICK_FORCE_USERSPACE_PATCH),
            f"{dockerfile_folder}/Dockerfile",
        )
        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {self.CONTAINER_NAME} {dockerfile_folder}",
            timeout=300,
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        results.append("Starting container...")
        ipv6_enabled = self._detect_server_ipv6()
        out, err, code = self.ssh.run_sudo_command(
            self._docker_run_cmd(self.CONTAINER_NAME, self.CONTAINER_NAME, port, ipv6_enabled)
        )
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.CONTAINER_NAME}")
        results.append("Waiting for container to start...")
        self._wait_container_running(self.CONTAINER_NAME)
        results.append("Container started")

        awg_params = None
        if obfuscation:
            wanted = {param_key for param_key, _ in TRANSIT_PARAM_KEYS}
            awg_params = {k: v for k, v in generate_awg_params(use_ranges=False).items() if k in wanted}

        try:
            results.append("Configuring transit endpoint...")
            self._configure_exit_container(port, net, awg_params)
            results.append("Transit endpoint configured ("
                           + ("AmneziaWG obfuscation on" if awg_params else "plain WireGuard") + ")")
            results.append("Starting transit service...")
            self._upload_start_script(self.PROTOCOL, warp_ctx=warp_ctx)
            self._verify_interface_up(self.PROTOCOL)
            results.append("Transit service started")
        except RuntimeError:
            # Do not leave a running container with no working interface behind.
            self.remove_container(self.PROTOCOL)
            raise

        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")
        results.append("Applying host network tuning (BBR)...")
        self.setup_host_tuning()
        results.append("Host network tuning applied")

        return {
            'status': 'success',
            'protocol': self.PROTOCOL,
            'port': port,
            'subnet': str(net),
            'public_key': self._get_server_public_key(),
            'obfuscation': bool(awg_params),
            'awg_params': awg_params or {},
            'log': results,
        }

    # ===================== STATUS / INFO =====================

    def get_server_status(self, protocol_type='exit'):
        info = super().get_server_status(self.PROTOCOL)
        if info.get('container_running') and 'error' not in info:
            info['peers_count'] = info.pop('clients_count', 0)
            info['subnet'] = self._read_config_key(self.PROTOCOL, 'Subnet')
            info['obfuscation'] = (self._read_config_key(self.PROTOCOL, 'Obfuscation') or 'off') == 'on'
            try:
                info['public_key'] = self._get_server_public_key()
            except RuntimeError as err:
                info['error'] = str(err)
        info['base_protocol'] = self.PROTOCOL
        info['instance'] = 1
        info['container_name'] = self.CONTAINER_NAME
        return info

    def get_info(self):
        """What an entry node needs to build its side of the link."""
        params = self._get_awg_params_from_config(self.PROTOCOL)
        port = params.pop('port', None)
        return {
            'public_key': self._get_server_public_key(),
            'port': port,
            'subnet': self._read_config_key(self.PROTOCOL, 'Subnet'),
            'obfuscation': (self._read_config_key(self.PROTOCOL, 'Obfuscation') or 'off') == 'on',
            'awg_params': params,
        }

    # ===================== PEERS =====================

    def list_peers(self):
        """Peers from the peers table enriched with live handshake/transfer
        data; blocks present only in transit0.conf are reported as external."""
        table = self._get_clients_table(self.PROTOCOL)
        try:
            live = self._wg_show(self.PROTOCOL)
        except Exception:
            live = {}
        conf_peers = self._parse_peers_from_config(self.PROTOCOL)

        peers = []
        seen = set()
        for entry in table:
            public_key = entry.get('clientId', '')
            user_data = entry.get('userData', {}) or {}
            show = live.get(public_key, {})
            seen.add(public_key)
            peers.append({
                'peer_id': user_data.get('peerId', ''),
                'name': user_data.get('clientName', ''),
                'transit_ip': user_data.get('clientIp', ''),
                'public_key': public_key,
                'created_at': user_data.get('creationDate', ''),
                'latest_handshake': show.get('latestHandshake', ''),
                'rx': show.get('dataReceived', ''),
                'tx': show.get('dataSent', ''),
                'rx_bytes': show.get('dataReceivedBytes', 0),
                'tx_bytes': show.get('dataSentBytes', 0),
                'external': False,
            })
        for public_key, peer in conf_peers.items():
            if public_key in seen:
                continue
            ip = self._extract_ipv4(peer.get('allowedIps', ''))
            show = live.get(public_key, {})
            peers.append({
                'peer_id': '',
                'name': f'External ({ip})' if ip else 'External',
                'transit_ip': ip or '',
                'public_key': public_key,
                'created_at': '',
                'latest_handshake': show.get('latestHandshake', ''),
                'rx': show.get('dataReceived', ''),
                'tx': show.get('dataSent', ''),
                'rx_bytes': show.get('dataReceivedBytes', 0),
                'tx_bytes': show.get('dataSentBytes', 0),
                'external': True,
            })
        return peers

    def _find_peer(self, peer_id):
        for entry in self._get_clients_table(self.PROTOCOL):
            if (entry.get('userData') or {}).get('peerId') == peer_id:
                return entry
        return None

    def peer_status(self, peer_id, now=None):
        """Handshake age / counters of one transit peer, addressed by its
        panel-side peer id (the chain poll uses `<uid>:chain<index>`)."""
        result = {'up': False, 'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0}
        entry = self._find_peer(peer_id)
        if not entry:
            result['error'] = 'peer_not_found'
            return result
        public_key = entry.get('clientId', '')
        try:
            out, _err, code = self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} sh -c 'awg show {self.INTERFACE} latest-handshakes; "
                f"echo ---; awg show {self.INTERFACE} transfer; echo ---; "
                f"awg show {self.INTERFACE} endpoints'"
            )
            if code == 0 and out.strip():
                peers = self._parse_wg_peer_lists(out)
                peer = peers.get(public_key)
                if peer:
                    handshake = peer.get('latest_handshake') or 0
                    result.update({
                        'up': True,
                        'rx_bytes': peer.get('rx_bytes') or 0,
                        'tx_bytes': peer.get('tx_bytes') or 0,
                        'handshake_age': (None if not handshake
                                          else max(0, int((now or time.time()) - handshake))),
                    })
        except Exception as err:  # SSH failure is a fact, not a crash
            result['error'] = str(err)
        return result

    def add_peer(self, peer_id, name, public_key):
        """Register (or re-register) an entry node as a peer.

        Upsert by `peer_id`: an existing peer keeps its transit address and is
        rewritten with the new key. Returns what the entry side needs for its
        exit0.conf - the transit address, a fresh per-peer PSK and the exit's
        own endpoint data.
        """
        peer_id = (peer_id or '').strip()
        public_key = (public_key or '').strip()
        if not peer_id or not public_key:
            raise ValueError('peer_id and public_key are required')

        keep_ip = None
        existing = self._find_peer(peer_id)
        if existing:
            keep_ip = (existing.get('userData') or {}).get('clientIp')
            self.remove_client(self.PROTOCOL, existing.get('clientId', ''))
        if public_key in self._parse_peers_from_config(self.PROTOCOL):
            # Same key already present under another (or no) peer id.
            self.remove_client(self.PROTOCOL, public_key)

        transit_ip = keep_ip or self._get_next_ip(self.PROTOCOL)
        psk = generate_psk()
        peer_section = (
            f"\n[Peer]\n"
            f"# peerId = {peer_id}\n"
            f"PublicKey = {public_key}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {transit_ip}/32\n"
        )
        self._insert_peer_sorted(self.PROTOCOL, peer_section)
        self._sync_server_config(self.PROTOCOL)
        try:
            table = self._get_clients_table(self.PROTOCOL)
            table.append({
                'clientId': public_key,
                'userData': {
                    'clientName': name or peer_id,
                    'peerId': peer_id,
                    'clientIp': transit_ip,
                    'creationDate': datetime.now().isoformat(),
                    'enabled': True,
                },
            })
            self._save_clients_table(self.PROTOCOL, table)
        except Exception:
            self.remove_client(self.PROTOCOL, public_key)
            raise

        info = self.get_info()
        info.update({'transit_ip': transit_ip, 'psk': psk})
        return info

    def remove_peer(self, public_key=None, peer_id=None):
        """Drop a peer by key or by peer id; True when something was removed."""
        if not public_key and peer_id:
            existing = self._find_peer(peer_id)
            public_key = existing.get('clientId', '') if existing else ''
        if not public_key:
            return False
        known = public_key in self._parse_peers_from_config(self.PROTOCOL) or any(
            e.get('clientId') == public_key for e in self._get_clients_table(self.PROTOCOL)
        )
        if not known:
            return False
        self.remove_client(self.PROTOCOL, public_key)
        return True

    # ===================== CHAIN RELAY (transit in, tunnel out) =====================
    #
    # A hop that is neither the first nor the last node of a chain plays two
    # roles inside the SAME amnezia-exit container: transit0 keeps accepting
    # the peer of the previous node, and exit<i> is its own link towards the
    # next hop. Both subnets, the policy-routing table and the NAT are per
    # (chain, hop) so several chains may share one relay host.
    #
    # Naming: the panel assigns every chain a short prefix and stores the
    # computed interface/table in the hop record, so start.sh can rebuild the
    # exact same wiring after a container restart.

    RELAY_DIR = '/opt/amnezia/exit/relay'
    RELAY_TABLE_BASE = 210
    RELAY_TABLE_RANGE = 500
    RELAY_PREF_BASE = 3000
    RELAY_PREF_RANGE = 500
    RELAY_IFACE_RE = re.compile(r'^c[0-9a-f]{4}[0-9]{1,3}$')
    RELAY_BLOCK_START = '# >>> exit-chain-relays >>>'
    RELAY_BLOCK_END = '# <<< exit-chain-relays <<<'

    @staticmethod
    def _validate_relay(relay):
        """Relay wiring is panel-generated, but data.json can be restored or
        hand-edited: refuse anything that is not a plain iface/table/src/mtu
        before it reaches a root shell inside the container."""
        iface = relay.get('iface')
        table = relay.get('table')
        source_ip = relay.get('source_ip')
        mtu = relay.get('mtu', 1420)
        if not isinstance(iface, str) or not ExitManager.RELAY_IFACE_RE.match(iface):
            raise ValueError(f'invalid relay interface: {iface!r}')
        if not isinstance(table, int) or isinstance(table, bool) \
                or not (200 < table < 1000):
            raise ValueError(f'invalid relay routing table: {table!r}')
        if not isinstance(source_ip, str) or not IPV4_RE.match(source_ip):
            raise ValueError(f'invalid relay source address: {source_ip!r}')
        if not isinstance(mtu, int) or isinstance(mtu, bool) \
                or not (1280 <= mtu <= 1420):
            raise ValueError(f'invalid relay MTU: {mtu!r}')
        pref = relay.get('rule_pref')
        if pref is not None and (not isinstance(pref, int) or isinstance(pref, bool)
                                 or not (3000 <= pref < 4000)):
            raise ValueError(f'invalid relay rule preference: {pref!r}')
        prefix = relay.get('prefix')
        if prefix is not None and (not isinstance(prefix, str)
                                   or not re.match(r'^[0-9a-f]{4}$', prefix)):
            raise ValueError(f'invalid relay chain prefix: {prefix!r}')

    @staticmethod
    def relay_conf_path(relay):
        return f'/opt/amnezia/exit/relay/{relay["iface"]}.conf'

    @staticmethod
    def relay_key_path(relay):
        return f'/opt/amnezia/exit/relay/{relay["iface"]}_private.key'

    @classmethod
    def relay_table_for(cls, prefix, index, taken=()):
        """Deterministic table per (chain prefix, hop index), bumped on clash."""
        import zlib
        base = cls.RELAY_TABLE_BASE + (
            zlib.crc32(f'{prefix}:{index}'.encode('utf-8')) % cls.RELAY_TABLE_RANGE)
        table = base
        while table in (taken or ()):
            table += 1
        return table

    @classmethod
    def relay_pref_for(cls, prefix, index, taken=()):
        """Deterministic ip-rule preference per (chain prefix, hop index).

        A shared preference would make the second chain on a relay host a no-op
        and let one teardown delete another chain's rule, so every relay owns
        its own slot (verified in x_relay_up)."""
        import zlib
        base = cls.RELAY_PREF_BASE + (
            zlib.crc32(f'{prefix}:{index}'.encode('utf-8')) % cls.RELAY_PREF_RANGE)
        pref = base
        while pref in (taken or ()):
            pref += 1
        return pref

    @staticmethod
    def relay_iface_for(prefix, index):
        return f'c{prefix}{index}'

    def _relay_shell_functions(self, relay):
        """Shell functions for one relay uplink (no side effects alone)."""
        self._validate_relay(relay)
        iface = relay['iface']
        table = relay['table']
        pref = relay.get('rule_pref')
        if pref is None:
            # legacy record without rule_pref: derive it from the iface so the
            # check stays meaningful instead of hashing the wrong inputs
            match = re.match(r'^c([0-9a-f]{4})([0-9]{1,3})$', str(iface))
            if match:
                pref = self.relay_pref_for(match.group(1), int(match.group(2)))
        return (
            f"R_IF={iface}\n"
            f"R_CONF=/opt/amnezia/exit/relay/{iface}.conf\n"
            f"R_KEY=/opt/amnezia/exit/relay/{iface}_private.key\n"
            f"R_TABLE={table}\n"
            f"R_PREF={pref}\n"
            f"R_SRC={relay['source_ip']}\n"          # /32 of the previous hop on transit0
            f"R_MTU={relay.get('mtu', 1420)}\n"
            "X_QUICK=awg-quick\n"                     # same binary inside the exit container
            "x_ipt_ins() { table=\"$1\"; chain=\"$2\"; pos=\"$3\"; shift 3; iptables -t \"$table\" -C \"$chain\" \"$@\" 2>/dev/null || iptables -t \"$table\" -I \"$chain\" \"$pos\" \"$@\"; }\n"
            f"{_IP_RULE_HELPERS}"
            "x_relay_up() {\n"
            # Fail-closed BEFORE the uplink exists: the policy rule and the
            # blackhole must be in place first (otherwise the previous hop's
            # traffic keeps using the main table and leaves via eth0), and the
            # eth0 guard must be INSERTED, not appended: start.sh already has
            # an ACCEPT for the transit subnet, and iptables is first-match.
            "  ip -4 route replace blackhole default metric 0 table $R_TABLE\n"
            "  x_rule -4 $R_PREF from $R_SRC lookup $R_TABLE\n"
            "  x_ipt_ins filter FORWARD 1 -i transit0 -o eth0 -s $R_SRC -j DROP\n"
            "  $X_QUICK down $R_CONF 2>/dev/null\n"
            "  $X_QUICK up $R_CONF || { echo \"! $R_IF failed to start; chain hop stays cut\"; return 3; }\n"
            "  sysctl -w net.ipv4.conf.$R_IF.rp_filter=2 >/dev/null 2>&1 || true\n"
            # the real default replaces the blackhole (same key, one route only)
            "  ip -4 route replace default dev $R_IF table $R_TABLE\n"
            "  x_ipt_add filter FORWARD -i transit0 -o $R_IF -s $R_SRC -j ACCEPT\n"
            "  x_ipt_add nat POSTROUTING -s $R_SRC -o $R_IF -j MASQUERADE\n"
            "  x_ipt_add mangle FORWARD -o $R_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n"
            "  if ! ip -4 route show table $R_TABLE | grep -q \"^default dev $R_IF\" || ! iptables -t nat -C POSTROUTING -s $R_SRC -o $R_IF -j MASQUERADE 2>/dev/null; then\n"
            "    echo \"! FATAL: relay routing for $R_IF is not in place\"; return 3; fi\n"
            "  if ! ip -4 rule show | grep -Eq \"^$R_PREF:[[:space:]]+from $R_SRC lookup $R_TABLE\"; then\n"
            "    echo \"! FATAL: policy rule for $R_SRC is not in place\"; return 3; fi\n"
            # verified: the eth0 guard is not needed any more
            "  x_ipt_del filter FORWARD -i transit0 -o eth0 -s $R_SRC -j DROP\n"
            "  if command -v conntrack >/dev/null 2>&1; then conntrack -D -s $R_SRC >/dev/null 2>&1; fi\n"
            "  echo \"relay up: $R_SRC via $R_IF -> table $R_TABLE pref $R_PREF\"\n"
            "}\n"
            "x_relay_down() {\n"
            # cut first, then clean up: the rule goes before the device, so the
            # relayed source can never fall through to the main table (eth0)
            "  x_unrule -4 $R_PREF\n"
            "  ip -4 route replace blackhole default metric 0 table $R_TABLE 2>/dev/null\n"
            "  [ -f \"$R_CONF\" ] && $X_QUICK down $R_CONF 2>/dev/null; ip link del $R_IF 2>/dev/null\n"
            "  ip -4 route flush table $R_TABLE 2>/dev/null\n"
            "  x_ipt_del filter FORWARD -i transit0 -o eth0 -s $R_SRC -j DROP\n"
            "  x_ipt_del filter FORWARD -i transit0 -o $R_IF -s $R_SRC -j ACCEPT\n"
            "  x_ipt_del nat POSTROUTING -s $R_SRC -o $R_IF -j MASQUERADE\n"
            "  x_ipt_del mangle FORWARD -o $R_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n"
            "}\n"
        )

    def relay_prepare_keys(self, relay):
        """Key pair of the relay's own uplink, kept inside the container."""
        self._validate_relay(relay)
        iface = relay['iface']
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'umask 077; mkdir -p /opt/amnezia/exit/relay; "
            f"[ -s /opt/amnezia/exit/relay/{iface}_private.key ] || awg genkey > /opt/amnezia/exit/relay/{iface}_private.key; "
            f"awg pubkey < /opt/amnezia/exit/relay/{iface}_private.key'"
        )
        if code != 0 or not out.strip():
            raise RuntimeError(f"Failed to prepare the relay key: {err or out}")
        return out.strip()

    def relay_write_conf(self, relay, link):
        """Write exit<i>.conf of the relay; the private key never leaves the box."""
        self._validate_relay(relay)
        iface = relay['iface']
        lines = [
            '[Interface]',
            '# Managed by Amnezia Web Panel - exit chain relay',
            'PrivateKey = __RELAY_KEY__',
            f"Address = {link['transit_ip']}/{link.get('subnet_cidr', 24)}",
            f"MTU = {relay.get('mtu', 1420)}",
            'Table = off',
            '',
            '[Peer]',
            f"PublicKey = {link['exit_public_key']}",
            f"PresharedKey = {link['psk']}",
            'AllowedIPs = 0.0.0.0/0',
            f"Endpoint = {link['endpoint_host']}:{link['endpoint_port']}",
            'PersistentKeepalive = 25',
        ]
        body = '\n'.join(lines) + '\n'
        local = f"/tmp/_amnz_{iface}.conf"
        self.ssh.upload_file(body, local)
        # The container keeps its own relay registry (KEY=VALUE per uplink), so
        # any later re-render of start.sh can rebuild the relay blocks without
        # the panel - and so several chains sharing this host do not overwrite
        # each other's startup wiring.
        params = '\n'.join([
            f"R_IF={iface}",
            f"R_TABLE={relay['table']}",
            f"R_PREF={relay.get('rule_pref') or ''}",
            f"R_SRC={relay['source_ip']}",
            f"R_MTU={relay.get('mtu', 1420)}",
        ]) + '\n'
        params_local = f"/tmp/_amnz_{iface}.params"
        self.ssh.upload_file(params, params_local)
        steps = (
            f"docker exec -i {self.CONTAINER_NAME} mkdir -p /opt/amnezia/exit/relay",
            f"docker cp {local} {self.CONTAINER_NAME}:/opt/amnezia/exit/relay/{iface}.conf",
            f"docker cp {params_local} {self.CONTAINER_NAME}:/opt/amnezia/exit/relay/{iface}.params",
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'k=$(cat /opt/amnezia/exit/relay/{iface}_private.key) && "
            f"sed -i \"s|__RELAY_KEY__|$k|\" /opt/amnezia/exit/relay/{iface}.conf && chmod 600 /opt/amnezia/exit/relay/{iface}.conf'",
        )
        try:
            for step in steps:
                out, err, code = self.ssh.run_sudo_command(step)
                if code != 0:
                    raise RuntimeError(f"Failed to write {iface}.conf: {err or out}")
        finally:
            self.ssh.run_command(f"rm -f {local}")
            self.ssh.run_command(f"rm -f {params_local}")

    def relay_apply(self, relay, teardown=False):
        """Apply the relay uplink live inside the container."""
        self._validate_relay(relay)
        iface = relay['iface']
        functions = self._relay_shell_functions(relay)
        action = 'x_relay_down\n' if teardown else 'x_relay_up\n'
        self.ssh.upload_file(functions + action, f"/tmp/_amnz_{iface}.sh")
        out, err, code = self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_{iface}.sh {self.CONTAINER_NAME}:/tmp/_amnz_{iface}.sh")
        if code != 0:
            self.ssh.run_command(f"rm -f /tmp/_amnz_{iface}.sh")
            raise RuntimeError(f"relay apply failed: {err or out}")
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {self.CONTAINER_NAME} bash /tmp/_amnz_{iface}.sh", timeout=60)
        self.ssh.run_command(f"rm -f /tmp/_amnz_{iface}.sh")
        if code != 0:
            raise RuntimeError(f"relay apply failed: {out or err or f'SSH exit code {code}'}")
        return out

    def relay_teardown(self, relay):
        """Take the uplink down and drop every file it owns (conf, params and
        the private key: a removed chain must not leave key material behind)."""
        self._validate_relay(relay)
        iface = relay['iface']
        try:
            self.relay_apply(relay, teardown=True)
        finally:
            self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} rm -f "
                f"/opt/amnezia/exit/relay/{iface}.conf /opt/amnezia/exit/relay/{iface}.params "
                f"/opt/amnezia/exit/relay/{iface}_private.key")
        return True

    def relay_status(self, relay, now=None):
        """Handshake age and counters of one relay uplink (no exceptions)."""
        try:
            self._validate_relay(relay)
        except ValueError as err:
            return {'iface': relay.get('iface'), 'up': False, 'handshake_age': None,
                    'rx_bytes': 0, 'tx_bytes': 0, 'error': str(err)}
        iface = relay['iface']
        result = {'iface': iface, 'up': False, 'handshake_age': None,
                  'rx_bytes': 0, 'tx_bytes': 0, 'error': None}
        try:
            out, _err, code = self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} sh -c 'awg show {iface} latest-handshakes; "
                f"echo ---; awg show {iface} transfer; echo ---; awg show {iface} endpoints'"
            )
            if code == 0 and out.strip():
                peers = self._parse_wg_peer_lists(out)
                if peers:
                    peer = next(iter(peers.values()))
                    result.update({
                        'rx_bytes': peer.get('rx_bytes') or 0,
                        'tx_bytes': peer.get('tx_bytes') or 0,
                        'endpoint': peer.get('endpoint') or '',
                    })
                    handshake = peer.get('latest_handshake') or 0
                    result['handshake_age'] = (
                        None if not handshake else max(0, int((now or time.time()) - handshake)))
            # "up" means the policy rule AND the uplink default are both in
            # place: a route alone is the false positive the chain poll must not
            # trust (the previous hop could be using the main table).
            rule, _err, _code = self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} ip -4 rule show 2>/dev/null")
            route, _err, _code = self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} ip -4 route show table {relay['table']} 2>/dev/null")
            pref = relay.get('rule_pref')
            result['route_ok'] = f"default dev {iface}" in (route or '')
            result['rule_ok'] = False
            if pref is not None:
                # iproute2 prints "pref:\tfrom ... lookup ...": match any whitespace
                for line in (rule or '').splitlines():
                    parts = line.replace(':', ' ').split()
                    if len(parts) >= 5 and parts[0] == str(pref) \
                            and parts[1] == 'from' and parts[2] == relay['source_ip'] \
                            and parts[3] == 'lookup' and parts[4] == str(relay['table']):
                        result['rule_ok'] = True
                        break
            result['up'] = bool(result.get('route_ok')) and bool(result.get('rule_ok'))
        except Exception as err:  # a dead relay is a fact, not a crash
            result['error'] = str(err)
        return result

    def relay_read_registry(self):
        """All relay uplinks this container knows about (from its own registry).

        The container is the source of truth, so a chain that shares this host
        with another chain never loses the other chain's startup block."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} sh -c "
            f"'for f in /opt/amnezia/exit/relay/*.params; do [ -e \"$f\" ] || continue; "
            f"echo \"### $f\"; cat \"$f\"; done'"
        )
        relays = []
        if code != 0:
            # unreadable is not the same as empty: the caller must keep the
            # existing start.sh instead of erasing every relay block
            return None
        current = {}
        for line in (out or '').splitlines():
            line = line.strip()
            if line.startswith('### '):
                if current:
                    relays.append(current)
                current = {}
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                current[key.strip()] = value.strip()
        if current:
            relays.append(current)
        cleaned = []
        for item in relays:
            try:
                relay = {
                    'iface': item['R_IF'],
                    'table': int(item['R_TABLE']),
                    'source_ip': item['R_SRC'],
                    'mtu': int(item.get('R_MTU') or 1420),
                }
                if item.get('R_PREF'):
                    relay['rule_pref'] = int(item['R_PREF'])
                self._validate_relay(relay)
            except (KeyError, TypeError, ValueError):
                logger.warning("skipping an unreadable relay registry entry: %s", item)
                continue
            cleaned.append(relay)
        return cleaned

    def relay_write_startup(self, relays=None):
        """Splice the relay blocks into start.sh so every uplink of this
        container comes back after a restart.

        The block set is the UNION of the container registry (what the container
        knows about) and the relays the panel passes explicitly - a chain built
        before the registry existed therefore still gets its block, and chains
        that share this host never lose each other's wiring. The block is
        spliced between markers (never re-rendered), so a WARP egress block or
        any other local content survives. When the registry cannot be read and
        the panel passed nothing, the existing start.sh is left untouched."""
        registry = self.relay_read_registry()
        known = {}
        if registry is None:
            if not relays:
                logger.warning("relay registry unreadable and no panel relays given: "
                               "keeping the existing start.sh")
                return []
            registry = []
        known = {relay['iface']: dict(relay) for relay in registry}
        for relay in relays or []:
            self._validate_relay(relay)
            known.setdefault(relay['iface'], dict(relay))
        merged = list(known.values())
        blocks = []
        for relay in merged:
            iface = relay['iface']
            conf = f'/opt/amnezia/exit/relay/{iface}.conf'
            blocks.append(
                f'# ---- exit chain relay {iface} (panel-managed) ----\n'
                f'if [ -f {conf} ]; then\n'
                + self._relay_shell_functions(relay)
                + f'  x_relay_up || echo "! chain relay {iface} not applied; hop stays cut"\n'
                + 'fi\n')
        block = (f'{self.RELAY_BLOCK_START}\n' + ''.join(blocks)
                 + f'{self.RELAY_BLOCK_END}\n')
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat /opt/amnezia/start.sh")
        if code != 0:
            raise RuntimeError(f'Failed to read start.sh: {err or out}')
        body = re.sub(re.escape(self.RELAY_BLOCK_START) + r'.*?' +
                      re.escape(self.RELAY_BLOCK_END) + r'\n?',
                      '', out or '', flags=re.S)
        if blocks:
            if 'tail -f /dev/null' in body:
                body = body.replace('tail -f /dev/null', block + '\ntail -f /dev/null', 1)
            else:
                body = body.rstrip('\n') + '\n' + block
        self.ssh.upload_file(body, '/tmp/_amnz_relay_start.sh')
        try:
            for step in (f'docker cp /tmp/_amnz_relay_start.sh {self.CONTAINER_NAME}:/opt/amnezia/start.sh',
                         f'docker exec -i {self.CONTAINER_NAME} chmod +x /opt/amnezia/start.sh'):
                out, err, code = self.ssh.run_sudo_command(step)
                if code != 0:
                    raise RuntimeError(f'Failed to write start.sh: {err or out}')
        finally:
            self.ssh.run_command('rm -f /tmp/_amnz_relay_start.sh')
        return [relay['iface'] for relay in merged]

    def _write_start_script(self, protocol_type=None, config_path=None,
                            warp_ctx=None):
        """Any re-render of the exit start.sh must keep the relay blocks."""
        super()._write_start_script(protocol_type, config_path, warp_ctx=warp_ctx)
        try:
            self.relay_write_startup()
        except Exception as err:
            logger.warning("relay startup not re-spliced after a start.sh re-render: %s", err)

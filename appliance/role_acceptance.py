"""Actual independent-endpoint measurements within a pre-owned Linux test namespace.

These primitives do not certify a whole role by themselves. In particular,
unknown-node admission and verifier-outage admission need a DERP wire test
client and a controlled guest fault channel; until those exist their gates
remain NOT RUN. Namespace ownership is checked before any test disruption.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import struct
import tempfile
import time

from .contracts import ApplianceError, canonical, identity, require
from . import state
from .connector import connector_config, validate_authorization
from .guest.connector import verify_controller
from .probes import REQUIREMENTS, sign_receipt, validate_request
from . import probe_agent


STUN_COOKIE = 0x2112A442


def stun_response(raw, transaction_id):
    """Parse RFC 8489 IPv4 XOR-MAPPED-ADDRESS with strict transaction binding."""
    require(type(raw) is bytes and 20 <= len(raw) <= 2048 and len(transaction_id) == 12, 'stun-response-invalid')
    kind, length, cookie = struct.unpack('!HHI', raw[:8])
    require(kind == 0x0101 and cookie == STUN_COOKIE and raw[8:20] == transaction_id and
            length % 4 == 0 and len(raw) == length + 20, 'stun-response-binding')
    address = None
    offset = 20
    while offset < len(raw):
        require(offset + 4 <= len(raw), 'stun-attribute-invalid')
        kind, size = struct.unpack('!HH', raw[offset:offset + 4])
        offset += 4
        require(offset + size <= len(raw), 'stun-attribute-invalid')
        value = raw[offset:offset + size]
        offset += (size + 3) & ~3
        if kind == 0x0020:
            require(address is None and size == 8 and value[:2] == b'\0\1', 'stun-address-invalid')
            port = struct.unpack('!H', value[2:4])[0] ^ (STUN_COOKIE >> 16)
            address = str(ipaddress.IPv4Address(struct.unpack('!I', value[4:8])[0] ^ STUN_COOKIE))
            require(port > 0, 'stun-address-invalid')
    require(offset == len(raw) and address is not None, 'stun-address-missing')
    return {'public_ipv4': address, 'port': port}


def stun_probe(address, *, expected_source):
    ipaddress.IPv4Address(address)
    ipaddress.IPv4Address(expected_source)
    transaction = secrets.token_bytes(12)
    wire = struct.pack('!HHI', 0x0001, 0, STUN_COOKIE) + transaction
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((address, 3478))
        sock.send(wire)
        answer = stun_response(sock.recv(2049), transaction)
    return {'stun_response': True, 'observed_client_ipv4': answer['public_ipv4'],
            'source_preserved': answer['public_ipv4'] == expected_source}


def namespace_profile(profile):
    require(type(profile) is dict, 'role-lab-profile')
    require(platform.system() == 'Linux' and os.geteuid() == 0 and hasattr(os, 'setns'),
            'role-lab-linux-root-required')
    name = profile.get('namespace')
    require(type(name) is str and re.fullmatch(r'rdcroles-[0-9a-f]{12}', name), 'role-lab-namespace')
    marker = state.read(Path(profile['ownership_marker']))
    namespace = Path('/run/netns') / name
    require(not namespace.is_symlink(), 'role-lab-namespace')
    info = namespace.stat()
    machine = hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()
    require(marker == {'schema': 1, 'disposable': True, 'namespace': name,
                       'namespace_inode': info.st_ino, 'machine_id': machine}, 'role-lab-not-owned')
    return name


@contextmanager
def network_namespace(name):
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    destination = os.open('/run/netns/' + name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.setns(destination, 0)
        yield
    finally:
        os.setns(original, 0)
        os.close(destination)
        os.close(original)


class NamespaceRunner:
    def __init__(self, runner, namespace, socket_path=None):
        self.runner, self.namespace, self.socket_path = runner, namespace, socket_path
    def run(self, argv, *, stdin=b'', timeout_s=30):
        if argv[0] == '/usr/bin/tailscale' and self.socket_path:
            argv = [argv[0], '--socket=' + str(self.socket_path), *argv[1:]]
        return self.runner.run(['/usr/sbin/ip', 'netns', 'exec', self.namespace, *argv],
                               stdin=stdin, timeout_s=timeout_s)


@contextmanager
def force_relay(profile, runner):
    """Block direct UDP only inside the inspected disposable namespace."""
    namespace = namespace_profile(profile)
    scoped = NamespaceRunner(runner, namespace)
    table = 'rdcprobe_' + secrets.token_hex(8)
    created = False
    try:
        scoped.run(['/usr/sbin/nft', 'add', 'table', 'inet', table])
        created = True
        policy = ('add chain inet ' + table + ' output { type filter hook output priority -10; policy accept; }\n'
                  'add rule inet ' + table + ' output meta l4proto udp udp dport != { 53, 3478 } drop\n')
        scoped.run(['/usr/sbin/nft', '-f', '-'], stdin=policy.encode())
        yield scoped
    finally:
        if created:
            scoped.run(['/usr/sbin/nft', 'delete', 'table', 'inet', table])


def selected_relay(before, after, derp_map, targets, region):
    require(type(region) is int and region > 0, 'probe-region-required')
    mapping = derp_map.get('Regions', {}).get(str(region), {})
    code = mapping.get('RegionCode')
    require(mapping.get('RegionID') == region and type(code) is str, 'probe-relay-map')
    ids = {t['peer_identity'] for t in targets if t['expect'] == 'allowed'}
    def peers(status):
        return {p.get('ID'): p for p in status.get('Peer', {}).values() if type(p) is dict}
    old, new = peers(before), peers(after)
    require(bool(ids), 'probe-targets-required')
    for node in ids:
        first, last = old.get(node, {}), new.get(node, {})
        require(last.get('Relay') == code and last.get('CurAddr') == '' and
                type(first.get('TxBytes')) is int and type(last.get('TxBytes')) is int and
                type(first.get('RxBytes')) is int and type(last.get('RxBytes')) is int and
                last['TxBytes'] > first['TxBytes'] and last['RxBytes'] > first['RxBytes'], 'probe-wrong-relay')
    return {'forced_relay': True, 'selected_region': region}


def collect_relay(request, profile, runner):
    validate_request(request)
    require(request['capability'] == 'relay', 'probe-capability-invalid')
    observed = {k: False for k in REQUIREMENTS['relay']}
    public = [t for t in request['targets'] if t['expect'] == 'public-tls']
    require(len(public) == 1 and 'expected_ipv4' in public[0], 'probe-relay-address-required')
    with fresh_client(profile, runner, request['nonce']) as scoped:
        with force_relay(profile, runner):
            with network_namespace(profile['namespace']):
                direct = probe_agent.collect(request, scoped)
                observed.update(direct)
                before = probe_agent._tail_status(scoped)
                # Run real HTTPS again while direct traffic is blocked; compare the
                # selected peer's byte counters with its actual relay diagnostics.
                flow = probe_agent.collect(request, scoped)
                after = probe_agent._tail_status(scoped)
                derp_map = json.loads(scoped.run(['/usr/bin/tailscale', 'debug', 'derp-map']).stdout)
                if all(flow.get('peer_identities', {}).get(t['id']) == t['peer_identity'] for t in request['targets']):
                    observed.update(selected_relay(before, after, derp_map, request['targets'], request['selected_region']))
                observed.update(stun_probe(public[0]['expected_ipv4'], expected_source=profile['expected_client_ipv4']))
    # STUN's observed client address is one source-preservation direction.
    # Reverse source and new-session admission are not inferred from it.
    observed['positive_control'] = observed.get('forced_relay') is True
    return observed


def preflight(suite, profile=None):
    cases = {'join': ('join-nat', 'relay-path', 'role-identity-restart'),
             'headscale': ('controller-hosting',), 'derp': ('standalone-relay-hosting',),
             'all': ('join-nat', 'relay-path', 'controller-hosting', 'standalone-relay-hosting',
                     'both-hosting-roles', 'role-identity-restart', 'private-role-export', 'full-operator')}
    require(suite in cases, 'role-lab-suite')
    reasons = ['owned-independent-linux-profile-required', 'execution-not-requested']
    if platform.system() != 'Linux':
        reasons.append('linux-test-machine-unavailable')
    if suite in ('derp', 'all'):
        reasons.extend(['derp-new-session-wire-client-not-implemented', 'private-verifier-fault-channel-not-implemented'])
    return {'schema': 1, 'status': 'NOT RUN', 'qualification': 'NOT RUN', 'suite': suite,
            'scope': 'read-only-preflight', 'reasons': reasons,
            'cases': [{'case_id': case, 'status': 'NOT RUN', 'state': 'unknown'} for case in cases[suite]]}


@contextmanager
def fresh_client(profile, runner, nonce):
    """Create a disposable client once; never reuse an uncertain authorization."""
    namespace = namespace_profile(profile)
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{64}', nonce), 'probe-nonce-invalid')
    authorization = state.read(Path(profile['authorization']))
    config = connector_config({'roles': {'connector': {'selected': True,
                                                       'controller': authorization.get('controller')}}})
    validate_authorization(config, authorization)
    require(authorization.get('ephemeral') is True, 'probe-ephemeral-authorization-required')
    with network_namespace(namespace):
        verify_controller(config['controller'], authorization['tls_sha256'])
    # No credential or hash of it is persisted; nonce binds the one permitted
    # attempt. An uncertain response needs inspection, not another key.
    state.begin(Path(profile['state']) / 'enrollment-operations',
                {'nonce': nonce, 'controller': config['controller']})
    unit = 'rdc-probe-' + secrets.token_hex(12) + '.service'
    existing = runner.run(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value']).stdout
    require(existing.strip() == b'not-found', 'probe-service-collision')
    directory = Path(tempfile.mkdtemp(prefix='rdc-role-probe-'))
    run_record = Path(profile['state']) / 'clients' / (nonce + '.json')
    state.write(run_record, {'schema': 1, 'phase': 'pending', 'unit': unit, 'directory': str(directory)})
    try:
        key, socket_path = directory / 'authorization', directory / 'tailscaled.sock'
        key.write_text(authorization['credential'])
        key.chmod(0o600)
        submitted = False
        try:
            submitted = True
            runner.run(['/usr/bin/systemd-run', '--unit=' + unit, '--collect', '--service-type=exec',
                '--property=NetworkNamespacePath=/run/netns/' + namespace,
                '/usr/sbin/tailscaled', '--state=' + str(directory / 'tailscaled.state'),
                '--socket=' + str(socket_path), '--tun=rdcts' + nonce[:8]], timeout_s=30)
            scoped = NamespaceRunner(runner, namespace, socket_path)
            try:
                scoped.run(['/usr/bin/tailscale', 'up', '--login-server=' + config['controller'],
                    '--auth-key=file:' + str(key), '--hostname=' + authorization['node_name'],
                    '--accept-routes=false', '--accept-dns=false', '--advertise-routes=',
                    '--advertise-exit-node=false', '--exit-node=', '--ssh=false', '--advertise-tags=',
                    '--timeout=60s'], timeout_s=75)
            finally:
                key.unlink(missing_ok=True)
            status = probe_agent._tail_status(scoped)
            require(status.get('BackendState') == 'Running' and status.get('Self', {}).get('ID'),
                    'probe-fresh-registration-failed')
            yield scoped
        finally:
            key.unlink(missing_ok=True)
            if submitted:
                runner.run(['/usr/bin/systemctl', 'stop', unit], timeout_s=30)
            state.write(run_record, {'schema': 1, 'phase': 'stopped', 'unit': unit, 'directory': str(directory)})
            shutil.rmtree(directory)
    except BaseException:
        # If stopping fails, preserve private state and the owned unit name for
        # explicit cleanup. Never erase a possibly live enrolled identity.
        raise


def collect_controller(request, profile, runner):
    validate_request(request)
    require(request['capability'] == 'controller', 'probe-capability-invalid')
    from urllib.parse import urlsplit
    public = [t for t in request['targets'] if t['expect'] == 'public-tls']
    require(len(public) == 1, 'probe-controller-target-required')
    authority = state.read(Path(profile['authorization']))
    parsed = urlsplit(public[0]['url'])
    require(authority.get('controller') == 'https://' + parsed.hostname and
            authority.get('tls_sha256') == public[0]['tls_sha256'], 'probe-controller-approval-mismatch')
    with fresh_client(profile, runner, request['nonce']) as scoped:
        before = probe_agent._tail_status(scoped)
        with network_namespace(profile['namespace']):
            observed = probe_agent.collect(request, scoped)
        after = probe_agent._tail_status(scoped)
        first_id, last_id = before.get('Self', {}).get('ID'), after.get('Self', {}).get('ID')
        observed['fresh_registration'] = before.get('BackendState') == after.get('BackendState') == 'Running'
        observed['identity_preserved'] = bool(first_id) and first_id == last_id
    return observed


def run_role_probe(request, private_key, runner, profile):
    validate_request(request)
    now = int(time.time())
    require(request['issued_at'] <= now <= request['expires_at'], 'probe-expired')
    namespace_profile(profile)
    if request['capability'] == 'controller':
        observed = collect_controller(request, profile, runner)
    elif request['capability'] == 'relay':
        observed = collect_relay(request, profile, runner)
    else:
        with fresh_client(profile, runner, request['nonce']) as scoped:
            with network_namespace(profile['namespace']):
                observed = probe_agent.collect(request, scoped)
    return sign_receipt(request, observed, private_key, runner, now=int(time.time()))

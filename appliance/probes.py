"""Independent, registered-key proofs with bounded challenge and receipt records.

Signature trust comes from operator registration, never a key embedded in a
receipt. These records certify only the requested capability and expire after
15 minutes; rendered policy and local success cannot substitute for them.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from urllib.parse import urlsplit

from .contracts import ApplianceError, canonical, identity, require

MAX_BYTES = 512 * 1024
REQUIREMENTS = {
    'enrollment': ('registered', 'identity_preserved', 'peer_control', 'peer_reachable',
                   'denied_control', 'denied_probe'),
    'controller': ('public_tls', 'dns_answer', 'fresh_registration', 'peer_control',
                   'peer_reachable', 'denied_control', 'denied_probe', 'identity_preserved'),
    'relay': ('public_tls', 'stun_response', 'forced_relay', 'source_preserved',
              'return_source_preserved', 'unknown_client_denied', 'verifier_outage_denied', 'positive_control'),
}
IDENTIFIER = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
HEX = re.compile(r'[0-9a-f]{64}')


def _bounded(value):
    raw = canonical(value)
    require(len(raw) <= MAX_BYTES, 'probe-size')
    return raw


def _key(path, *, private=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16384,
                    'probe-key-unsafe')
            require(not stat.S_IMODE(info.st_mode) & 0o022, 'probe-key-unsafe')
            if private:
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                        'probe-key-private')
            result = source.read(16385)
        require(len(result) <= 16384, 'probe-key-unsafe')
        return result
    except OSError:
        raise ApplianceError('probe-key-unsafe') from None


def validate_request(request):
    _bounded(request)
    required = {'schema', 'nonce', 'issued_at', 'expires_at', 'plan_id', 'build_id', 'capability',
                'targets', 'probe', 'selected_region', 'dependencies'}
    require(set(request) == required and request['schema'] == 1, 'probe-request-invalid')
    require(all(type(request.get(k)) is str and HEX.fullmatch(request[k]) for k in
                ('nonce', 'plan_id', 'build_id')), 'probe-request-binding')
    require(type(request['issued_at']) is int and request['issued_at'] >= 0 and
            type(request['expires_at']) is int and
            request['expires_at'] - request['issued_at'] == 900, 'probe-expiry-invalid')
    require(type(request['capability']) is str and request['capability'] in REQUIREMENTS, 'probe-capability-invalid')
    dependencies = request['dependencies']
    require(type(dependencies) is dict and not set(dependencies) -
            {'role_identity', 'config', 'policy', 'certificate', 'guest_boot', 'router_boot'} and
            all(type(v) is str and IDENTIFIER.fullmatch(v) for v in dependencies.values()),
            'probe-dependencies-invalid')
    registration = request['probe']
    require(type(registration) is dict and set(registration) ==
            {'id', 'host_id', 'admin_id', 'appliance_host_id', 'appliance_admin_id', 'key_sha256'},
            'probe-registration-required')
    require(all(type(registration[k]) is str and IDENTIFIER.fullmatch(registration[k])
                for k in registration if k != 'key_sha256') and
            type(registration['key_sha256']) is str and HEX.fullmatch(registration['key_sha256']),
            'probe-registration-invalid')
    require(registration['host_id'] != registration['appliance_host_id'] and
            registration['admin_id'] != registration['appliance_admin_id'], 'probe-not-independent')
    region = request['selected_region']
    require(region is None or type(region) is int and 1 <= region <= 65535, 'probe-region-invalid')
    require(request['capability'] != 'relay' or region is not None, 'probe-region-required')
    targets = request['targets']
    require(type(targets) is list and 1 <= len(targets) <= 16, 'probe-targets-required')
    ids = set()
    for target in targets:
        require(type(target) is dict and
                {'id', 'url', 'expect', 'peer_identity', 'tls_sha256'} <= set(target) and
                not set(target) - {'id', 'url', 'expect', 'peer_identity', 'tls_sha256', 'expected_ipv4'},
                'probe-target-invalid')
        if 'expected_ipv4' in target:
            try:
                require(type(target['expected_ipv4']) is str and
                        str(ipaddress.IPv4Address(target['expected_ipv4'])) == target['expected_ipv4'], 'probe-target-address')
            except ValueError:
                raise ApplianceError('probe-target-address') from None
        require(type(target['id']) is str and IDENTIFIER.fullmatch(target['id']) and
                target['id'] not in ids, 'probe-target-id-invalid')
        ids.add(target['id'])
        require(target['expect'] in ('allowed', 'denied', 'denied-control', 'public-tls'), 'probe-expectation-invalid')
        require(type(target['peer_identity']) is str and IDENTIFIER.fullmatch(target['peer_identity']) and
                type(target['tls_sha256']) is str and HEX.fullmatch(target['tls_sha256']), 'probe-target-identity')
        require(type(target['url']) is str and len(target['url']) <= 1024, 'probe-target-url')
        try:
            parsed = urlsplit(target['url'])
            require(parsed.scheme == 'https' and parsed.hostname and parsed.username is None and
                    parsed.password is None and not parsed.fragment and not parsed.query and
                    parsed.port in (None, 443) and not any(ord(c) < 33 for c in target['url']), 'probe-target-url')
        except ValueError:
            raise ApplianceError('probe-target-url') from None
    if request['capability'] == 'enrollment':
        # A reachable unrelated tailnet peer says nothing about the connector.
        # Bind every positive endpoint to its locally observed node identity.
        allowed = [target for target in targets if target['expect'] == 'allowed']
        require(bool(allowed) and dependencies.get('role_identity') is not None and
                all(target['peer_identity'] == dependencies['role_identity'] for target in allowed),
                'probe-connector-target-required')
    return request


def make_probe(plan, build_id, capability, targets, *, now, dependencies=None):
    request = {'schema': 1, 'nonce': secrets.token_hex(32), 'issued_at': now, 'expires_at': now + 900,
               'plan_id': identity(plan), 'build_id': build_id, 'capability': capability,
               'targets': targets, 'probe': plan.get('probe_endpoint'), 'dependencies': dependencies or {},
               'selected_region': plan.get('roles', {}).get('derp', {}).get('region_id')
                   if capability == 'relay' else None}
    return validate_request(request)


def sign_receipt(request, observations, private_key, runner, *, now):
    """External collector signing boundary. Call only with collected observations."""
    validate_request(request)
    require(type(now) is int and request['issued_at'] <= now <= request['expires_at'], 'probe-expired')
    private_bytes = _key(private_key, private=True)
    with tempfile.TemporaryDirectory(prefix='rdc-probe-sign-') as temp:
        key_path = Path(temp) / 'key.pem'
        key_path.write_bytes(private_bytes)
        key_path.chmod(0o600)
        public = runner.run(['/usr/bin/openssl', 'pkey', '-in', str(key_path), '-pubout'], timeout_s=10).stdout
        require(hashlib.sha256(public).hexdigest() == request['probe']['key_sha256'], 'probe-key-not-registered')
        receipt = {k: request[k] for k in ('schema', 'nonce', 'plan_id', 'build_id', 'capability', 'targets')}
        receipt.update(request_id=identity(request), probe_id=request['probe']['id'],
                       created_at=now, observations=observations)
        signature = runner.run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(key_path)],
                               stdin=_bounded(receipt), timeout_s=10).stdout
        require(64 <= len(signature) <= 1024, 'probe-signature-size')
    receipt['signature'] = base64.b64encode(signature).decode('ascii')
    _bounded(receipt)
    return receipt


def verify_probe(request, receipt, trusted_key, runner, *, now):
    result = {'schema': 1, 'capability': request.get('capability') if type(request) is dict else None,
              'state': 'unknown', 'checked_at': now,
              'plan_id': request.get('plan_id') if type(request) is dict else None,
              'build_id': request.get('build_id') if type(request) is dict else None,
              'observations': {}, 'next_action': 'Run the registered independent probe with a fresh challenge.'}
    try:
        validate_request(request)
        if receipt is None:
            return result
        require(type(now) is int and request['issued_at'] <= now <= request['expires_at'], 'probe-expired')
        require(type(receipt) is dict and set(receipt) == {'schema', 'nonce', 'plan_id', 'build_id',
            'capability', 'targets', 'request_id', 'probe_id', 'created_at', 'observations', 'signature'},
            'probe-receipt-invalid')
        _bounded(receipt)
        require(all(receipt[k] == request[k] for k in ('schema', 'nonce', 'plan_id', 'build_id', 'capability', 'targets'))
                and receipt['request_id'] == identity(request) and receipt['probe_id'] == request['probe']['id'],
                'probe-receipt-binding')
        require(type(receipt['created_at']) is int and request['issued_at'] <= receipt['created_at'] <= now,
                'probe-receipt-time')
        public = _key(trusted_key)
        require(hashlib.sha256(public).hexdigest() == request['probe']['key_sha256'], 'probe-key-not-registered')
        require(type(receipt['signature']) is str and len(receipt['signature']) <= 2048, 'probe-signature-invalid')
        try:
            signature = base64.b64decode(receipt['signature'], validate=True)
        except ValueError:
            raise ApplianceError('probe-signature-invalid') from None
        require(64 <= len(signature) <= 1024, 'probe-signature-invalid')
        unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
        with tempfile.TemporaryDirectory(prefix='rdc-probe-verify-') as temp:
            key_path, signature_path = Path(temp) / 'public.pem', Path(temp) / 'signature'
            key_path.write_bytes(public)
            signature_path.write_bytes(signature)
            runner.run(['/usr/bin/openssl', 'dgst', '-sha256', '-verify', str(key_path),
                        '-signature', str(signature_path)], stdin=_bounded(unsigned), timeout_s=10)
        observed = receipt['observations']
        require(type(observed) is dict, 'probe-observations-invalid')
        keys = REQUIREMENTS[request['capability']]
        result['observations'] = {k: observed.get(k) is True for k in keys}
        peers = {t['id']: t['peer_identity'] for t in request['targets']}
        require(observed.get('peer_identities') == peers, 'probe-peer-identity-mismatch')
        require(all(observed.get(k) is True for k in keys), 'probe-controls-incomplete')
        if request['capability'] == 'relay':
            require(type(observed.get('selected_region')) is int and
                    observed['selected_region'] == request['selected_region'], 'probe-wrong-relay')
            result['observations']['selected_region'] = observed['selected_region']
        result.update(state='verified', probe_id=receipt['probe_id'], targets=request['targets'],
                      request_id=identity(request),
                      dependencies={'plan': request['plan_id'], 'build': request['build_id'],
                                    'probe': identity(request['probe']), 'challenge': request['nonce'], **request['dependencies']},
                      next_action='Repeat after any plan, build, endpoint, policy or identity change.')
    except ApplianceError as error:
        result['code'] = error.code
        result['state'] = 'unknown' if error.code in ('probe-expired', 'probe-controls-incomplete') else 'blocked'
    return result

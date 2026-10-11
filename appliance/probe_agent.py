"""Run an operator-authorized challenge on the independent Linux endpoint.

The endpoint must already be enrolled as the approved test identity. This
collector performs real bounded HTTPS checks and reads Tailscale's actual
peer state; it never enrolls an identity, modifies a firewall or broadens ACLs.
Unmeasured hosting/admission requirements remain false in its signed receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import urlsplit

from .contracts import ApplianceError, canonical, load_json, require
from .probes import REQUIREMENTS, sign_receipt, validate_request


def _https(target, nonce):
    parsed = urlsplit(target['url'])
    conn = http.client.HTTPSConnection(parsed.hostname, 443, timeout=10,
                                       context=ssl.create_default_context())
    try:
        conn.connect()
        if target.get('expected_ipv4'):
            require(conn.sock.getpeername()[0] == target['expected_ipv4'], 'probe-public-address')
        require(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() == target['tls_sha256'],
                'probe-tls-identity')
        conn.request('GET', parsed.path or '/', headers={'X-RDC-Probe-Nonce': nonce,
                                                       'Accept': 'application/json'})
        response = conn.getresponse()
        require(response.status == 200 and response.getheader('Location') is None, 'probe-http-response')
        raw = response.read(65537)
        require(len(raw) <= 65536, 'probe-response-bound')
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            payload = {}
        require(type(payload) is dict, 'probe-response-object')
        return payload
    finally:
        conn.close()


def _tail_status(runner):
    try:
        raw = runner.run(['/usr/bin/tailscale', 'status', '--json'], timeout_s=15).stdout
        require(len(raw) <= 512 * 1024, 'probe-response-bound')
        status = json.loads(raw)
        require(type(status) is dict and type(status.get('Peer')) is dict, 'probe-peer-state')
        return status
    except (ApplianceError, ValueError, UnicodeError):
        return {}


def collect(request, runner, *, https=None, tail_status=None):
    """No caller-supplied successful observations are consumed by the collector."""
    validate_request(request)
    https = https or _https
    tail_status = tail_status or _tail_status
    observed = {key: False for key in REQUIREMENTS[request['capability']]}
    observed['peer_identities'] = {}
    outcomes, bodies = {}, {}
    before = tail_status(runner)
    for target in request['targets']:
        try:
            payload = https(target, request['nonce'])
            bodies[target['id']] = payload
            outcomes[target['id']] = ('tls' if target['expect'] == 'public-tls' else
                'allowed' if payload.get('nonce') == request['nonce'] and
                payload.get('peer_identity') == target['peer_identity'] else 'invalid')
            if outcomes[target['id']] in ('allowed', 'tls'):
                observed['peer_identities'][target['id']] = target['peer_identity']
        except (OSError, ssl.SSLError, http.client.HTTPException):
            outcomes[target['id']] = 'unreachable'
        except ApplianceError:
            outcomes[target['id']] = 'invalid'
    after = tail_status(runner)
    allowed = [t for t in request['targets'] if t['expect'] == 'allowed']
    denied = [t for t in request['targets'] if t['expect'] == 'denied']
    controls = [t for t in request['targets'] if t['expect'] == 'denied-control']
    public = [t for t in request['targets'] if t['expect'] == 'public-tls']
    approved_reachable = bool(allowed) and all(outcomes[t['id']] == 'allowed' for t in allowed)
    controlled = bool(denied) and all(any(outcomes[c['id']] == 'allowed' and
        c['peer_identity'] == target['peer_identity'] and
        bodies[c['id']].get('listener_url') == target['url'] and
        bodies[c['id']].get('listener_up') is True for c in controls) for target in denied)
    if controlled:
        for target in denied:
            observed['peer_identities'][target['id']] = target['peer_identity']
    booleans = {'peer_control': approved_reachable, 'peer_reachable': approved_reachable,
                'denied_control': controlled,
                'denied_probe': controlled and all(outcomes[t['id']] == 'unreachable' for t in denied),
                'public_tls': bool(public) and all(outcomes[t['id']] == 'tls' for t in public),
                'dns_answer': bool(public) and all(outcomes[t['id']] == 'tls' for t in public)}
    def peer_ids(status):
        return {peer.get('ID') for peer in status.get('Peer', {}).values()
                if type(peer) is dict and peer.get('Online') is True}
    expected = {t['peer_identity'] for t in allowed}
    booleans['registered'] = bool(expected) and expected <= peer_ids(after)
    booleans['identity_preserved'] = bool(expected) and expected <= peer_ids(before) & peer_ids(after)
    for key in observed:
        if key in booleans:
            observed[key] = booleans[key]
    # No generic local check can attest fresh remote registration, routed STUN,
    # source preservation, or unknown/verifier-down *new* relay sessions.
    # Dedicated disposable acceptance scenarios must supply those measurements.
    return observed


def run_probe(request, private_key, runner):
    validate_request(request)
    now = int(time.time())
    require(request['issued_at'] <= now <= request['expires_at'], 'probe-expired')
    observations = collect(request, runner)
    return sign_receipt(request, observations, private_key, runner, now=int(time.time()))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run a registered independent network proof.')
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--private-key', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        from .runner import Runner
        receipt = run_probe(load_json(args.request, limit=512 * 1024), args.private_key,
                            Runner(max_output_bytes=512 * 1024))
        sys.stdout.buffer.write(canonical(receipt) + b'\n')
        return 0
    except ApplianceError as error:
        sys.stderr.write(error.code + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

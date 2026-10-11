"""Real OpenSSL signatures with replay, substitution and incomplete-control refusals."""
import copy
import hashlib
from pathlib import Path
import subprocess

import pytest

from appliance import probes
from appliance.contracts import ApplianceError
from appliance.runner import Runner


@pytest.fixture
def pair(tmp_path):
    private = tmp_path / 'signing.pem'
    public = tmp_path / 'verify.pem'
    subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                    'rsa_keygen_bits:2048', '-out', str(private)], check=True, capture_output=True)
    private.chmod(0o600)
    public.write_bytes(subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout'],
                                     check=True, capture_output=True).stdout)
    return private, public


@pytest.fixture
def challenge(site, pair):
    site['probe_endpoint'] = {'id': 'independent-one', 'host_id': 'remote-host', 'admin_id': 'network-owner',
        'appliance_host_id': 'pilot-host', 'appliance_admin_id': 'local-owner',
        'key_sha256': hashlib.sha256(pair[1].read_bytes()).hexdigest()}
    return probes.make_probe(site, 'a' * 64, 'enrollment', [
        {'id': 'allowed', 'url': 'https://peer.example.org/rdc-proof', 'expect': 'allowed',
         'peer_identity': 'connector-node', 'tls_sha256': 'b' * 64},
        {'id': 'denied', 'url': 'https://denied.example.org/rdc-proof', 'expect': 'denied',
         'peer_identity': 'peer-two', 'tls_sha256': 'c' * 64},
        {'id': 'control', 'url': 'https://control.example.org/rdc-proof', 'expect': 'denied-control',
         'peer_identity': 'peer-two', 'tls_sha256': 'd' * 64},
    ], now=1000, dependencies={'role_identity': 'connector-node'})


def observations(challenge):
    return {**{key: True for key in probes.REQUIREMENTS[challenge['capability']]},
            'peer_identities': {t['id']: t['peer_identity'] for t in challenge['targets']}}


def signed(challenge, pair):
    return probes.sign_receipt(challenge, observations(challenge), pair[0], Runner(), now=1001)


def test_real_signature_accepts_complete_fresh_bound_evidence(challenge, pair):
    result = probes.verify_probe(challenge, signed(challenge, pair), pair[1], Runner(), now=1002)
    assert result['state'] == 'verified'
    assert result['plan_id'] == challenge['plan_id']


@pytest.mark.parametrize('field,value', [('nonce', 'a' * 64), ('build_id', 'b' * 64),
    ('plan_id', 'c' * 64), ('capability', 'controller')])
def test_substituted_binding_rejected(challenge, pair, field, value):
    receipt = signed(challenge, pair)
    receipt[field] = value
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1002)['state'] != 'verified'


def test_expired_or_future_receipt_unknown(challenge, pair):
    receipt = signed(challenge, pair)
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1901)['state'] == 'unknown'
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=999)['state'] != 'verified'


def test_missing_control_never_verifies(challenge, pair):
    observed = observations(challenge)
    observed['denied_control'] = False
    receipt = probes.sign_receipt(challenge, observed, pair[0], Runner(), now=1001)
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1002)['state'] != 'verified'


def test_signature_tamper_and_wrong_key_rejected(challenge, pair, tmp_path):
    receipt = signed(challenge, pair)
    receipt['observations']['peer_reachable'] = False
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1002)['state'] != 'verified'
    wrong = tmp_path / 'wrong.pem'
    wrong.write_bytes(b'not a public key')
    assert probes.verify_probe(challenge, signed(challenge, pair), wrong, Runner(), now=1002)['state'] != 'verified'


def test_same_host_or_administrator_cannot_be_external(site, pair):
    site['probe_endpoint'] = {'id': 'probe', 'host_id': 'host', 'appliance_host_id': 'host',
        'admin_id': 'a', 'appliance_admin_id': 'b', 'key_sha256': 'a' * 64}
    with pytest.raises(ApplianceError, match='probe-not-independent'):
        probes.make_probe(site, 'a' * 64, 'enrollment', [], now=1000)


def test_selected_relay_must_match(challenge, pair):
    challenge['capability'] = 'relay'
    challenge['selected_region'] = 901
    observed = observations(challenge)
    observed['selected_region'] = 902
    receipt = probes.sign_receipt(challenge, observed, pair[0], Runner(), now=1001)
    assert probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1002)['state'] != 'verified'


def test_missing_probe_is_unknown(challenge, pair):
    assert probes.verify_probe(challenge, None, pair[1], Runner(), now=1002)['state'] == 'unknown'


def test_collector_requires_live_denied_listener_and_bound_peer(challenge, monkeypatch):
    from appliance import probe_agent
    monkeypatch.setattr(probe_agent, '_tail_status', lambda runner: {
        'Peer': {'peer': {'ID': 'connector-node', 'Online': True}}})
    def https(target, nonce):
        if target['expect'] == 'denied':
            raise TimeoutError()
        body = {'nonce': nonce, 'peer_identity': target['peer_identity']}
        if target['expect'] == 'denied-control':
            body.update(listener_url=challenge['targets'][1]['url'], listener_up=True)
        return body
    monkeypatch.setattr(probe_agent, '_https', https)
    result = probe_agent.collect(challenge, None)
    assert all(result[k] is True for k in probes.REQUIREMENTS['enrollment'])
    challenge['targets'][2]['peer_identity'] = 'wrong-listener'
    result = probe_agent.collect(challenge, None)
    assert result['denied_control'] is False and result['denied_probe'] is False


def test_unmeasured_hosting_gates_remain_false(challenge, monkeypatch):
    from appliance import probe_agent
    challenge['capability'] = 'controller'
    monkeypatch.setattr(probe_agent, '_tail_status', lambda runner: {})
    monkeypatch.setattr(probe_agent, '_https', lambda *args: {})
    result = probe_agent.collect(challenge, None)
    assert result['fresh_registration'] is False


@pytest.mark.parametrize('role_identity', [None, 'unrelated-node'])
def test_enrollment_request_must_target_the_observed_connector(site, challenge, role_identity):
    dependencies = {} if role_identity is None else {'role_identity': role_identity}
    with pytest.raises(ApplianceError, match='probe-connector-target-required'):
        probes.make_probe(site, challenge['build_id'], 'enrollment', challenge['targets'],
                          now=1000, dependencies=dependencies)


def test_enrollment_request_cannot_omit_a_positive_connector_target(challenge):
    challenge['targets'] = [t for t in challenge['targets'] if t['expect'] != 'allowed']
    with pytest.raises(ApplianceError, match='probe-connector-target-required'):
        probes.validate_request(challenge)


def test_signed_unrelated_peer_cannot_verify_connector(challenge, pair):
    import base64
    from appliance.contracts import canonical, identity
    # Model a registered external signer returning a cryptographically valid
    # but semantically unrelated success. Signature validity is insufficient.
    receipt = signed(challenge, pair)
    challenge['dependencies']['role_identity'] = 'actual-other-connector'
    receipt['request_id'] = identity(challenge)
    unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
    signature = Runner().run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(pair[0])],
                             stdin=canonical(unsigned)).stdout
    receipt['signature'] = base64.b64encode(signature).decode()
    result = probes.verify_probe(challenge, receipt, pair[1], Runner(), now=1002)
    assert result['state'] == 'blocked'
    assert result['code'] == 'probe-connector-target-required'


def test_collector_needs_actual_connector_identity_nonce_and_tls_bound_response(challenge):
    from appliance import probe_agent
    connector_id = challenge['dependencies']['role_identity']
    def status(runner):
        return {'Peer': {'key': {'ID': connector_id, 'Online': True}}}
    def https(target, nonce):
        if target['expect'] == 'denied':
            raise TimeoutError()
        reply = {'nonce': nonce, 'peer_identity': target['peer_identity']}
        if target['expect'] == 'denied-control':
            reply.update(listener_url=challenge['targets'][1]['url'], listener_up=True)
        return reply
    observed = probe_agent.collect(challenge, None, https=https, tail_status=status)
    assert observed['registered'] is True and observed['peer_reachable'] is True
    assert observed['peer_identities']['allowed'] == connector_id
    wrong_status = lambda runner: {'Peer': {'key': {'ID': 'unrelated-node', 'Online': True}}}
    wrong = probe_agent.collect(challenge, None, https=https, tail_status=wrong_status)
    assert wrong['registered'] is False and wrong['identity_preserved'] is False
    def stale_https(target, nonce):
        reply = https(target, nonce)
        if target['expect'] == 'allowed':
            reply['nonce'] = 'stale'
        return reply
    stale = probe_agent.collect(challenge, None, https=stale_https, tail_status=status)
    assert stale['peer_reachable'] is False


def test_enrollment_cannot_mix_connector_with_unrelated_positive_target(challenge):
    unrelated = copy.deepcopy(challenge['targets'][0])
    unrelated.update(id='unrelated-positive', peer_identity='unrelated-node')
    challenge['targets'].append(unrelated)
    with pytest.raises(ApplianceError, match='probe-connector-target-required'):
        probes.validate_request(challenge)


def test_collector_rejects_listener_claiming_different_node(challenge):
    from appliance import probe_agent
    status = lambda runner: {'Peer': {'key': {'ID': challenge['dependencies']['role_identity'], 'Online': True}}}
    def https(target, nonce):
        return {'nonce': nonce, 'peer_identity': 'unrelated-node'}
    observed = probe_agent.collect(challenge, None, https=https, tail_status=status)
    assert observed['peer_reachable'] is False
    assert 'allowed' not in observed['peer_identities']

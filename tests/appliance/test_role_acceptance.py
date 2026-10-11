import copy
import struct
from types import SimpleNamespace

import pytest

from appliance.contracts import ApplianceError
from appliance import role_acceptance as role


def stun_packet(transaction=b'x' * 12, address=0x08080808, port=12345):
    attr = struct.pack('!HHBBHI', 0x20, 8, 0, 1, port ^ 0x2112, address ^ role.STUN_COOKIE)
    return struct.pack('!HHI', 0x101, len(attr), role.STUN_COOKIE) + transaction + attr


def test_stun_transaction_and_xor_source_are_checked():
    assert role.stun_response(stun_packet(), b'x' * 12) == {'public_ipv4': '8.8.8.8', 'port': 12345}
    with pytest.raises(ApplianceError, match='stun-response-binding'):
        role.stun_response(stun_packet(), b'y' * 12)
    with pytest.raises(ApplianceError):
        role.stun_response(stun_packet()[:-1], b'x' * 12)


def test_selected_relay_requires_actual_flow_bytes_and_correct_region():
    before = {'Peer': {'key': {'ID': 'peer', 'TxBytes': 1, 'RxBytes': 2}}}
    after = {'Peer': {'key': {'ID': 'peer', 'TxBytes': 200, 'RxBytes': 100, 'Relay': 'own', 'CurAddr': ''}}}
    mapping = {'Regions': {'901': {'RegionID': 901, 'RegionCode': 'own'}}}
    targets = [{'expect': 'allowed', 'peer_identity': 'peer'}]
    assert role.selected_relay(before, after, mapping, targets, 901)['forced_relay']
    after['Peer']['key']['Relay'] = 'fallback'
    with pytest.raises(ApplianceError, match='probe-wrong-relay'):
        role.selected_relay(before, after, mapping, targets, 901)


def test_owned_firewall_is_removed_after_flow_failure(monkeypatch):
    monkeypatch.setattr(role, 'namespace_profile', lambda _: 'rdcroles-123456abcdef')
    class Runner:
        def __init__(self): self.calls = []
        def run(self, argv, **kwargs):
            self.calls.append(argv)
            return SimpleNamespace(stdout=b'')
    runner = Runner()
    with pytest.raises(RuntimeError):
        with role.force_relay({}, runner):
            raise RuntimeError('flow interrupted')
    assert runner.calls[-1][-4:-1] == ['delete', 'table', 'inet']
    assert runner.calls[-1][-1] == runner.calls[0][-1]
    assert all('flush' not in c for c in runner.calls)


def test_unimplemented_admission_cannot_be_hidden_by_machine_presence(monkeypatch):
    monkeypatch.setattr(role.platform, 'system', lambda: 'Linux')
    report = role.preflight('all')
    assert report['qualification'] == 'NOT RUN'
    assert 'derp-new-session-wire-client-not-implemented' in report['reasons']
    assert all(case['status'] == 'NOT RUN' for case in report['cases'])


def test_fresh_client_stops_only_owned_unit_and_never_logs_credential(tmp_path, monkeypatch):
    from appliance import state
    monkeypatch.setattr(role, 'namespace_profile', lambda _: 'rdcroles-123456abcdef')
    monkeypatch.setattr(role, 'verify_controller', lambda *args: None)
    monkeypatch.setattr(role, 'network_namespace', lambda name: __import__('contextlib').nullcontext())
    auth = tmp_path / 'approval.json'
    state.write(auth, {'controller': 'https://controller.example.org', 'tls_sha256': 'a' * 64,
        'approved': True, 'owner_reference': 'test-network-owner', 'node_name': 'disposable-proof',
        'expires_at': int(role.time.time()) + 100, 'one_use': True, 'ephemeral': True,
        'credential': 'secret-probe-credential'})
    class Runner:
        def __init__(self): self.calls = []
        def run(self, argv, **kwargs):
            self.calls.append(argv)
            if 'show' in argv: return SimpleNamespace(stdout=b'not-found\n')
            if 'status' in argv: return SimpleNamespace(stdout=b'{"BackendState":"Running","Self":{"ID":"fresh-node"},"Peer":{}}')
            return SimpleNamespace(stdout=b'')
    runner = Runner()
    profile = {'authorization': str(auth), 'state': str(tmp_path / 'private')}
    with pytest.raises(RuntimeError):
        with role.fresh_client(profile, runner, 'a' * 64) as scoped:
            raise RuntimeError('interrupted measurement')
    assert runner.calls[-1][1] == 'stop'
    assert runner.calls[-1][2].startswith('rdc-probe-')
    assert 'secret-probe-credential' not in str(runner.calls)
    with pytest.raises(ApplianceError, match='operation-needs-inspection'):
        with role.fresh_client(profile, runner, 'a' * 64):
            pass

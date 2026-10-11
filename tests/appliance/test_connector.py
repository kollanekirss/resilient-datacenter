"""Identity, policy and one-use approval boundaries for connector enrollment."""
import copy
import json
from types import SimpleNamespace

import pytest

from appliance.contracts import ApplianceError
from appliance import connector
from appliance.guest import connector as guest


@pytest.fixture
def chosen(site):
    site['roles']['connector'] = {'selected': True, 'controller': 'https://control.example.org'}
    site['vms']['connector'] = {'vmid': 110}
    return site


@pytest.fixture
def authorization(monkeypatch):
    monkeypatch.setattr(connector.time, 'time', lambda: 1000)
    return {'controller': 'https://control.example.org', 'tls_sha256': 'a' * 64,
            'approved': True, 'owner_reference': 'owner-ticket-17', 'node_name': 'pilot-connector',
            'expires_at': 1100, 'one_use': True, 'credential': 'private-one-use-secret'}


class Client:
    def __init__(self, *, timeout=False, node='node-1'):
        self.calls, self.timeout, self.node = [], timeout, node
    def run(self, argv, *, stdin=b'', timeout_s=30):
        self.calls.append(argv)
        if argv[1] == 'up' and self.timeout:
            raise ApplianceError('command-timeout')
        if argv[1:3] == ['status', '--json']:
            return SimpleNamespace(stdout=json.dumps({'BackendState': 'Running', 'Self': {'ID': self.node}}).encode())
        if argv[1:3] == ['debug', 'prefs']:
            return SimpleNamespace(stdout=json.dumps({'ControlURL': 'https://control.example.org',
                'RouteAll': False, 'CorpDNS': False, 'RunSSH': False, 'AdvertiseRoutes': [],
                'AdvertiseTags': [], 'ExitNodeID': '', 'ExitNodeIP': ''}).encode())
        if argv[0].endswith('/sysctl'):
            return SimpleNamespace(stdout=b'0\n')
        if argv[0].endswith('/ip'):
            return SimpleNamespace(stdout=b'[{"dst":"100.64.0.2","dev":"tailscale0"}]')
        return SimpleNamespace(stdout=b'')


def request(chosen, authorization, action='enroll'):
    return {'schema': 1, 'operation_id': 'a' * 64, 'plan_id': 'b' * 64,
            'role': 'connector', 'action': action,
            'parameters': {'config': connector.connector_config(chosen), 'authorization': authorization}}


def test_fixed_no_routing_policy(chosen):
    c = connector.connector_config(chosen)
    assert c['advertise_routes'] == []
    assert not any(c[k] for k in ('advertise_exit_node', 'accept_routes', 'tailscale_ssh', 'accept_dns', 'ip_forward'))
    assert c['exit_node'] == ''


@pytest.mark.parametrize('change,code', [({'approved': False}, 'network-owner-approval-required'),
    ({'expires_at': 999}, 'enrollment-authorization-expired'),
    ({'controller': 'https://wrong.example.org'}, 'controller-approval-mismatch'),
    ({'one_use': False}, 'single-use-authorization-required')])
def test_bad_approval_never_contacts_guest(chosen, authorization, tmp_path, change, code):
    authorization.update(change)
    with pytest.raises(ApplianceError, match=code):
        connector.join(chosen, authorization, Client(), tmp_path)


def test_guest_checks_tls_before_consuming_credential(chosen, authorization, tmp_path, monkeypatch):
    runner = Client()
    def refuse(*args):
        raise ApplianceError('controller-tls-identity')
    monkeypatch.setattr(guest, 'verify_controller', refuse)
    with pytest.raises(ApplianceError, match='controller-tls-identity'):
        guest.handle(request(chosen, authorization), tmp_path, runner)
    assert not any('up' in c for c in runner.calls)
    assert not list(tmp_path.rglob('*credential*'))


def test_enrollment_preserves_identity_and_deletes_credential(chosen, authorization, tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    runner = Client()
    first = guest.handle(request(chosen, authorization), tmp_path, runner)
    assert first['observations']['node_id'] == 'node-1'
    second = guest.handle(request(chosen, authorization), tmp_path, runner)
    assert second['observations']['node_id'] == 'node-1'
    assert sum(c[1] == 'up' for c in runner.calls) == 1
    assert authorization['credential'] not in json.dumps(runner.calls)
    assert authorization['credential'] not in ''.join(p.read_text() for p in tmp_path.rglob('*.json'))
    assert not list(tmp_path.rglob('*credential*'))


def test_timeout_cannot_reenroll(chosen, authorization, tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    runner = Client(timeout=True)
    with pytest.raises(ApplianceError, match='command-timeout'):
        guest.handle(request(chosen, authorization), tmp_path, runner)
    response = guest.handle(request(chosen, authorization), tmp_path, runner)
    assert response['observations']['node_id'] == 'node-1'
    assert sum(c[1] == 'up' for c in runner.calls) == 1
    assert not list(tmp_path.rglob('*credential*'))


def test_changed_authority_and_node_identity_refused(chosen, authorization, tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    runner = Client()
    guest.handle(request(chosen, authorization), tmp_path, runner)
    runner.node = 'node-2'
    with pytest.raises(ApplianceError, match='connector-identity-changed'):
        guest.handle(request(chosen, authorization, 'inspect'), tmp_path, runner)
    changed = request(chosen, authorization)
    changed['parameters']['config']['controller'] = 'https://other.example.org'
    with pytest.raises(ApplianceError, match='connector-authority-change-refused'):
        guest.handle(changed, tmp_path, runner)


def test_subnet_or_exit_route_drift_fails_inspection(chosen, authorization, tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    runner = Client()
    original = runner.run
    def run(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1:3] == ['debug', 'prefs']:
            prefs = json.loads(result.stdout)
            prefs['RouteAll'] = True
            result.stdout = json.dumps(prefs).encode()
        return result
    runner.run = run
    with pytest.raises(ApplianceError, match='connector-policy-drift'):
        guest.handle(request(chosen, authorization), tmp_path, runner)


def test_colocated_override_requires_deliberately_selected_controller(chosen):
    chosen['roles']['headscale'] = {'selected': True, 'hostname': 'other.example.org'}
    chosen['vms']['headscale'] = {'nics': [{'zone': 'infrastructure', 'address': '10.77.1.12'}]}
    assert 'controller_address' not in connector.connector_config(chosen)
    chosen['roles']['headscale']['hostname'] = 'control.example.org'
    assert connector.connector_config(chosen)['controller_address'] == '10.77.1.12'


def test_readonly_verification_does_not_start_service(chosen, authorization, tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    runner = Client()
    guest.handle(request(chosen, authorization), tmp_path, runner)
    runner.calls.clear()
    guest.handle(request(chosen, authorization, 'verify'), tmp_path, runner)
    assert not any(c[0].endswith('/systemctl') for c in runner.calls)


def test_guest_dispatch_recovers_pending_then_allows_new_boot(chosen, authorization, tmp_path, monkeypatch):
    from appliance.guest import helper, state as guest_state
    monkeypatch.setattr(guest, 'verify_controller', lambda *args: None)
    monkeypatch.setattr(helper, '_boot_id', lambda: '11111111-1111-1111-1111-111111111111')
    guest_state.initialize(tmp_path, {'schema': 1, 'plan_id': 'b' * 64, 'role': 'connector', 'vmid': 110}, 'c' * 32)
    runner = Client(timeout=True)
    first = request(chosen, authorization)
    with pytest.raises(ApplianceError, match='command-timeout'):
        helper.dispatch(first, tmp_path, runner)
    resume = request(chosen, authorization, 'inspect')
    resume['operation_id'] = 'd' * 64
    assert helper.dispatch(resume, tmp_path, runner)['observations']['registered']
    assert helper.query_operation(first['operation_id'], tmp_path)['phase'] == 'complete'
    monkeypatch.setattr(helper, '_boot_id', lambda: '22222222-2222-2222-2222-222222222222')
    resume['operation_id'] = 'e' * 64
    assert helper.dispatch(resume, tmp_path, runner)['observations']['node_id'] == 'node-1'
    assert sum(c[1] == 'up' for c in runner.calls) == 1

import pytest

from appliance.contracts import ApplianceError, identity
from appliance.headscale import headscale_config, create_authority
from hosting_fixtures import hosting_site, certificates, HostingRunner


def test_headscale_native_tls_and_deny_policy_separate_relay(site):
    config = headscale_config(hosting_site(site))
    assert config['server_url'] == 'https://control.example.net'
    assert config['listen_addr'] == '10.77.1.11:443'
    assert config['derp']['server']['enabled'] is False
    assert config['tls_letsencrypt_hostname'] == ''
    assert config['tls_cert_path'].endswith('/tls.crt')
    assert config['policy']['mode'] == 'file'
    assert config['database']['type'] == 'sqlite'
    assert config['grpc_listen_addr'].startswith('127.0.0.1:')


def test_authority_creation_requires_explicit_matching_name(site, tmp_path):
    plan = hosting_site(site)
    with pytest.raises(ApplianceError, match='authority-approval-required'):
        create_authority(plan, {'authority': 'fallback'}, object(), tmp_path)


def request(plan, credentials):
    return {'schema': 1, 'operation_id': 'hosting-operation', 'plan_id': identity(plan),
            'role': 'headscale', 'action': 'configure',
            'parameters': {'plan': plan, 'credentials': {**credentials, 'authority': 'pilot-authority'}}}


def test_guest_creation_preserves_identity_and_requires_explicit_tls_replacement(site, tmp_path):
    from appliance.guest.headscale import handle
    plan = hosting_site(site)
    runner = HostingRunner(tmp_path)
    first = handle(request(plan, certificates()), tmp_path, runner)
    assert first['configured'] is True
    assert first['ordinary_client_ready'] is False
    assert first['tls']['valid'] is True
    replacement = request(plan, certificates())
    with pytest.raises(ApplianceError, match='certificate-replacement-approval'):
        handle(replacement, tmp_path, runner)
    replacement['parameters']['credentials']['replace_certificate'] = True
    second = handle(replacement, tmp_path, runner)
    assert second['identity'] == first['identity']
    assert second['tls']['certificate_sha256'] != first['tls']['certificate_sha256']
    changed = hosting_site(site)
    changed['roles']['headscale']['authority'] = 'unapproved-new-authority'
    credentials = {**certificates(), 'authority': 'unapproved-new-authority'}
    changed_request = request(changed, credentials)
    changed_request['parameters']['credentials']['authority'] = 'unapproved-new-authority'
    with pytest.raises(ApplianceError, match='authority-change-forbidden'):
        handle(changed_request, tmp_path, runner)


def test_invalid_certificate_never_mutates_authority_or_runs_commands(site, tmp_path):
    from appliance.guest.headscale import handle
    runner = HostingRunner(tmp_path)
    with pytest.raises(ApplianceError, match='hosting-tls-invalid'):
        handle(request(hosting_site(site), certificates('wrong.example.net')), tmp_path, runner)
    assert runner.calls == []
    assert not (tmp_path / 'headscale').exists()


def test_failed_configtest_preserves_running_config_and_identity(site, tmp_path):
    from appliance.guest.headscale import handle
    plan = hosting_site(site)
    runner = HostingRunner(tmp_path)
    creds = certificates()
    first = handle(request(plan, creds), tmp_path, runner)
    old_config = (tmp_path / 'headscale/config.json').read_bytes()
    runner.failure = 'configtest'
    updated = request(plan, certificates())
    updated['parameters']['credentials']['replace_certificate'] = True
    with pytest.raises(ApplianceError, match='command-failed'):
        handle(updated, tmp_path, runner)
    assert (tmp_path / 'headscale/config.json').read_bytes() == old_config
    runner.failure = None
    observed = handle({**updated, 'action': 'inspect', 'parameters': {}}, tmp_path, runner)
    assert observed['identity'] == first['identity']


def test_enrollment_and_verification_policy_are_narrow_fixed_operations(site, tmp_path):
    from appliance.guest.headscale import handle
    from appliance.contracts import load_json
    plan, runner = hosting_site(site), HostingRunner(tmp_path)
    req = request(plan, certificates())
    initial = handle(req, tmp_path, runner)
    approved = handle({**req, 'action': 'enroll', 'parameters': {'owner_approval': 'network-owner-ticket-42',
        'registration_id': 'abcdefghijklmnopqrst', 'user': 'verification'}}, tmp_path, runner)
    assert approved['approved'] is True
    assert approved['identity'] == initial['identity']
    policy = {'purpose': 'verification-policy', 'owner_approval': 'network-owner-ticket-42',
              'source_ipv4': '100.64.0.1', 'allowed_peer_ipv4': '100.64.0.2', 'denied_peer_ipv4': '100.64.0.3'}
    result = handle({**req, 'parameters': policy}, tmp_path, runner)
    assert result['policy_verified'] is False
    actual = load_json(tmp_path / 'headscale/policy.json')
    assert actual['acls'] == [{'action': 'accept', 'src': ['100.64.0.1'], 'dst': ['100.64.0.2:443']}]
    assert actual['ssh'] == []


def test_actual_dispatch_returns_no_credential_and_journals_once(site, tmp_path, monkeypatch):
    from appliance.guest.helper import dispatch
    from appliance.guest import helper
    from appliance.guest.state import initialize
    plan, runner = hosting_site(site), HostingRunner(tmp_path)
    monkeypatch.setattr(helper, '_boot_id', lambda: '12345678-1234-1234-1234-123456789abc')
    initialize(tmp_path, {'schema': 1, 'role': 'headscale', 'plan_id': identity(plan), 'vmid': 104}, 'a' * 32)
    req = request(plan, certificates())
    reply = dispatch(req, tmp_path, runner)
    assert reply['phase'] == 'complete'
    assert reply['observations']['configured'] is True
    assert reply['observations']['machine_id'] == 'a' * 32
    count = len(runner.calls)
    assert dispatch(req, tmp_path, runner) == reply
    assert len(runner.calls) == count
    journal = (tmp_path / 'operations/hosting-operation.json').read_text()
    assert 'PRIVATE KEY' not in journal and 'CERTIFICATE' not in journal


def test_failed_tls_preflight_does_not_block_corrected_setup(site, tmp_path, monkeypatch):
    from appliance.guest import helper
    from appliance.guest.state import initialize
    plan, runner = hosting_site(site), HostingRunner(tmp_path)
    monkeypatch.setattr(helper, '_boot_id', lambda: '12345678-1234-1234-1234-123456789abc')
    initialize(tmp_path, {'schema': 1, 'role': 'headscale', 'plan_id': identity(plan), 'vmid': 104}, 'a' * 32)
    with pytest.raises(ApplianceError, match='hosting-tls-invalid'):
        helper.dispatch(request(plan, certificates('wrong.example.net')), tmp_path, runner)
    assert not (tmp_path / 'operations/hosting-operation.json').exists()
    corrected = request(plan, certificates())
    assert helper.dispatch(corrected, tmp_path, runner)['phase'] == 'complete'


def test_reconnect_refuses_changed_policy_before_start(site, tmp_path):
    from appliance.guest.headscale import handle
    from appliance.guest.hosting import private_write
    plan, runner = hosting_site(site), HostingRunner(tmp_path)
    req = request(plan, certificates())
    handle(req, tmp_path, runner)
    private_write(tmp_path / 'headscale/policy.json', b'{"acls": [{"src": ["*"], "dst": ["*:*"]}]}')
    count = len(runner.calls)
    with pytest.raises(ApplianceError, match='role-policy-changed'):
        handle({**req, 'action': 'verify', 'parameters': {'reconnect': True}}, tmp_path, runner)
    assert not any('start' in call for call in runner.calls[count:])

import pytest

from appliance.derp import derp_config, relay_policy
from appliance.hosting import prerequisites
from appliance.contracts import ApplianceError, identity
from hosting_fixtures import hosting_site, certificates, HostingRunner


def test_admission_is_fail_closed_and_colocated_verifier_is_explicit(site):
    config = derp_config(hosting_site(site))
    assert config['verify_client_url_fail_open'] is False
    assert config['verify_client_url'] == 'https://control.example.net/verify'
    assert config['verifier_host_binding'] == {'hostname': 'control.example.net', 'address': '10.77.1.11'}


def test_relay_has_no_translation_and_preserves_source(site):
    policy = relay_policy(hosting_site(site))
    assert policy['inbound_translation'] is False
    assert policy['outbound_translation'] is False
    assert policy['preserve_client_source'] is True
    assert policy['services'] == [{'protocol': 'tcp', 'port': 443}, {'protocol': 'tcp', 'port': 80}, {'protocol': 'udp', 'port': 3478}]


def test_return_route_and_routed_allocation_are_required(site):
    plan = hosting_site(site)
    plan['roles']['derp']['gateway'] = '8.8.8.6'
    assert 'derp-router-gateway-mismatch' in prerequisites(plan, 'derp')


def request(plan, credentials):
    return {'schema': 1, 'operation_id': 'derp-operation', 'plan_id': identity(plan),
        'role': 'derp', 'action': 'configure', 'parameters': {'plan': plan, 'credentials': credentials}}


def test_native_relay_args_force_fail_closed_and_identity_survives_restart(site, tmp_path):
    from appliance.guest.derp import handle, command
    from appliance.state import read
    plan, runner = hosting_site(site), HostingRunner(tmp_path)
    req = request(plan, certificates('relay.example.net'))
    first = handle(req, tmp_path, runner)
    config = read(tmp_path / 'derp/config.json')
    argv = command(config, root=str(tmp_path / 'derp'))
    assert '-verify-client-url-fail-open=false' in argv
    assert '-certmode=manual' in argv
    assert '-c=' + str(tmp_path / 'derp/derper.key') in argv
    assert (tmp_path / 'derp/hosts').read_text() == '127.0.0.1 localhost\n10.77.1.11 control.example.net\n'
    again = handle(req, tmp_path, runner)
    assert first['identity'] == again['identity']
    assert again['published'] is False


def test_unsupported_failclosed_binary_never_starts_relay(site, tmp_path):
    from appliance.guest.derp import handle
    import subprocess
    class NoFlagRunner(HostingRunner):
        def run(self, argv, **kwargs):
            if '-help' in argv:
                return subprocess.CompletedProcess(argv, 0, b'old derper', b'')
            return super().run(argv, **kwargs)
    runner = NoFlagRunner(tmp_path)
    with pytest.raises(ApplianceError, match='derp-fail-closed-unsupported'):
        handle(request(hosting_site(site), certificates('relay.example.net')), tmp_path, runner)
    assert not any('restart' in call for call in runner.calls)
    assert not (tmp_path / 'derp/derper.key').exists()


def test_changed_relay_identity_is_never_recreated(site, tmp_path):
    from appliance.guest.derp import handle
    from appliance.guest.hosting import private_write
    runner, plan = HostingRunner(tmp_path), hosting_site(site)
    req = request(plan, certificates('relay.example.net'))
    handle(req, tmp_path, runner)
    private_write(tmp_path / 'derp/derper.key', b'foreign-key')
    with pytest.raises(ApplianceError, match='role-identity-changed'):
        handle(req, tmp_path, runner)

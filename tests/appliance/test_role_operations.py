import importlib
from types import SimpleNamespace

import pytest

from appliance.contracts import ApplianceError


def module(): return importlib.import_module('appliance.role_operations')


def test_join_command_has_no_auth_secret_on_command_line():
    from appliance.cli import parser
    args = parser().parse_args(['roles', 'join', '--authorization', '/private/approval.json'])
    assert args.action == 'join'
    with pytest.raises(SystemExit):
        parser().parse_args(['roles', 'join', '--auth-key', 'secret'])


def test_cold_role_start_requires_router_and_runtime_gate(site, tmp_path, monkeypatch):
    from appliance import guests, router
    site['roles']['connector']['selected'] = True
    called = []
    monkeypatch.setattr(router, 'collect_router', lambda *a: called.append('router') or {'stage': 'bootstrap'})
    monkeypatch.setattr(router, 'router_ready', lambda *a: {'checks_passed': True})
    monkeypatch.setattr(guests, 'start_linux', lambda *a: called.append('start') or {})
    with pytest.raises(ApplianceError, match='role-router-transit-required'):
        module().start_role(site, 'connector', object(), tmp_path)
    assert called == ['router']


def test_role_failure_does_not_skip_other_selected_roles(site, tmp_path, monkeypatch):
    from appliance import startup
    ops = module()
    for role in site['roles']: site['roles'][role]['selected'] = True
    called = []
    def start(plan, role, runner, state):
        called.append(role)
        if role == 'headscale': raise ApplianceError('guest-not-configured')
        return {'role': role, 'state': 'configured'}
    monkeypatch.setattr(ops, 'start_role', start)
    result = startup.start_roles(site, object(), state=tmp_path)
    assert set(called) == set(site['roles'])
    assert next(item for item in result if item['role'] == 'headscale')['state'] == 'blocked'
    assert next(item for item in result if item['role'] == 'connector')['state'] == 'configured'


def test_status_never_uses_untrusted_precomputed_proof(site, tmp_path):
    from appliance import state
    state.write(tmp_path / 'role-evidence/headscale.json', {'state': 'verified', 'secret': 'NEVER-SHOW'})
    result = module().role_status(site, {'build_id': 'b' * 64}, object(), tmp_path)
    assert all(item['state'] == 'not-selected' for item in result.values())
    assert 'NEVER-SHOW' not in str(result)

import importlib

import pytest

from appliance.contracts import ApplianceError


def module(): return importlib.import_module('appliance.startup')


class NeverRunner:
    def run(self, *args, **kwargs): raise AssertionError('unexpected target command')


def test_no_router_receipt_reports_blocked_without_preventing_menu(site, tmp_path):
    result = module().start_local(site, NeverRunner(), state=tmp_path, timeout_s=1)
    assert result[0]['state'] == 'blocked'
    assert result[0]['capability'] == 'router'


def test_router_start_does_not_start_ordinary_guests(site, tmp_path, monkeypatch):
    startup = module()
    called = []
    monkeypatch.setattr(startup, 'start_owned', lambda plan, role, runner, state:
                        called.append(role) or {'running': True, 'boot_id': 'boot-one'})
    result = startup.start_local(site, NeverRunner(), state=tmp_path)
    assert called == ['router']
    assert result[0]['state'] == 'configured'
    assert result[0]['state'] != 'verified'


def test_role_start_reports_unprovisioned_role_without_enrolling(site, tmp_path, monkeypatch):
    site['roles']['connector']['selected'] = True
    from appliance import role_operations
    def not_ready(*args): raise ApplianceError('guest-not-provisioned')
    monkeypatch.setattr(role_operations, 'start_role', not_ready)
    result = module().start_roles(site, NeverRunner(), state=tmp_path)
    assert result == [{'role': 'connector', 'state': 'blocked', 'code': 'guest-not-provisioned',
                       'next_action': 'Inspect this role locally. Its identity has been retained.'}]

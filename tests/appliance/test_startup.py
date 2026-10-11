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


def test_role_start_refuses_unimplemented_enrollment(site, tmp_path):
    site['roles']['connector']['selected'] = True
    with pytest.raises(ApplianceError, match='role-provisioning-unavailable'):
        module().start_roles(site, NeverRunner(), state=tmp_path)

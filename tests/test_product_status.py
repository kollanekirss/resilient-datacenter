import importlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_status_keeps_dimensions_separate_and_missing_proof_untested():
    m=importlib.import_module('product_status')
    data={'network':{'state':'enrolled','controller_reachable':True},'applications':{'state':'service-listeners-verified'},
          'certificates':{'state':'certificate-valid','automatic_renewal':False},'backup':{'state':'backup-overdue','backup_age_seconds':999999},
          'recovery':{'state':'untested','user_operation':'not-recorded'},'partners':{'state':'partners-disabled'}}
    result=m.collect(probe=lambda name:data[name])
    assert result['dimensions']['backup']['state']=='backup-overdue'
    assert result['dimensions']['recovery']['state']=='untested'
    assert 'healthy' not in result and 'resilient' not in result
    assert result['dimensions']['applications']['user_operation']=='not-recorded'


def test_status_redacts_unexpected_fields_and_raw_errors():
    m=importlib.import_module('product_status')
    def probe(name):
        if name=='backup':raise PermissionError('secret-token-must-not-appear')
        return {'state':'enrolled','password':'secret-token-must-not-appear','next_step':'run untrusted command'}
    result=m.collect(probe=probe)
    raw=json.dumps(result)
    assert 'secret-token' not in raw and 'untrusted command' not in raw
    assert result['dimensions']['backup']['state']=='unknown'
    assert result['dimensions']['certificates']['state']=='unknown'  # A network state cannot stand in for a certificate check.


def test_failed_backup_preserves_last_success_without_claiming_current_storage():
    m=importlib.import_module('product_status')
    def probe(name):
        if name=='backup':return {'state':'backup-unreachable','last_success_at':'2026-09-25T10:00:00+00:00','last_attempt':'failed'}
        if name=='recovery':return {'state':'restore-pending','user_operation':'not-recorded'}
        return {'state':'unknown'}
    result=m.collect(probe=probe)
    assert result['dimensions']['backup']['last_success_at']=='2026-09-25T10:00:00+00:00'
    assert result['dimensions']['backup']['last_attempt']=='failed'
    assert result['dimensions']['recovery']['state']=='restore-pending'


def test_owned_discovery_rejects_partial_or_mixed_roles(tmp_path):
    m=importlib.import_module('status_probe')
    from test_gateway_backup import gateway_source
    store,owner=gateway_source(tmp_path/'root')
    found=m.discover(tmp_path/'root',require_root=False)
    assert found['package']=='gateway' and found['owner']==owner
    (store.base/'ownership.json').unlink()
    with pytest.raises(ValueError):m.discover(tmp_path/'root',require_root=False)


def test_status_cli_is_read_only_and_returns_attention_for_missing_evidence(monkeypatch,capsys):
    import rdc
    import product_status
    monkeypatch.setattr(product_status,'collect',lambda:{'dimensions':{name:{'state':'unknown','next_step':'Inspect locally.'} for name in product_status.DIMENSIONS}})
    assert rdc.main(['status','--json'])==3
    result=capsys.readouterr().out
    assert json.loads(result)['dimensions']['network']['state']=='unknown'


def test_discovery_rejects_links_mixed_packages_and_unowned_apps(tmp_path):
    import status_probe as m
    from test_gateway_backup import gateway_source
    root=tmp_path/'root';store,_=gateway_source(root)
    (root/'etc/rdc-nextcloud').mkdir()
    with pytest.raises(ValueError):m.discover(root,require_root=False)
    (root/'etc/rdc-nextcloud').rmdir()
    marker=root/'etc/server-connectivity-profile.json';raw=marker.read_bytes();marker.unlink()
    with pytest.raises(ValueError):m.discover(root,require_root=False)
    target=root/'network';target.write_bytes(raw);marker.symlink_to(target)
    with pytest.raises(ValueError):m.discover(root,require_root=False)


def test_no_roles_is_not_an_installed_healthy_node(tmp_path):
    import status_probe as m
    assert m.discover(tmp_path,require_root=False) is None


def test_application_readiness_absence_is_stopped_without_starting(monkeypatch):
    import status_probe as m
    import backup_scope
    from types import SimpleNamespace
    runtime=SimpleNamespace(UNITS={'app':'owned-app'},read_settings=lambda:{},inspect_container=lambda *a:None)
    monkeypatch.setattr(backup_scope,'application_runtime',lambda _:runtime)
    assert m.applications({'application':{'packages':['matrix']}})['state']=='stopped'


def test_backup_failure_retains_local_success_and_never_lists_other_scope(tmp_path,monkeypatch):
    import status_probe as m
    import backup_operations as operations
    import backup_schedule as schedule
    from types import SimpleNamespace
    (tmp_path/'last-attempt.json').write_text('{}')
    monkeypatch.setattr(operations,'BASE',tmp_path)
    owner={'test':'current'};calls=[]
    def snapshots(**kwargs):calls.append(kwargs);raise ValueError('private storage details')
    monkeypatch.setattr(operations,'configured',lambda:({'ownership':owner},SimpleNamespace(snapshots=snapshots)))
    monkeypatch.setattr(schedule,'read_private',lambda _:{'last_attempt':{'outcome':'failed'},'last_success':{'finished_at':'2026-09-25T10:00:00+00:00'}})
    result=m.backup({'owner':owner})
    assert result['state']=='backup-unreachable' and result['last_attempt']=='failed' and result['last_success_at']
    assert calls==[{'timeout':10}]
    assert m.backup({'owner':{'different':'scope'}})['state']=='backup-scope-missing'
    assert len(calls)==1


def test_certificate_renewal_failure_is_visible_even_with_saved_success(tmp_path,monkeypatch):
    import status_probe as m
    import service_issuer
    monkeypatch.setattr(service_issuer,'BASE',tmp_path)
    monkeypatch.setattr(service_issuer,'status',lambda:{'state':'renewal-failed','serving_verified':True,'automatic_renewal':True})
    assert m.certificates({'application':{},'package':'matrix'})['state']=='renewal-failed'


def test_partner_review_overrides_running_proxy(monkeypatch):
    import status_probe as m
    import gateway_operations
    monkeypatch.setattr(gateway_operations,'status',lambda:{'state':'gateway-recovery-review-required','proxy_running':True})
    assert m.partners({'application':{},'package':'gateway'})['state']=='partner-review-required'


def test_summary_worker_timeout_does_not_expose_exception_or_start_repair(monkeypatch):
    import product_status as m
    import subprocess
    def probe(_):raise subprocess.TimeoutExpired('private command',30)
    result=m.collect(probe=probe)
    assert all(item['state']=='unknown' for item in result['dimensions'].values())
    assert 'private command' not in json.dumps(result)


def test_portable_local_network_status_is_not_reported_as_enrollment():
    import product_status as m
    result=m.sanitize('network',{'state':'local-address-verified','controller_required':False})
    assert result['state']=='local-address-verified'
    assert result['controller_required'] is False
    assert 'local' in result['next_step'].lower()

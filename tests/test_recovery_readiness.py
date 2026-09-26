import importlib
import json
from pathlib import Path
import sys
from datetime import datetime,timezone
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_private_recovery import kit


def api():return importlib.import_module('recovery_readiness')


def test_report_missing_bundles_fails_closed_without_paths(tmp_path):
    result=api().report(tmp_path/'software','a'*64,tmp_path/'private','b'*64)
    assert result['state']=='blocked'
    assert result['checks']['software']['state']=='missing'
    assert result['checks']['private-material']['state']=='missing'
    assert str(tmp_path) not in json.dumps(result)


def test_all_recorded_evidence_never_becomes_live_readiness():
    result=api().summarize({'one':{'state':'verified'},'two':{'state':'recorded'}})
    assert result=='needs-exercise'


def test_invalid_evidence_blocks_even_if_others_pass():
    assert api().summarize({'one':{'state':'verified'},'two':{'state':'stale'}})=='blocked'


def test_references_must_be_in_verified_manifest_and_category(kit):
    from private_recovery_contract import inventory
    data=inventory(kit)
    with pytest.raises(ValueError):api().read(kit,data,'../elsewhere','tls')
    with pytest.raises(ValueError):api().read(kit,data,'operator/fixture','tls')
    assert api().read(kit,data,'tls/fixture','tls')==b'private synthetic material'
    (kit/'tls/fixture').write_bytes(b'changed')
    with pytest.raises(ValueError):api().read(kit,data,'tls/fixture','tls')


def test_readiness_schema_rejects_unknown_fields():
    data=api().example();data['execute']='curl somewhere'
    with pytest.raises(ValueError):api().settings(data)


@pytest.mark.parametrize('value',[True,0,-1,100000,'24'])
def test_policy_age_limits_are_explicit_integers(value):
    data=api().example();data['max_backup_age_hours']=value
    with pytest.raises(ValueError):api().settings(data)


def test_template_is_valid_and_has_all_required_tls_roles():
    result=api().settings(api().example())
    assert set(result['certificates'])=={'frontend-chat','frontend-element','frontend-files','backend-chat','backend-files'}


def test_private_bytes_are_checked_even_without_readiness_settings(kit,tmp_path):
    from private_recovery_contract import make_manifest,write_manifest
    trusted=write_manifest(kit,make_manifest(kit))
    result=api().report(tmp_path/'missing','a'*64,kit,trusted)
    assert result['checks']['private-material']['state']=='verified'
    assert result['checks']['readiness-settings']['state']=='missing'
    assert result['checks']['whole-site-acceptance']['state']=='not-tested'
    assert 'tallinn-kit' not in json.dumps(result)

from test_readiness_checks import certificates,plan,snapshot,NOW


@pytest.fixture
def prepared(kit,certificates):
    from private_recovery_contract import make_manifest,write_manifest
    m=api();config=m.example();p=plan()
    def write(name,raw):
        target=kit/name;target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        target.write_bytes(raw);target.chmod(0o600)
    write('configuration/site.json',json.dumps(p).encode())
    for role,item in config['certificates'].items():
        names=[p['domains'][role.split('-')[1]]]
        if role=='backend-chat':names.append(p['domains']['element'])
        cert,key,ca=certificates(hostname=names[0],names=names)
        for name,raw in [(item['certificate'],cert),(item['private_key'],key),(item['ca'],ca)]:write(name,raw)
    for role,item in config['backups'].items():
        write(item['metadata'],json.dumps(snapshot(role)).encode())
        for part in ('config','data/fixture','index/fixture','keys/fixture','snapshots/fixture'):write(item['repository']+'/'+part,b'synthetic encrypted repository layout')
    for name in config['access'].values():write(name,b'synthetic private instructions')
    write('operator/readiness.json',json.dumps(config).encode())
    def seal():
        (kit/'manifest.json').unlink(missing_ok=True)
        data=make_manifest(kit);data['captured_at']=NOW.isoformat()
        return write_manifest(kit,data)
    return kit,config,write,seal


def test_report_actual_private_evidence_is_read_only_and_redacted(prepared,tmp_path,monkeypatch):
    import socket,subprocess
    from offline_bundle import file_names,digest
    root,config,write,seal=prepared;trusted=seal()
    before={n:digest(root,n) for n in file_names(root)}
    monkeypatch.setattr(socket,'socket',lambda *a,**k:pytest.fail('no network allowed'))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('no subprocess allowed'))
    result=api().report(tmp_path/'absent','a'*64,root,trusted,now=NOW)
    assert all(result['checks']['certificate-'+r]['state']=='verified' for r in api().TLS_ROLES)
    assert result['checks']['backup-chat']['state']=='recorded'
    assert result['checks']['backup-copy-files']['state']=='recorded'
    assert result['checks']['exercise-site']['state']=='not-tested'
    assert {n:digest(root,n) for n in file_names(root)}==before
    text=json.dumps(result)
    for secret in (str(root),'south.test','tallinn-kit','synthetic private instructions','PRIVATE KEY'):
        assert secret not in text


@pytest.mark.parametrize('bad',['tampered','wrong-hash','future-capture'])
def test_unverified_material_never_drives_certificate_checks(prepared,tmp_path,bad):
    root,config,write,seal=prepared;trusted=seal()
    if bad=='tampered':write('tls/frontend-chat.crt',b'tampered')
    if bad=='wrong-hash':trusted='a'*64
    now=NOW if bad!='future-capture' else NOW.replace(year=2025)
    result=api().report(tmp_path/'absent','a'*64,root,trusted,now=now)
    assert result['checks']['private-material']['state']=='invalid'
    assert 'certificate-frontend-chat' not in result['checks']


def test_recorded_exercise_cannot_predate_snapshot(prepared,tmp_path):
    from portable_network import fingerprint
    import hashlib
    root,config,write,seal=prepared
    config['exercises']['chat']='operator/chat-restore.json'
    record={'schema_version':1,'site_sha256':fingerprint(plan()),'role':'chat',
        'backup_metadata_sha256':hashlib.sha256((root/config['backups']['chat']['metadata']).read_bytes()).hexdigest(),
        'performed_at':'2026-09-25T00:00:00+00:00','result':'pass'}
    write('operator/chat-restore.json',json.dumps(record).encode());write('operator/readiness.json',json.dumps(config).encode())
    result=api().report(tmp_path/'absent','a'*64,root,seal(),now=NOW)
    assert result['checks']['exercise-chat']['state']=='invalid'


def test_cli_never_exits_success_for_unproven_complete_site(monkeypatch,capsys,tmp_path):
    m=api();monkeypatch.setattr(m,'report',lambda *a:{'state':'needs-exercise','assessed_at':NOW.isoformat(),'checks':{},'notice':'not proven'})
    args=['--software-dir',str(tmp_path),'--software-sha256','a'*64,'--private-dir',str(tmp_path),'--private-sha256','b'*64,'--json']
    assert m.main(args)==2
    assert json.loads(capsys.readouterr().out)['state']=='needs-exercise'


def test_deeply_nested_settings_are_invalid_evidence(prepared,tmp_path):
    root,config,write,seal=prepared
    write('operator/readiness.json',b'['*20000+b']'*20000)
    result=api().report(tmp_path/'absent','a'*64,root,seal(),now=NOW)
    assert result['checks']['readiness-settings']['state']=='invalid'


def test_deeply_nested_snapshot_does_not_abort_other_checks(prepared,tmp_path):
    root,config,write,seal=prepared
    write(config['backups']['chat']['metadata'],b'['*20000+b']'*20000)
    result=api().report(tmp_path/'absent','a'*64,root,seal(),now=NOW)
    assert result['checks']['backup-chat']['state']=='invalid'
    assert result['checks']['backup-files']['state']=='recorded'

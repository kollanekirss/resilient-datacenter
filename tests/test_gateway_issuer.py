import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
import pytest
from test_gateway_store import fixture
from test_regional_agreements import pair


def profile(identity):
    from regional_agreements import fingerprint
    own=identity['payload']
    return {'kind':'gateway-certificates','schema_version':1,'provider':'cloudflare',
            'institution_id':own['institution_id'],'node_name':own['gateway_node'],
            'gateway_fingerprint':fingerprint(identity),
            **{name+'_hostname':domain for name,domain in own['services'].items()},
            'acme_email':'operator@example.test','acme_agree_terms':True}


def test_gateway_issuer_accepts_only_declared_application_names_and_fingerprint():
    m=importlib.import_module('service_issuer_contracts');_,_,own,_=pair();data=profile(own)
    assert m.validate(data)==[]
    assert m.issue_command(data).count('-d')==2
    single=dict(data);single.pop('nextcloud_hostname')
    assert m.validate(single)==[] and m.issue_command(single).count('-d')==1
    for changes in ({'gateway_fingerprint':'wrong'},{'element_hostname':'chat.test'},{'nextcloud_hostname':data['matrix_hostname']}, {'command':'custom'}):
        assert m.validate(dict(data,**changes))
    empty={k:v for k,v in data.items() if k not in ('matrix_hostname','nextcloud_hostname')}
    assert m.validate(empty)


def test_gateway_issuer_matches_the_installed_signed_identity(tmp_path,monkeypatch):
    m=importlib.import_module('service_issuer');gateway=importlib.import_module('gateway_runtime')
    store,_=fixture(tmp_path);monkeypatch.setattr(gateway,'BASE',store.base)
    monkeypatch.setattr(gateway,'verify_runtime',lambda:None)
    data=profile(store.identity())
    assert m.matching_application(data).identity()==store.identity()
    for changes in ({'gateway_fingerprint':'a'*64},{'matrix_hostname':'other.test'},{'node_name':'other'}):
        with pytest.raises(ValueError):m.matching_application(dict(data,**changes))
    reduced=dict(data);reduced.pop('nextcloud_hostname')
    with pytest.raises(ValueError):m.matching_application(reduced)


def test_gateway_issuer_wizard_derives_names_from_public_identity(tmp_path):
    m=importlib.import_module('service_issuer_setup');_,_,own,_=pair();answers=iter(['operator@example.test','AGREE']);target=tmp_path/'issuer.json'
    result=m.wizard(target,package='gateway',identity=own,input_fn=lambda _:next(answers),output_fn=lambda _:None)
    assert result['state']=='prepared' and json.loads(target.read_text())==profile(own)


def test_frozen_issuer_has_gateway_activation_dependencies(tmp_path):
    m=importlib.import_module('service_issuer');source=Path(m.__file__).parent
    for name in m.FILES:shutil.copyfile(source/name,tmp_path/name)
    command=[sys.executable,'-I','-c','import sys;sys.path.insert(0,sys.argv[1]);import service_issuer;import gateway_runtime;import gateway_certificates',str(tmp_path)]
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    (tmp_path/'gateway_store.py').unlink()
    assert subprocess.run(command,capture_output=True).returncode!=0


def test_gateway_issuer_cli_requires_public_identity_only_for_setup():
    from rdc import parser
    args=parser().parse_args(['gateway','issuer','setup','--identity','own.json','--output-file','request.json'])
    assert args.certificate_package=='gateway' and str(args.identity)=='own.json'
    assert parser().parse_args(['gateway','issuer','enable']).issuer_action=='enable'
    args=parser().parse_args(['gateway','issuer','issue','request.json','--token-file','/root/dns-token'])
    assert str(args.token_file)=='/root/dns-token'


def test_gateway_issuer_holds_backup_then_gateway_lock(tmp_path,monkeypatch):
    import fcntl
    m=importlib.import_module('service_issuer');gateway=importlib.import_module('gateway_runtime')
    store,_=fixture(tmp_path);monkeypatch.setattr(gateway,'BASE',store.base)
    backup=tmp_path/'backup';backup.mkdir();restore=tmp_path/'restore-pending'
    def local_path(value):
        if value=='/etc/rdc-backup':return backup
        if value=='/etc/rdc-backup/operation.lock':return backup/'operation.lock'
        if value=='/etc/rdc-restore-pending.json':return restore
        if value=='/run/rdc-gateway-certificate-setup.lock':return tmp_path/'issuer.lock'
        raise AssertionError('Unexpected issuer path '+str(value))
    monkeypatch.setattr(m,'Path',local_path)
    with m.operation_lock(profile(store.identity())):
        with pytest.raises(BlockingIOError):
            with store.lock():pass
        with (backup/'operation.lock').open('a') as another:
            with pytest.raises(BlockingIOError):fcntl.flock(another,fcntl.LOCK_EX|fcntl.LOCK_NB)
    restore.write_text('{}')
    with pytest.raises(ValueError,match='pending restore'):
        with m.operation_lock(profile(store.identity())):pass

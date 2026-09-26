import importlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('offline_applications')


@pytest.fixture
def local(monkeypatch):
    m=api();monkeypatch.setattr(m,'platform_errors',lambda:[])
    monkeypatch.setattr(m,'executable',lambda path:True)
    def inspect(name,settings):return None
    monkeypatch.setattr(m,'verify_image',inspect)
    return m


@pytest.mark.parametrize('role',['chat','files'])
def test_prepared_is_software_only(local,role):
    result=local.check(role)
    assert result['state']=='application-software-prepared'
    assert result['recovery']=='not-tested'
    assert result['application_operations']=='not-tested'
    assert result['certificates']=='not-tested'
    assert all(c['status']=='verified' for c in result['checks'])


def test_unsupported_machine_never_inspects_images(local,monkeypatch):
    monkeypatch.setattr(local,'platform_errors',lambda:['Ubuntu 24.04 amd64 is required'])
    monkeypatch.setattr(local,'verify_image',lambda *a:pytest.fail('must not execute server software'))
    assert local.check('chat')['state']=='application-software-blocked'


def test_missing_podman_does_not_execute_it(local,monkeypatch):
    monkeypatch.setattr(local,'executable',lambda path:path!='/usr/bin/podman')
    monkeypatch.setattr(local,'verify_image',lambda *a:pytest.fail('missing executable'))
    assert local.check('files')['state']=='application-software-blocked'


@pytest.mark.parametrize('error',[ValueError('wrong identity'),subprocess.CalledProcessError(1,['podman'],stderr='SECRET'),subprocess.TimeoutExpired('podman',20),json.JSONDecodeError('bad','',0),KeyError('SECRET'),TypeError('bad')])
def test_failed_inspection_blocks_without_leaking_runtime_details(local,monkeypatch,error):
    def fail(*a):raise error
    monkeypatch.setattr(local,'verify_image',fail)
    result=local.check('chat')
    assert result['state']=='application-software-blocked'
    assert 'SECRET' not in json.dumps(result)
    with pytest.raises(ValueError,match='Offline software'):local.require('chat')


@pytest.mark.parametrize('role',['invalid','frontend','matrix'])
def test_role_is_exact(local,role):
    with pytest.raises(ValueError):local.check(role)


@pytest.mark.parametrize('code',[1,125])
def test_offline_image_acquisition_never_pulls(monkeypatch,code):
    import service_operations as m
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        assert argv[1:4]==['--remote=false','image','exists']
        return SimpleNamespace(returncode=code)
    monkeypatch.setattr(m.subprocess,'run',run)
    with pytest.raises(ValueError):m.pull_images({'x':{'image':'pinned'}},offline=True)
    assert len(calls)==1


@pytest.mark.parametrize('module,role,extra',[('service_operations','chat',()),('nextcloud_operations','files',('user','password'))])
def test_low_level_offline_installer_blocks_before_tls_or_mutation(monkeypatch,module,role,extra):
    m=importlib.import_module(module);off=api()
    monkeypatch.setattr(m,'require_platform',lambda:None)
    seen=[]
    def block(found):seen.append(found);raise ValueError('Offline software is incomplete')
    monkeypatch.setattr(off,'require',block)
    monkeypatch.setattr(m,'ownership',lambda *a:pytest.fail('must gate before ownership/tls work'))
    with pytest.raises(ValueError,match='Offline software'):
        m.install_or_resume({}, {}, '10.1.1.1',*extra,offline=True)
    assert seen==[role]


@pytest.mark.parametrize('role',['chat','files'])
def test_portable_wrapper_checks_before_creating_identity(monkeypatch,role):
    import portable_application_install as m
    monkeypatch.setattr(m,'require_platform',lambda:None)
    def block(found):assert found==role;raise ValueError('Offline software missing')
    monkeypatch.setattr(api(),'require',block)
    monkeypatch.setattr(m,'profiles',lambda *a:pytest.fail('must fail before identity preparation'))
    with pytest.raises(ValueError,match='Offline software'):m.backend({},role,offline=True)


def test_read_only_cli_reports_blocked_exit(monkeypatch,capsys):
    import rdc
    monkeypatch.setattr(api(),'check',lambda role:{'state':'application-software-blocked','checks':[]})
    plan=Path(__file__).resolve().parents[1]/'examples/portable-site.json'
    assert rdc.main(['portable','applications-check',str(plan),'--role','chat','--json'])!=0
    assert 'application-software-blocked' in capsys.readouterr().out


def test_offline_flag_cannot_be_silently_ignored(capsys):
    import rdc
    plan=Path(__file__).resolve().parents[1]/'examples/portable-site.json'
    assert rdc.main(['portable','preview',str(plan),'--offline','--json'])!=0
    assert 'offline' in capsys.readouterr().out.lower()


@pytest.mark.parametrize('role',['chat','files'])
def test_actual_image_identity_validation_is_used(local,monkeypatch,role):
    import service_runtime
    monkeypatch.setattr(local,'verify_image',service_runtime.verify_image)
    monkeypatch.setattr(service_runtime,'podman',lambda *a:json.dumps([{'Architecture':'amd64','Os':'linux','Id':'sha256:'+'0'*64}]))
    assert local.check(role)['state']=='application-software-blocked'


@pytest.mark.parametrize('variable',['CONTAINER_HOST','CONTAINER_CONNECTION'])
def test_remote_podman_environment_cannot_pass(monkeypatch,variable):
    m=api()
    monkeypatch.setenv(variable,'ssh://not-a-local-image-store')
    monkeypatch.setattr(m.platform,'system',lambda:'Linux')
    monkeypatch.setattr(m.platform,'machine',lambda:'x86_64')
    monkeypatch.setattr(m.platform,'freedesktop_os_release',lambda:{'ID':'ubuntu','VERSION_ID':'24.04'})
    monkeypatch.setattr(m.Path,'is_dir',lambda self:True)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    assert any('remote' in error.lower() for error in m.platform_errors())


def test_remote_default_cannot_make_remote_images_look_locally_prepared(local,monkeypatch):
    import service_runtime
    from service_contracts import image_pins
    pins=image_pins()
    monkeypatch.setattr(local,'verify_image',service_runtime.verify_image)
    def remote_default(argv,**kwargs):
        # Simulate a containers.conf remote default with an empty local store.
        if '--remote=false' in argv:raise subprocess.CalledProcessError(1,argv)
        pin=next(p for p in pins.values() if p['image']==argv[-1])
        return SimpleNamespace(stdout=json.dumps([{'Architecture':'amd64','Os':'linux','Id':pin['config_digest']}]))
    monkeypatch.setattr(service_runtime.subprocess,'run',remote_default)
    assert local.check('chat')['state']=='application-software-blocked'

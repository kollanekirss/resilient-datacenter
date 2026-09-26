import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('offline_bundle_install')


def test_bootstrap_checks_platform_before_mutation(monkeypatch,tmp_path):
    m=api();monkeypatch.setattr(m.platform,'system',lambda:'Darwin')
    monkeypatch.setattr(m,'run',lambda *a,**k:pytest.fail('unsupported machine cannot run commands'))
    with pytest.raises(ValueError):m.bootstrap(tmp_path/'missing','a'*64)


def test_apt_install_has_no_sources_no_download_and_no_network_namespace(tmp_path):
    args=api().package_command(tmp_path,[tmp_path/'one.deb'])
    text=' '.join(map(str,args))
    assert args[:3]==['/usr/bin/unshare','--net','--']
    assert '--no-download' in args and '--no-remove' in args
    assert 'Dir::Etc::sourceparts=-' in text
    assert 'Dir::Etc::sourcelist=/dev/null' in text


def test_partial_or_minimal_manifest_cannot_be_bootstrapped():
    with pytest.raises(ValueError):api().closure({'files':{},'images':{}})


def test_autostart_guard_is_removed_after_failure(tmp_path):
    m=api();path=tmp_path/'policy-rc.d'
    with pytest.raises(RuntimeError):
        with m.no_autostart(path):
            assert path.read_text().endswith('exit 101\n')
            raise RuntimeError('failed package install')
    assert not path.exists()


def test_foreign_autostart_policy_is_never_overwritten(tmp_path):
    path=tmp_path/'policy-rc.d';path.write_text('existing policy')
    with pytest.raises(ValueError):
        with api().no_autostart(path):pass
    assert path.read_text()=='existing policy'


def test_image_import_cannot_select_remote_transport(tmp_path,monkeypatch):
    m=api();calls=[]
    pin={'reference':'docker.io/test/image@sha256:'+'a'*64,'path':'images/'+'a'*64,'config_digest':'sha256:'+'b'*64}
    def run(args,**kwargs):
        calls.append([str(x) for x in args])
        if 'inspect' in args:return '[{"Id":"sha256:'+('b'*64)+'","Architecture":"amd64","Os":"linux"}]'
        return ''
    monkeypatch.setattr(m,'run',run)
    m.import_images(tmp_path,{'a'*64:pin})
    assert calls[0][-2:] == ['dir:'+str(tmp_path/pin['path']),'containers-storage:'+pin['reference']]
    assert calls[1][1]=='--remote=false'


def test_offline_vm_disables_implicit_uplink():
    import ci_home_vm
    command=ci_home_vm.qemu_command('/tmp/guest',22222,offline=True)
    net=command[command.index('-netdev')+1]
    assert 'restrict=on' in net
    assert 'hostfwd=tcp:127.0.0.1:22222-:22' in net


def test_prepared_retry_does_not_reinstall_packages(monkeypatch,tmp_path):
    import json
    m=api();base=tmp_path/'state';base.mkdir(mode=0o700);installed=tmp_path/'installed'
    trusted='a'*64;data={'source_commit':'b'*40,'images':{},'files':{}}
    (base/'installation.json').write_text(json.dumps({'identity':{'manifest_sha256':trusted,'source_commit':'b'*40},'state':'prepared'}))
    monkeypatch.setattr(m,'BASE',base);monkeypatch.setattr(m,'INSTALL',installed)
    monkeypatch.setattr(m,'supported',lambda:None);monkeypatch.setattr(m,'verify',lambda *a:data)
    monkeypatch.setattr(m,'closure',lambda *a:None);monkeypatch.setattr(m,'stage',lambda *a:tmp_path)
    monkeypatch.setattr(m,'source_copy',lambda *a,**k:None)
    monkeypatch.setattr(m,'verify_prepared',lambda *a:None)
    monkeypatch.setattr(m,'run',lambda *a,**k:pytest.fail('prepared retry must not install'))
    assert m.bootstrap(tmp_path,trusted)['state']=='role-software-prepared'


def test_interrupted_source_copy_can_resume_without_partial_final_file(monkeypatch,tmp_path):
    import hashlib
    m=api();source=tmp_path/'kit';(source/'source').mkdir(parents=True);(source/'source/rdc').write_bytes(b'complete source')
    installed=tmp_path/'installed';monkeypatch.setattr(m,'INSTALL',installed)
    data={'files':{'source/rdc':{'size':15,'sha256':hashlib.sha256(b'complete source').hexdigest()}}}
    original=m.shutil.copyfileobj
    def fail(src,dst,*a):dst.write(b'partial');raise OSError('disk interrupted')
    monkeypatch.setattr(m.shutil,'copyfileobj',fail)
    with pytest.raises(OSError):m.source_copy(source,data)
    assert not (installed/'source/rdc').exists()
    monkeypatch.setattr(m.shutil,'copyfileobj',original)
    m.source_copy(source,data)
    assert (installed/'source/rdc').read_bytes()==b'complete source'


def test_failed_bootstrap_command_reports_bounded_cause(monkeypatch):
    m=api()
    def fail(*args,**kwargs):
        raise m.subprocess.CalledProcessError(100,args[0],output='x'*10000+' dependency conflict',stderr='E: package installation refused')
    monkeypatch.setattr(m.subprocess,'run',fail)
    with pytest.raises(ValueError,match='package installation refused') as error:
        m.run(['/usr/bin/unshare','--net','--','apt-get'])
    assert 'dependency conflict' in str(error.value)
    assert len(str(error.value))<9000


def test_package_plan_allows_only_default_time_service_replacement():
    m=api()
    assert m.check_package_plan('Inst chrony (4.5 Ubuntu)\nRemv systemd-timesyncd [255.4]\nConf chrony (4.5 Ubuntu)\n') == {'systemd-timesyncd'}
    for unsafe in ('Remv ubuntu-server [1]\n', 'Remv openssh-server [1]\n', 'Inst libc6 [2.39] (2.40 Ubuntu)\n', 'Remv\n'):
        with pytest.raises(ValueError):m.check_package_plan(unsafe)


def test_package_command_preserves_installed_dependencies(tmp_path):
    args=api().package_command(tmp_path,[tmp_path/'one.deb'])
    assert '--no-upgrade' in args
    assert '--no-remove' in args
    args=api().package_command(tmp_path,[tmp_path/'one.deb'],allow_time_replacement=True)
    assert '--no-upgrade' in args and '--no-remove' not in args

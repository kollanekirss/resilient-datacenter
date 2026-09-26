import importlib
import json
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
ROOT=Path(__file__).resolve().parents[1]


def api():return importlib.import_module('private_recovery_contract')


@pytest.fixture
def kit(tmp_path):
    root=tmp_path/'input';root.mkdir(mode=0o700)
    for category in ('configuration','edge','trust','tls','backup-access','application-backups','operator'):
        folder=root/category;folder.mkdir(mode=0o700)
        (folder/'fixture').write_bytes(b'private synthetic material');(folder/'fixture').chmod(0o600)
    for name,source in [('site.json','portable-site.json'),('network.json','portable-network.json')]:
        path=root/'configuration'/name;path.write_bytes((ROOT/'examples'/source).read_bytes());path.chmod(0o600)
    return root


def test_private_inventory_checks_configuration_and_hashes(kit):
    data=api().inventory(kit)
    assert len(data)==9
    assert data['tls/fixture']['size']==26


@pytest.mark.parametrize('issue',['symlink','fifo','public-file','public-dir','missing-category','unknown-category','bad-site','duplicate-json'])
def test_private_inventory_rejects_unsafe_or_incomplete_material(kit,issue):
    if issue=='symlink':(kit/'tls/link').symlink_to('/etc/passwd')
    if issue=='fifo':os.mkfifo(kit/'tls/pipe',0o600)
    if issue=='public-file':(kit/'tls/fixture').chmod(0o644)
    if issue=='public-dir':(kit/'tls').chmod(0o755)
    if issue=='missing-category':(kit/'tls/fixture').unlink()
    if issue=='unknown-category':(kit/'surprise').write_text('secret')
    if issue=='bad-site':(kit/'configuration/site.json').write_text('{}')
    if issue=='duplicate-json':(kit/'configuration/site.json').write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):api().inventory(kit)


def test_private_manifest_roundtrip_and_mutation(kit):
    m=api();expected=m.make_manifest(kit)
    digest=m.write_manifest(kit,expected)
    assert m.verify(kit,digest)==expected
    (kit/'tls/fixture').write_bytes(b'changed')
    with pytest.raises(ValueError):m.verify(kit,digest)


def test_private_manifest_requires_independent_hash(kit):
    m=api();m.write_manifest(kit,m.make_manifest(kit))
    with pytest.raises(ValueError):m.verify(kit,'a'*64)


def test_tree_rejects_linked_parent(kit):
    link=kit.parent/'linked';link.symlink_to(kit)
    with pytest.raises(ValueError):api().inventory(link/'tls'/ '..')


def test_private_manifest_rejects_unexpected_restored_file(kit):
    m=api();digest=m.write_manifest(kit,m.make_manifest(kit))
    extra=kit/'tls/extra';extra.write_text('secret');extra.chmod(0o600)
    with pytest.raises(ValueError):m.verify(kit,digest)


def package():return importlib.import_module('private_recovery_package')


def test_private_operations_refuse_workstation_before_writes(monkeypatch,tmp_path):
    m=package();monkeypatch.setattr(m.platform,'system',lambda:'Darwin')
    with pytest.raises(ValueError):m.supported()
    assert list(tmp_path.iterdir())==[]


def test_local_command_has_no_ambient_credentials(monkeypatch,tmp_path):
    m=package();seen={}
    def run(args,**kwargs):
        seen.update(args=args,kwargs=kwargs)
        kwargs['stdout'].write(b'{}');return type('Result',(),{'returncode':0})()
    monkeypatch.setattr(m.subprocess,'run',run)
    monkeypatch.setenv('RESTIC_REPOSITORY','sftp:outside:/secret')
    monkeypatch.setenv('RESTIC_PASSWORD','do not inherit')
    m.execute(tmp_path/'tool',tmp_path/'repo',tmp_path/'password',['check','--read-data'])
    assert 'RESTIC_PASSWORD' not in seen['kwargs']['env']
    assert 'RESTIC_REPOSITORY' not in seen['kwargs']['env']
    assert seen['args'][1:5]==['--repo',str(tmp_path/'repo'),'--password-file',str(tmp_path/'password')]
    assert seen['kwargs']['stdin']==m.subprocess.DEVNULL


def test_failed_command_does_not_print_private_output(monkeypatch,tmp_path):
    m=package()
    def fail(args,**kwargs):
        kwargs['stdout'].write(b'SECRET');return type('Result',(),{'returncode':1})()
    monkeypatch.setattr(m.subprocess,'run',fail)
    with pytest.raises(ValueError) as error:m.execute(tmp_path/'tool',tmp_path/'repo',tmp_path/'password',['check'])
    assert 'SECRET' not in str(error.value)


def test_password_cannot_be_captured_in_package(kit):
    m=package()
    with pytest.raises(ValueError):m.credentials(kit/'tls/fixture',[kit])


def test_new_destination_refuses_existing_or_nested_input(kit):
    m=package()
    with pytest.raises(ValueError):m.destination(kit,[kit])
    with pytest.raises(ValueError):m.destination(kit/'new',[kit])


def test_copy_uses_private_files_and_verifies_contents(kit,tmp_path):
    m=package();data=api().make_manifest(kit)
    target=tmp_path/'copy';m.copy_material(kit,target,data)
    assert api().inventory(target)==data['files']
    assert (target/'tls/fixture').stat().st_mode & 0o077 == 0


def test_repository_rejects_symlinks_before_restic(tmp_path):
    root=tmp_path/'repo';root.mkdir(mode=0o700)
    (root/'data').symlink_to('/tmp')
    with pytest.raises(ValueError):package().repository(root)


def test_unreadable_subtree_cannot_silently_disappear(kit,monkeypatch):
    m=api();hidden=kit/'tls'/'unreadable';hidden.mkdir(mode=0o700)
    path=hidden/'essential.key';path.write_text('private key');path.chmod(0o600)
    original=os.scandir
    def fail(path):
        if Path(path)==hidden:raise PermissionError('simulated unreadable recovery directory')
        return original(path)
    monkeypatch.setattr(os,'scandir',fail)
    with pytest.raises(ValueError):m.inventory(kit)


def test_response_capture_stays_on_private_work_storage(monkeypatch,tmp_path):
    m=package();original=m.tempfile.TemporaryFile;seen=[]
    def capture(*args,**kwargs):seen.append(kwargs.get('dir'));return original(*args,**kwargs)
    monkeypatch.setattr(m.tempfile,'TemporaryFile',capture)
    monkeypatch.setattr(m.subprocess,'run',lambda *a,**k:type('Result',(),{'returncode':0})())
    m.execute(tmp_path/'tool',tmp_path/'repo',tmp_path/'password',['check'])
    assert seen==[tmp_path]


def test_package_requires_consistent_root_recovery_identity(monkeypatch):
    m=package();monkeypatch.setattr(m.platform,'system',lambda:'Linux')
    monkeypatch.setattr(m.platform,'machine',lambda:'x86_64')
    monkeypatch.setattr(m.os,'geteuid',lambda:1000)
    monkeypatch.setattr(m.platform,'freedesktop_os_release',lambda:{'ID':'ubuntu','VERSION_ID':'24.04'})
    with pytest.raises(ValueError):m.supported()

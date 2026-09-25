import importlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('backup_snapshot')

class Services:
    def __init__(self,active=('headscale',),fail_stop=False,fail_start=False):
        self.active=set(active);self.events=[];self.fail_stop=fail_stop;self.fail_start=fail_start
    def is_active(self,name): return name in self.active
    def stop(self,name):
        self.events.append(('stop',name))
        if self.fail_stop: raise OSError('stop failed')
        self.active.discard(name)
    def start(self,name):
        self.events.append(('start',name))
        if self.fail_start: raise OSError('restart failed')
        self.active.add(name)


def source(tmp_path):
    root=tmp_path/'source';(root/'var/lib/headscale').mkdir(parents=True)
    (root/'etc/headscale').mkdir(parents=True)
    (root/'var/lib/headscale/db.sqlite').write_bytes(b'database')
    (root/'usr/bin').mkdir(parents=True)
    (root/'usr/bin/headscale').write_bytes(b'pinned controller')
    (root/'etc/headscale/key').write_bytes(b'private-key')
    (root/'etc/server-connectivity-profile.json').write_text(json.dumps({'role':'controller'}))
    return root


def test_consistent_snapshot_restarts_before_return_and_is_private(tmp_path):
    root=source(tmp_path);services=Services()
    stage=tmp_path/'stage'
    api().capture(root,stage,{'role':'controller'},services=services)
    assert services.events==[('stop','headscale'),('start','headscale')]
    assert stage.stat().st_mode & 0o777==0o700
    assert (stage/'data/var/lib/headscale/db.sqlite').read_bytes()==b'database'
    assert json.loads((stage/'snapshot.json').read_text())['schema_version']==1


def test_failed_copy_restarts_service_and_removes_partial_snapshot(tmp_path,monkeypatch):
    root=source(tmp_path);services=Services();stage=tmp_path/'stage'
    def failed(*args,**kwargs): raise OSError('disk failed')
    monkeypatch.setattr(api(),'copy_resource',failed)
    with pytest.raises(OSError): api().capture(root,stage,{'role':'controller'},services=services)
    assert services.events==[('stop','headscale'),('start','headscale')]
    assert not stage.exists()


def test_stopped_service_stays_stopped_after_backup(tmp_path):
    root=source(tmp_path);services=Services(active=())
    api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert services.events==[]


def test_missing_required_identity_blocks_before_stopping(tmp_path):
    root=source(tmp_path);(root/'etc/server-connectivity-profile.json').unlink();services=Services()
    with pytest.raises(ValueError): api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert services.events==[]


def test_restart_failure_is_not_a_successful_backup(tmp_path):
    root=source(tmp_path);services=Services(fail_start=True)
    with pytest.raises(api().ServiceRecoveryError): api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert not (tmp_path/'stage').exists()


def test_stop_failure_still_attempts_recovery_and_no_snapshot(tmp_path):
    root=source(tmp_path);services=Services(fail_stop=True)
    with pytest.raises(OSError): api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert ('start','headscale') in services.events and not (tmp_path/'stage').exists()


def test_existing_destination_and_external_symlinks_are_refused(tmp_path):
    root=source(tmp_path); services=Services()
    (root/'etc/headscale/escape').symlink_to('/etc/shadow')
    with pytest.raises(ValueError): api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert not services.events


def test_owner_mismatch_blocks_before_service_changes(tmp_path):
    root=source(tmp_path);services=Services()
    with pytest.raises(ValueError): api().capture(root,tmp_path/'stage',{'role':'controller','institution_id':'different'},services=services)
    assert services.events==[]


def test_insufficient_staging_space_blocks_before_service_changes(tmp_path,monkeypatch):
    root=source(tmp_path);services=Services()
    from collections import namedtuple
    usage=namedtuple('usage','total used free')
    monkeypatch.setattr(api().shutil,'disk_usage',lambda _:usage(100,100,0))
    with pytest.raises(ValueError): api().capture(root,tmp_path/'stage',{'role':'controller'},services=services)
    assert services.events==[]

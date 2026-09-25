import importlib
import json
from pathlib import Path
import sys
import pytest
from test_setup_contracts import manifest
from setup_contracts import local_ownership
from backup_snapshot import capture
from test_backup_snapshot import Services
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('restore_transaction')

class Runtime:
    def __init__(self,fail=False): self.events=[];self.fail=fail;self.active=True
    def is_active(self,name): return self.active
    def stop(self,name): self.events.append('stop');self.active=False
    def start(self,name): self.events.append('start');self.active=True
    def isolate(self,owner): self.events.append('isolate')
    def allow_validation(self): self.events.append('validation')
    def finish_validation(self): self.events.append('validation-ended')
    def release(self): self.events.append('release')
    def verify(self,owner):
        self.events.append('verify')
        if self.fail: self.fail=False;raise ValueError('service failed')


def fixture(tmp_path):
    owner=local_ownership(manifest())
    def make(name,state):
        root=tmp_path/name;(root/'etc').mkdir(parents=True);(root/'var/lib/tailscale').mkdir(parents=True);(root/'usr/local/bin').mkdir(parents=True)
        (root/'etc/server-connectivity-profile.json').write_text(json.dumps(owner))
        (root/'var/lib/tailscale/tailscaled.state').write_text(state)
        for relative in ('usr/local/bin/tailscale','usr/local/sbin/tailscaled'):
            (root/relative).parent.mkdir(parents=True,exist_ok=True);(root/relative).write_bytes(b'pinned')
        return root
    source=make('source','saved identity');target=make('target','current identity')
    stage=tmp_path/'stage';capture(source,stage,owner,services=Services(active=()))
    return owner,target,stage


def test_success_restores_owned_data_under_isolation(tmp_path):
    owner,root,stage=fixture(tmp_path);runtime=Runtime()
    result=api().apply(stage,owner,root=root,runtime=runtime,permissions=lambda *a:None)
    assert result['state']=='restored-service-verified'
    assert (root/'var/lib/tailscale/tailscaled.state').read_text()=='saved identity'
    assert runtime.events.index('isolate')<runtime.events.index('start')<runtime.events.index('verify')<runtime.events.index('release')
    assert not (root/'etc/rdc-restore-pending.json').exists()


def test_failed_service_reverts_data_before_releasing_isolation(tmp_path):
    owner,root,stage=fixture(tmp_path);runtime=Runtime(fail=True)
    with pytest.raises(api().RestoreError) as error: api().apply(stage,owner,root=root,runtime=runtime,permissions=lambda *a:None)
    assert error.value.recovered is True
    assert (root/'var/lib/tailscale/tailscaled.state').read_text()=='current identity'
    assert runtime.events.count('verify')==2 and runtime.events[-1]=='release'
    assert not (root/'etc/rdc-restore-pending.json').exists()


def test_component_change_or_pending_transaction_blocks_before_isolation(tmp_path):
    owner,root,stage=fixture(tmp_path);runtime=Runtime()
    (root/'usr/local/sbin/tailscaled').write_text('different binary')
    with pytest.raises(ValueError): api().apply(stage,owner,root=root,runtime=runtime,permissions=lambda *a:None)
    assert runtime.events==[]


def test_interruption_leaves_guard_and_can_be_rolled_back(tmp_path):
    owner,root,stage=fixture(tmp_path)
    class Interrupted(Runtime):
        def verify(self,owner): raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt): api().apply(stage,owner,root=root,runtime=Interrupted(),permissions=lambda *a:None)
    assert (root/'etc/rdc-restore-pending.json').exists()
    runtime=Runtime()
    result=api().recover(owner,root=root,runtime=runtime)
    assert result['state']=='previous-data-restored'
    assert (root/'var/lib/tailscale/tailscaled.state').read_text()=='current identity'


def test_release_failure_retains_committed_journal_and_never_rolls_back(tmp_path):
    owner,root,stage=fixture(tmp_path)
    class InterruptedRelease(Runtime):
        def release(self): raise ValueError('firewall unavailable')
    with pytest.raises(api().RestoreError) as error:
        api().apply(stage,owner,root=root,runtime=InterruptedRelease(),permissions=lambda *a:None)
    assert error.value.committed is True
    (root/'var/lib/tailscale/tailscaled.state').write_text('new client writes')
    api().recover(owner,root=root,runtime=Runtime())
    assert (root/'var/lib/tailscale/tailscaled.state').read_text()=='new client writes'


def test_isolation_failure_never_restarts_service_or_replaces_data(tmp_path):
    owner,root,stage=fixture(tmp_path)
    class ForeignFirewall(Runtime):
        def isolate(self,owner): raise ValueError('foreign table')
    runtime=ForeignFirewall()
    with pytest.raises(api().RestoreError): api().apply(stage,owner,root=root,runtime=runtime,permissions=lambda *a:None)
    assert runtime.events==[]
    assert (root/'var/lib/tailscale/tailscaled.state').read_text()=='current identity'


def test_recovery_rejects_symlink_journal(tmp_path):
    owner,root,stage=fixture(tmp_path)
    class Interrupted(Runtime):
        def verify(self,owner): raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt): api().apply(stage,owner,root=root,runtime=Interrupted(),permissions=lambda *a:None)
    pending=root/'etc/rdc-restore-pending.json';copy=root/'original.json';pending.rename(copy);pending.symlink_to(copy)
    with pytest.raises(ValueError,match='Unsafe'): api().recover(owner,root=root,runtime=Runtime())


def test_recovery_state_parent_is_private_and_unowned_shared_parent_blocks(tmp_path):
    owner,root,stage=fixture(tmp_path)
    parent=root/'var/lib/rdc-backup';parent.mkdir(mode=0o755)
    with pytest.raises(ValueError,match='journal'):
        api().apply(stage,owner,root=root,runtime=Runtime(),permissions=lambda *a:None)
    assert parent.stat().st_mode&0o077!=0  # Do not silently adopt/chmod existing state.

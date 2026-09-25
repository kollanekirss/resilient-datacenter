from datetime import datetime,timezone
import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def plan():
    from test_backup_service_scope import fixture
    from backup_scope import include
    from application_catalogue import predecessor
    from backup_contracts import binary_paths
    network,current=fixture();old=dict(current,images={k:v['image'] for k,v in predecessor('matrix').items()})
    source=include(network,old);target=include(network,current)
    return {'source_owner':source,'target_owner':target,'source_hashes':{name:'a'*64 for name in binary_paths(source)}}


class Backend:
    def __init__(self,fail=None):self.events=[];self.fail=fail
    def event(self,name):
        self.events.append(name)
        if self.fail==name:self.fail=None;raise ValueError('injected private failure')
    def prepare(self,journal):self.event('prepare')
    def quiesce(self,journal):self.event('quiesce')
    def snapshot(self,journal):
        self.event('snapshot')
        return {'id':'b'*64,'captured_at':datetime.now(timezone.utc).isoformat()}
    def stage(self,journal):self.event('stage')
    def isolate(self,journal):self.event('isolate')
    def migrate(self,journal):self.event('migrate')
    def verify(self,journal,*,original=False):self.event('verify-old' if original else 'verify-new')
    def restore_original(self,journal):self.event('restore-original')
    def publish(self,journal):self.event('publish')
    def clean(self,journal):self.event('clean')
    def freeze(self,journal):self.event('freeze')


def test_upgrade_requires_verified_snapshot_before_candidate_migration(tmp_path):
    m=importlib.import_module('upgrade_transaction');backend=Backend()
    result=m.apply(plan(),backend,root=tmp_path)
    assert result['state']=='upgraded-service-verified'
    assert backend.events==['prepare','quiesce','snapshot','stage','isolate','migrate','verify-new','publish','clean']
    assert not (tmp_path/m.PENDING).exists()
    record=m.last_result(tmp_path)
    assert record['snapshot']['id']=='b'*64 and record['user_operation']=='not-recorded'


def test_precommit_failure_restores_untouched_original_before_publication(tmp_path):
    m=importlib.import_module('upgrade_transaction');backend=Backend('verify-new')
    with pytest.raises(m.UpgradeError) as error:m.apply(plan(),backend,root=tmp_path)
    assert error.value.recovered is True and not error.value.committed
    assert backend.events[-4:]==['restore-original','verify-old','publish','clean']
    assert m.last_result(tmp_path)['state']=='previous-version-restored'


def test_postcommit_publication_failure_never_rolls_back_data(tmp_path):
    m=importlib.import_module('upgrade_transaction');backend=Backend('publish')
    with pytest.raises(m.UpgradeError) as error:m.apply(plan(),backend,root=tmp_path)
    assert error.value.committed and 'restore-original' not in backend.events
    assert (tmp_path/m.PENDING).exists()
    resumed=Backend();result=m.recover(resumed,root=tmp_path)
    assert result['state']=='upgraded-service-verified'
    assert 'migrate' not in resumed.events and 'restore-original' not in resumed.events


def test_interruption_after_candidate_change_preserves_guard_and_recovers_original(tmp_path):
    m=importlib.import_module('upgrade_transaction')
    class Interrupt(Backend):
        def migrate(self,journal):raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):m.apply(plan(),Interrupt(),root=tmp_path)
    assert (tmp_path/m.PENDING).exists()
    backend=Backend();assert m.recover(backend,root=tmp_path)['state']=='previous-version-restored'
    assert 'restore-original' in backend.events and 'migrate' not in backend.events


def test_rollback_commit_survives_release_failure_without_a_second_restore(tmp_path):
    m=importlib.import_module('upgrade_transaction')
    class Fails(Backend):
        def verify(self,journal,*,original=False):
            if not original:raise ValueError('candidate failed')
        def publish(self,journal):raise ValueError('release interrupted')
    with pytest.raises(m.UpgradeError):m.apply(plan(),Fails(),root=tmp_path)
    backend=Backend();assert m.recover(backend,root=tmp_path)['state']=='previous-version-restored'
    assert 'restore-original' not in backend.events


def test_backup_failure_cannot_stage_or_migrate(tmp_path):
    m=importlib.import_module('upgrade_transaction');backend=Backend('snapshot')
    with pytest.raises(m.UpgradeError):m.apply(plan(),backend,root=tmp_path)
    assert 'stage' not in backend.events and 'migrate' not in backend.events


def test_invalid_source_or_identity_changes_fail_before_backend_actions(tmp_path):
    m=importlib.import_module('upgrade_transaction');backend=Backend();data=plan()
    data['target_owner']['applications']['node_name']='someone-else'
    with pytest.raises(ValueError):m.apply(data,backend,root=tmp_path)
    assert backend.events==[] and not (tmp_path/m.PENDING).exists()

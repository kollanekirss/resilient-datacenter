import json
from pathlib import Path
import pytest
from test_restore_transaction import fixture,Runtime
import restore_transaction as restore


def test_finished_restore_records_capture_completion_and_limited_verification(tmp_path):
    owner,root,stage=fixture(tmp_path)
    restore.apply(stage,owner,root=root,runtime=Runtime(),permissions=lambda *a:None)
    path=root/'var/lib/rdc-backup/restore-result.json'
    result=json.loads(path.read_text())
    assert result['ownership']==owner and result['service_verification']=='verified'
    assert result['user_operation']=='not-recorded'
    assert result['captured_at']==json.loads((stage/'snapshot.json').read_text())['captured_at']
    assert result['completed_at']>=result['captured_at']
    assert path.stat().st_mode&0o777==0o600


def test_failed_restore_has_no_success_record(tmp_path):
    owner,root,stage=fixture(tmp_path)
    with pytest.raises(restore.RestoreError):restore.apply(stage,owner,root=root,runtime=Runtime(fail=True),permissions=lambda *a:None)
    assert not (root/'var/lib/rdc-backup/restore-result.json').exists()


def test_release_failure_cannot_publish_completed_restore_evidence(tmp_path):
    owner,root,stage=fixture(tmp_path)
    class ReleaseFailure(Runtime):
        def release(self):raise ValueError('cannot release')
    with pytest.raises(restore.RestoreError):restore.apply(stage,owner,root=root,runtime=ReleaseFailure(),permissions=lambda *a:None)
    assert not (root/'var/lib/rdc-backup/restore-result.json').exists()
    restore.recover(owner,root=root,runtime=Runtime())
    assert (root/'var/lib/rdc-backup/restore-result.json').exists()


def test_pending_restore_takes_precedence_over_historical_evidence(tmp_path):
    import restore_evidence
    owner,root,stage=fixture(tmp_path)
    assert restore_evidence.latest(root,owner)['state']=='untested'
    restore.apply(stage,owner,root=root,runtime=Runtime(),permissions=lambda *a:None)
    assert restore_evidence.latest(root,owner)['state']=='service-verified'
    pending=root/'etc/rdc-restore-pending.json';pending.write_text('{}')
    assert restore_evidence.latest(root,owner)['state']=='restore-pending'
    pending.unlink();(root/'usr/local/sbin/tailscaled').write_bytes(b'new version')
    assert restore_evidence.latest(root,owner)['state']=='verified-on-prior-components'

import importlib
import json
from pathlib import Path
import pytest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api(): return importlib.import_module('backup_schedule')


def test_failed_attempt_preserves_last_success_without_claiming_fresh_backup(tmp_path):
    status=tmp_path/'status.json';m=api()
    m.record_attempt(status,{'state':'snapshot-created','snapshot_id':'a'*64},now='2026-09-25T10:00:00+00:00')
    m.record_attempt(status,None,now='2026-09-25T11:00:00+00:00')
    data=json.loads(status.read_text())
    assert data['last_attempt']['outcome']=='failed'
    assert data['last_success']['snapshot_id']=='a'*64
    assert data['last_success']['finished_at']=='2026-09-25T10:00:00+00:00'
    assert status.stat().st_mode&0o077==0


def test_overdue_uses_capture_age_and_explicit_schedule():
    m=api()
    assert m.overdue('hourly',7200) is True
    assert m.overdue('daily',7200) is False
    assert m.overdue('hourly',100) is False
    assert m.overdue('daily',None) is True
    with pytest.raises(ValueError):m.overdue('every five seconds',10)


def test_frozen_runtime_detects_changed_code_and_rejects_symlinks(tmp_path):
    m=api();source=Path(__file__).resolve().parents[1]/'scripts'
    destination=tmp_path/'runtime';m.create_runtime(source,destination)
    m.verify_runtime(destination,require_root=False)
    (destination/'backup_snapshot.py').write_text('modified')
    with pytest.raises(ValueError):m.verify_runtime(destination,require_root=False)


def test_termination_runs_cleanup_instead_of_abandoning_paused_service(tmp_path):
    import subprocess
    marker=tmp_path/'cleanup';scripts=Path(__file__).resolve().parents[1]/'scripts'
    program='import sys,time\nsys.path.insert(0,'+repr(str(scripts))+')\nfrom backup_runner import install_signal_handlers\ninstall_signal_handlers()\ntry:\n print("ready",flush=True)\n time.sleep(30)\nfinally:\n open('+repr(str(marker))+',"w").write("cleanup ran")\n'
    process=subprocess.Popen([sys.executable,'-c',program],stdout=subprocess.PIPE,text=True)
    try:
        assert process.stdout.readline().strip()=='ready'
        process.terminate();assert process.wait(timeout=5)!=0
        assert marker.read_text()=='cleanup ran'
    finally:
        if process.poll() is None: process.kill();process.wait()

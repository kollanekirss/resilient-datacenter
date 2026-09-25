import importlib
from pathlib import Path
import pytest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_runtime_transition_can_resume_after_old_directory_is_retained(tmp_path,monkeypatch):
    m=importlib.import_module('backup_schedule')
    source=Path(__file__).resolve().parents[1]/'scripts';runtime=tmp_path/'runtime';base=tmp_path/'base';base.mkdir()
    m.create_runtime(source,runtime)
    # A valid previous frozen version, with one older source file.
    (runtime/'backup_snapshot.py').write_text('older reviewed runtime')
    import hashlib,json
    manifest=json.loads((runtime/'manifest.json').read_text())
    manifest['files']['backup_snapshot.py']=hashlib.sha256((runtime/'backup_snapshot.py').read_bytes()).hexdigest()
    m.private_json(runtime/'manifest.json',manifest)
    monkeypatch.setattr(m,'RUNTIME',runtime);monkeypatch.setattr(m,'BASE',base)
    original=m.os.replace
    def interrupted(source_path,destination):
        if Path(source_path).name=='.rdc-backup-runtime-next':raise KeyboardInterrupt()
        return original(source_path,destination)
    monkeypatch.setattr(m.os,'replace',interrupted)
    with pytest.raises(KeyboardInterrupt):m.refresh_runtime(source,require_root=False)
    assert (base/'runtime-update.json').exists() and not runtime.exists()
    monkeypatch.setattr(m.os,'replace',original)
    m.refresh_runtime(source,require_root=False)
    assert m.verify_runtime(runtime,require_root=False)['files']!=manifest['files']
    assert not (base/'runtime-update.json').exists()
    assert (tmp_path/'.rdc-backup-runtime-previous').exists()
    m.refresh_runtime(source,require_root=False)  # Already-current resume is harmless.

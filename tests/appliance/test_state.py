"""Private state tests use actual files and kernel locks, never a mutation runner."""
import importlib
import json
import os
from pathlib import Path
import stat

import pytest

from appliance.contracts import ApplianceError, identity


def api():
    return importlib.import_module("appliance.state")


def operation():
    return {"kind": "create-vm", "plan_id": "plan-one", "vmid": 101, "nonce": "one"}


def test_begin_persists_intent_and_never_replays_pending(tmp_path):
    state = api()
    work = tmp_path / "private"
    intent = operation()
    operation_id = state.begin(work, intent)
    assert operation_id == identity(intent)
    assert state.read(work / (operation_id + ".json")) == {
        "schema": 1, "operation_id": operation_id, "phase": "pending", "operation": intent}
    with pytest.raises(ApplianceError, match="operation-needs-inspection"):
        state.begin(work, intent)
    assert stat.S_IMODE(work.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in work.iterdir())


def test_finish_reconciles_once_and_refuses_changed_outcome(tmp_path):
    state = api()
    op_id = state.begin(tmp_path, operation())
    observation = {"vmid": 101, "owned": True, "config_id": "actual-config"}
    state.finish(tmp_path, op_id, observation)
    path = tmp_path / (op_id + ".json")
    before = path.read_bytes()
    state.finish(tmp_path, op_id, observation.copy())
    assert path.read_bytes() == before
    record = state.read(path)
    assert record["phase"] == "complete"
    assert record["observation"] == observation
    with pytest.raises(ApplianceError, match="operation-outcome-conflict"):
        state.finish(tmp_path, op_id, {"vmid": 999})
    with pytest.raises(ApplianceError, match="operation-needs-inspection"):
        state.begin(tmp_path, operation())
    assert path.read_bytes() == before


def test_nonblocking_lock_rejects_concurrent_holder_then_recovers(tmp_path):
    state = api()
    with state.lock(tmp_path):
        with pytest.raises(ApplianceError, match="operation-locked"):
            state.begin(tmp_path, operation())
    assert state.begin(tmp_path, operation())


@pytest.mark.parametrize("kind", ["directory-symlink", "ancestor-symlink", "unsafe-parent", "directory-mode"])
def test_unsafe_directory_inheritance_is_rejected_without_changes(tmp_path, kind):
    state = api()
    original = tmp_path / "original"
    original.mkdir(mode=0o700)
    path = original
    if kind == "directory-symlink":
        path = tmp_path / "link"
        path.symlink_to(original, target_is_directory=True)
    elif kind == "ancestor-symlink":
        link = tmp_path / "link"
        link.symlink_to(original, target_is_directory=True)
        path = link / "private"
    elif kind == "unsafe-parent":
        original.chmod(0o777)
        path = original / "private"
    else:
        original.chmod(0o755)
    with pytest.raises(ApplianceError):
        state.begin(path, operation())
    assert not list(original.iterdir())


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public-mode", "fifo"])
def test_record_read_and_write_refuse_unsafe_existing_files(tmp_path, kind):
    state = api()
    record = tmp_path / "state.json"
    target = tmp_path / "other.json"
    target.write_bytes(b'{"untouched":true}')
    target.chmod(0o600)
    if kind == "symlink":
        record.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, record)
    elif kind == "fifo":
        os.mkfifo(record, 0o600)
    else:
        record.write_bytes(b"{}")
        record.chmod(0o644)
    for action in (lambda: state.read(record), lambda: state.write(record, {"changed": True})):
        with pytest.raises(ApplianceError):
            action()
    assert target.read_bytes() == b'{"untouched":true}'


@pytest.mark.parametrize("raw", [b'{"cut":', b'{"a":1,"a":2}', b'{"number":1.5}', b'[]', b'{"secret":"PRIVATE"]'])
def test_invalid_private_json_is_rejected_without_input_disclosure(tmp_path, raw):
    path = tmp_path / "broken.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(ApplianceError) as err:
        api().read(path)
    assert "PRIVATE" not in str(err.value)
    assert path.read_bytes() == raw


def test_size_and_depth_bounds_apply_to_writes_and_reads(tmp_path):
    state = api()
    path = tmp_path / "bounded.json"
    with pytest.raises(ApplianceError, match="state-size"):
        state.write(path, {"value": "x" * (1024 * 1024)})
    assert not path.exists()
    value = {}
    for _ in range(40):
        value = {"nested": value}
    with pytest.raises(ApplianceError, match="json-depth"):
        state.write(path, value)
    path.write_bytes(b" " * (1024 * 1024 + 1))
    path.chmod(0o600)
    with pytest.raises(ApplianceError, match="state-size"):
        state.read(path)


def test_finish_requires_existing_matching_intent_and_safe_id(tmp_path):
    state = api()
    with pytest.raises(ApplianceError, match="operation-id-invalid"):
        state.finish(tmp_path, "../outside", {})
    with pytest.raises(ApplianceError, match="operation-missing"):
        state.finish(tmp_path, "a" * 64, {})
    op_id = state.begin(tmp_path, operation())
    path = tmp_path / (op_id + ".json")
    record = state.read(path)
    record["operation"]["vmid"] = 202
    state.write(path, record)
    with pytest.raises(ApplianceError, match="operation-identity-mismatch"):
        state.finish(tmp_path, op_id, {})


def test_failure_before_file_fsync_preserves_previous_record(tmp_path, monkeypatch):
    state = api()
    path = tmp_path / "state.json"
    state.write(path, {"revision": 1})
    before = path.read_bytes()
    def fail_fsync(fd):
        raise OSError("PRIVATE failure detail")
    monkeypatch.setattr(state.os, "fsync", fail_fsync)
    with pytest.raises(ApplianceError, match="state-write-failed") as err:
        state.write(path, {"revision": 2})
    assert "PRIVATE" not in str(err.value)
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_failure_after_publication_leaves_pending_for_reconciliation(tmp_path, monkeypatch):
    state = api()
    real_fsync = state.os.fsync
    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory durability unknown")
        real_fsync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(state.os, "fsync", fail_directory_fsync)
        with pytest.raises(ApplianceError, match="state-write-failed"):
            state.begin(tmp_path, operation())
    with pytest.raises(ApplianceError, match="operation-needs-inspection"):
        state.begin(tmp_path, operation())
    assert state.read(tmp_path / (identity(operation()) + ".json"))["phase"] == "pending"


def test_existing_symlink_lock_is_never_followed(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    target.chmod(0o600)
    (tmp_path / ".lock").symlink_to(target)
    with pytest.raises(ApplianceError):
        api().begin(tmp_path, operation())
    assert target.read_bytes() == b"untouched"


def test_record_writer_cannot_replace_active_lock_inode(tmp_path):
    state = api()
    with state.lock(tmp_path):
        original = (tmp_path / ".lock").stat().st_ino
        with pytest.raises(ApplianceError, match="state-path-reserved"):
            state.write(tmp_path / ".lock", {})
        assert (tmp_path / ".lock").stat().st_ino == original
        with pytest.raises(ApplianceError, match="operation-locked"):
            with state.lock(tmp_path):
                pass


def test_finish_retry_rechecks_durability_after_failed_directory_sync(tmp_path, monkeypatch):
    state = api()
    op_id = state.begin(tmp_path, operation())
    real_fsync = state.os.fsync
    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory unavailable")
        real_fsync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(state.os, "fsync", fail_directory_fsync)
        with pytest.raises(ApplianceError, match="state-write-failed"):
            state.finish(tmp_path, op_id, {"owned": True})
        with pytest.raises(ApplianceError, match="state-write-failed"):
            state.finish(tmp_path, op_id, {"owned": True})
    state.finish(tmp_path, op_id, {"owned": True})
    assert state.read(tmp_path / (op_id + ".json"))["phase"] == "complete"

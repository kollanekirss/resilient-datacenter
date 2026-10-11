"""Durable private records and explicit operation reconciliation.

Ownership follows the effective UID: root for the installed appliance, the
invoking user for unprivileged library tests. The privileged command boundary
must enforce root before deployment. These functions never execute an intent.
All paths are traversed through directory descriptors without following links.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .contracts import ApplianceError, canonical, identity, require


MAX_BYTES = 1024 * 1024
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _directory_info(info, *, private):
    require(stat.S_ISDIR(info.st_mode), "state-directory-unsafe")
    mode = stat.S_IMODE(info.st_mode)
    if private:
        require(info.st_uid == os.geteuid() and mode == 0o700, "state-directory-private")
    else:
        require(info.st_uid in (0, os.geteuid()), "state-ancestor-owner")
        sticky_root_temp = info.st_uid == 0 and mode & stat.S_ISVTX
        require(not mode & 0o022 or sticky_root_temp, "state-ancestor-writable")


@contextmanager
def _directory_fd(directory, *, create=False):
    path = Path(directory)
    require(".." not in path.parts, "state-path-invalid")
    path = path.absolute()
    fd = None
    try:
        fd = os.open(path.anchor, _DIRECTORY_FLAGS)
        _directory_info(os.fstat(fd), private=len(path.parts) == 1)
        for index, name in enumerate(path.parts[1:], start=1):
            try:
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, mode=0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            _directory_info(os.fstat(fd), private=index == len(path.parts) - 1)
        yield fd
    except OSError:
        raise ApplianceError("state-directory-unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)


def _file_info(info):
    require(stat.S_ISREG(info.st_mode), "state-file-not-regular")
    require(info.st_uid == os.geteuid(), "state-file-owner")
    require(stat.S_IMODE(info.st_mode) == 0o600, "state-file-private")
    require(info.st_nlink == 1, "state-file-hardlink")


def _existing_info(dfd, name):
    try:
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _file_info(info)
    return info


def _filename(path):
    value = Path(path)
    require(value.name not in ("", ".", "..") and ".." not in value.parts, "state-path-invalid")
    return value.parent, value.name


def _record_bytes(record):
    require(type(record) is dict, "object-required")
    raw = canonical(record)
    require(len(raw) <= MAX_BYTES, "state-size")
    return raw


def _unique(pairs):
    record = {}
    for key, value in pairs:
        require(key not in record, "duplicate-json-key")
        record[key] = value
    return record


def _read_at(dfd, name):
    before = _existing_info(dfd, name)
    require(before is not None, "state-file-missing")
    fd = os.open(name, _READ_FLAGS, dir_fd=dfd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _file_info(info)
        require((before.st_dev, before.st_ino) == (info.st_dev, info.st_ino), "state-file-changed")
        require(info.st_size <= MAX_BYTES, "state-size")
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        same = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        require(same(info) == same(after) == same(current), "state-file-changed")
    require(len(raw) <= MAX_BYTES, "state-size")
    try:
        record = json.loads(raw, object_pairs_hook=_unique)
        _record_bytes(record)
        return record
    except ApplianceError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ApplianceError("state-json-invalid") from None


def read(path: Path) -> dict:
    """Read one bounded private object; corrupt or unsafe data is never repaired."""
    parent, name = _filename(path)
    with _directory_fd(parent) as dfd:
        try:
            return _read_at(dfd, name)
        except OSError:
            raise ApplianceError("state-read-failed") from None


def _write_at(dfd, name, raw):
    temp_name = None
    try:
        previous = _existing_info(dfd, name)
        temp_name = ".record-" + secrets.token_hex(16)
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        with os.fdopen(fd, "wb") as stream:
            _file_info(os.fstat(stream.fileno()))
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        current = _existing_info(dfd, name)
        original = None if previous is None else (previous.st_dev, previous.st_ino, previous.st_mtime_ns, previous.st_ctime_ns)
        observed = None if current is None else (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns)
        require(original == observed, "state-file-changed")
        os.replace(temp_name, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        temp_name = None
        os.fsync(dfd)
    except OSError:
        raise ApplianceError("state-write-failed") from None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=dfd)
            except FileNotFoundError:
                pass


def write(path: Path, record: dict) -> None:
    """Publish through file fsync, atomic rename and parent directory fsync.

    A failure after rename has an uncertain durability outcome. Callers must
    inspect that record; they must not replay an external mutation.
    """
    raw = _record_bytes(record)
    parent, name = _filename(path)
    require(name != ".lock", "state-path-reserved")
    with _directory_fd(parent, create=True) as dfd:
        _write_at(dfd, name, raw)


@contextmanager
def _locked_fd(directory):
    with _directory_fd(directory, create=True) as dfd:
        fd = None
        try:
            try:
                fd = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dfd)
            except FileExistsError:
                before = _existing_info(dfd, ".lock")
                require(before is not None, "state-file-changed")
                fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                after = os.fstat(fd)
                require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "state-file-changed")
            _file_info(os.fstat(fd))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ApplianceError("operation-locked") from None
            yield dfd
        except OSError:
            raise ApplianceError("state-lock-failed") from None
        finally:
            if fd is not None:
                os.close(fd)


@contextmanager
def lock(directory: Path):
    """Hold the real nonblocking operation lock, releasing it on every exit."""
    with _locked_fd(directory):
        yield Path(directory)


def begin(directory: Path, operation: dict) -> str:
    """Persist intent before dispatch; the same intent is never replayable."""
    _record_bytes(operation)
    operation_id = identity(operation)
    name = operation_id + ".json"
    raw = _record_bytes({"schema": 1, "operation_id": operation_id,
                         "phase": "pending", "operation": operation})
    with _locked_fd(directory) as dfd:
        require(_existing_info(dfd, name) is None, "operation-needs-inspection")
        _write_at(dfd, name, raw)
    return operation_id


def finish(directory: Path, operation_id: str, observation: dict) -> None:
    """Explicitly reconcile a recorded intent with an observed outcome."""
    require(isinstance(operation_id, str) and re.fullmatch(r"[0-9a-f]{64}", operation_id) is not None, "operation-id-invalid")
    observation_bytes = _record_bytes(observation)
    name = operation_id + ".json"
    with _locked_fd(directory) as dfd:
        require(_existing_info(dfd, name) is not None, "operation-missing")
        record = _read_at(dfd, name)
        require(record.get("schema") == 1 and record.get("operation_id") == operation_id
                and type(record.get("operation")) is dict
                and identity(record["operation"]) == operation_id, "operation-identity-mismatch")
        phase = record.get("phase")
        require(phase in ("pending", "complete"), "operation-phase-invalid")
        expected = {"schema", "operation_id", "phase", "operation"}
        if phase == "complete":
            expected.add("observation")
        require(set(record) == expected, "operation-record-invalid")
        if phase == "complete":
            require(canonical(record["observation"]) == observation_bytes, "operation-outcome-conflict")
            try:
                os.fsync(dfd)
            except OSError:
                raise ApplianceError("state-write-failed") from None
            return
        record.update(phase="complete", observation=observation)
        _write_at(dfd, name, _record_bytes(record))

"""Bounded descriptor-relative I/O for explicitly owned appliance host files."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import stat

from .contracts import ApplianceError, require

LIMIT = 1024 * 1024


def _check_file(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "host-file-unsafe")
    require(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022, "host-file-owner-mode")


@contextmanager
def _parent(root, absolute_path, *, create=False):
    root, name = Path(root), Path(absolute_path)
    require(root.is_absolute() and name.is_absolute() and ".." not in root.parts + name.parts
            and name.name not in ("", ".", ".."), "host-path-invalid")
    parts = (root / name.relative_to("/")).parts
    fd = None
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            require(info.st_uid in (0, os.geteuid()) and
                    (not mode & 0o022 or info.st_uid == 0 and mode & stat.S_ISVTX), "host-directory-unsafe")
        yield fd, parts[-1]
    except FileNotFoundError:
        raise
    except OSError:
        raise ApplianceError("host-file-io") from None
    finally:
        if fd is not None:
            os.close(fd)


def _read(dfd, name):
    before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    _check_file(before)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _check_file(opened)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "host-file-changed")
        require(opened.st_size <= LIMIT, "host-file-size")
        data = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        require((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "host-file-changed")
    require(len(data) <= LIMIT, "host-file-size")
    return data


def read_optional(root, absolute_path):
    try:
        with _parent(root, absolute_path) as (dfd, name):
            return _read(dfd, name)
    except FileNotFoundError:
        return None


def atomic_write(root, absolute_path, data, *, mode=0o644):
    require(type(data) is bytes and len(data) <= LIMIT, "host-file-size")
    require(mode in (0o600, 0o644, 0o755), "host-file-mode")
    with _parent(root, absolute_path, create=True) as (dfd, name):
        try:
            previous = _read(dfd, name)
        except FileNotFoundError:
            previous = None
        temporary = ".rdc-" + secrets.token_hex(16)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dfd)
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), mode)
                _check_file(os.fstat(target.fileno()))
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            try:
                current = _read(dfd, name)
            except FileNotFoundError:
                current = None
            require(current == previous, "host-file-changed")
            os.replace(temporary, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            temporary = None
            os.fsync(dfd)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=dfd)
                except FileNotFoundError:
                    pass


def delete_owned(root, absolute_path, *, expected_sha256):
    with _parent(root, absolute_path) as (dfd, name):
        data = _read(dfd, name)
        require(hashlib.sha256(data).hexdigest() == expected_sha256, "host-file-changed")
        os.unlink(name, dir_fd=dfd)
        os.fsync(dfd)

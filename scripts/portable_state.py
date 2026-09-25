"""Private local wizard records and nonblocking operation locks."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
from portable_plan import require


def directory(path):
    path=Path(path).absolute()
    if not path.exists():path.mkdir(mode=0o700,parents=True)
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0,
            'Use a private directory owned by you with mode 0700; symlinks are not accepted.')
    return path


@contextmanager
def regular(path):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0,
                    'Use private owned regular files; symlinks are not accepted.')
            yield stream
    except OSError:
        raise ValueError('Cannot access private local state or media.') from None


def read(path):
    with regular(path) as stream:
        raw=stream.read(65537)
    require(len(raw)<=65536,'Local record exceeds its size limit.')
    try:return json.loads(raw)
    except (ValueError,UnicodeError,RecursionError):raise ValueError('Invalid local record.') from None


def write(path,record):
    parent=directory(path.parent)
    fd,tmp=tempfile.mkstemp(prefix='.record-',dir=parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(record,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        dfd=os.open(parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


@contextmanager
def lock(path):
    path=directory(path)
    try:
        fd=os.open(path/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            info=os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0,'Invalid operation lock.')
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Another operation is using this state directory.') from None
            yield path
    except OSError:raise ValueError('Cannot lock private operation directory.') from None

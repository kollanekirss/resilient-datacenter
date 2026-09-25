import importlib
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('service_operations')


def test_resume_preserves_identical_config_and_rejects_changed_or_linked_files(tmp_path):
    m=api();p=tmp_path/'configuration'
    m.write(p,'owned',uid=os.geteuid(),gid=os.getegid())
    inode=p.stat().st_ino
    m.write(p,'owned',uid=os.geteuid(),gid=os.getegid())
    assert p.stat().st_ino==inode
    with pytest.raises(ValueError):m.write(p,'different',uid=os.geteuid(),gid=os.getegid())
    linked=tmp_path/'link';linked.symlink_to(p)
    with pytest.raises(ValueError):m.write(linked,'owned',uid=os.geteuid(),gid=os.getegid())
    assert p.read_text()=='owned'


def test_resume_never_adopts_shared_or_linked_state_directory(tmp_path):
    m=api();p=tmp_path/'state';p.mkdir(mode=0o755)
    with pytest.raises(ValueError):m.directory(p,mode=0o700,uid=os.geteuid(),gid=os.getegid())
    assert p.stat().st_mode&0o077!=0

import hashlib
import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_local_restic_does_not_use_network(tmp_path,monkeypatch):
    import bz2
    m=importlib.import_module('backup_operations')
    binary=b'\x7fELF'+b'\0'*14+b'\x3e\x00'+b'test executable bytes'
    compressed=bz2.compress(binary);artifact=tmp_path/'restic.bz2';artifact.write_bytes(compressed)
    monkeypatch.setattr(m,'RESTIC_SHA256',hashlib.sha256(compressed).hexdigest())
    monkeypatch.setattr(m.urllib.request,'urlopen',lambda *a,**k:pytest.fail('offline tool must not fetch'))
    target=tmp_path/'restic'
    assert m.install_binary(target,artifact=artifact)==hashlib.sha256(binary).hexdigest()
    assert target.read_bytes()==binary


def test_bad_local_restic_never_creates_target(tmp_path,monkeypatch):
    import backup_operations as m
    artifact=tmp_path/'bad';artifact.write_bytes(b'bad')
    monkeypatch.setattr(m.urllib.request,'urlopen',lambda *a,**k:pytest.fail('no fallback'))
    with pytest.raises(ValueError):m.install_binary(tmp_path/'target',artifact=artifact)
    assert not (tmp_path/'target').exists()


def test_restic_flag_routes_to_configuration():
    import rdc
    args=rdc.parser().parse_args(['backup','configure','/private/backup.yml','--restic-artifact','/media/restic.bz2'])
    assert str(args.restic_artifact)=='/media/restic.bz2'

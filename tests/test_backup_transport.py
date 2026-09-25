import importlib
from pathlib import Path
import sys
import json
import pytest
from test_backup_contracts import profile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('backup_transport')


def test_ssh_arguments_pin_identity_and_do_not_use_user_config(tmp_path):
    m=api().Restic(profile(),base=tmp_path)
    args=m.command(['snapshots'])
    ssh=args[args.index('-o')+1]
    for option in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','HostKeyAlgorithms=ssh-ed25519','/dev/null','known_hosts'):
        assert option in ssh
    assert '--no-cache' in args and 'sftp:rdc-backup@100.64.0.12:/data/south-home-services' in args


def test_backup_requires_complete_snapshot_id(monkeypatch,tmp_path):
    m=api().Restic(profile(),base=tmp_path)
    monkeypatch.setattr(m,'execute',lambda *a,**k:json.dumps({'message_type':'summary','snapshot_id':'a'*64}))
    assert m.backup(tmp_path)=='a'*64
    monkeypatch.setattr(m,'execute',lambda *a,**k:json.dumps({'message_type':'summary'}))
    with pytest.raises(ValueError): m.backup(tmp_path)

@pytest.mark.parametrize('identifier',['latest','abc123','../escape','--help','a'*63])
def test_restore_requires_exact_snapshot_and_no_existing_directory(tmp_path,identifier):
    m=api().Restic(profile(),base=tmp_path)
    with pytest.raises(ValueError): m.restore(identifier,tmp_path/'restore')
    assert not (tmp_path/'restore').exists()


def test_remote_status_is_read_only_and_unknown_restore_is_preserved(monkeypatch,tmp_path):
    m=api().Restic(profile(),base=tmp_path);calls=[]
    def execute(args,**kwargs):
        calls.append(args)
        return json.dumps([{'id':'a'*64,'time':'2026-09-25T09:00:00Z','hostname':'home-services'}])
    monkeypatch.setattr(m,'execute',execute)
    result=m.snapshots()
    assert result[0]['id']=='a'*64 and '--no-lock' in calls[0]


def test_secret_files_cannot_be_symlinks_or_readable_by_others(tmp_path):
    m=api().Restic(profile(),base=tmp_path)
    for name in ('password','ssh_key','known_hosts'): (tmp_path/name).write_text('private')
    with pytest.raises(ValueError): m.check_credentials()

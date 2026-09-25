from pathlib import Path
import sys
import importlib
import pytest
from test_backup_contracts import profile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api():return importlib.import_module('backup_target')


def test_storage_only_listens_on_overlay_and_disables_shell_and_forwarding():
    config=api().sshd_configuration('100.64.0.12')
    for text in ('ListenAddress 100.64.0.12','Port 2222','ForceCommand internal-sftp','AllowTcpForwarding no','PermitRootLogin no','PasswordAuthentication no','ChrootDirectory /srv/rdc-backup-target'):
        assert text in config
    assert '0.0.0.0' not in config

@pytest.mark.parametrize('address',['0.0.0.0','127.0.0.1','1.1.1.1','host;evil','::1'])
def test_storage_rejects_non_overlay_bind(address):
    with pytest.raises(ValueError): api().sshd_configuration(address)


def test_public_key_comments_cannot_add_authorized_keys_or_options():
    key=profile()['backup_host_key']
    assert api().public_key(key+' rdc-backup-writer')==key
    for value in (key+'\n'+key,'command="evil" '+key):
        with pytest.raises(ValueError): api().public_key(value)

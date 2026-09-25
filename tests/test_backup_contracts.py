import base64
import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('backup_contracts')

def profile():
    kind=b'ssh-ed25519'; key=len(kind).to_bytes(4,'big')+kind+(32).to_bytes(4,'big')+b'k'*32
    return {'kind':'backup-profile','schema_version':1,'institution_id':'south','node_name':'home-services','role':'peer',
            'backup_host':'100.64.0.12','backup_port':22,'backup_host_key':'ssh-ed25519 '+base64.b64encode(key).decode()}


def test_backup_profile_contains_no_password_or_command():
    data=profile(); assert api().validate(data)==[]
    assert api().repository(data)=='sftp:rdc-backup@100.64.0.12:/data/south-home-services'

@pytest.mark.parametrize('field,value',[('password','SECRET'),('ssh_command','evil'),('backup_host','host;touch /tmp/x'),('backup_host','127.0.0.1'),('backup_port',True),('backup_host_key','ssh-ed25519 garbage'),('node_name','../other'),('role','arbitrary')])
def test_invalid_backup_configuration_is_rejected(field,value):
    data=profile();data[field]=value;assert api().validate(data)


def test_backup_host_key_wire_type_must_match_display_type():
    data=profile(); data['backup_host_key']='ssh-ed25519 '+base64.b64encode(b'not an SSH public key').decode()
    assert api().validate(data)


def test_resource_catalogue_is_fixed_by_owned_role_and_mode():
    owner={'role':'controller','tls_mode':'managed-acme'}
    resources=api().resources(owner)
    assert 'var/lib/headscale' in resources.paths and 'etc/letsencrypt' in resources.paths
    assert resources.services==('headscale',)
    assert all(not p.startswith('/') and '..' not in p.split('/') for p in resources.paths)
    assert 'etc/letsencrypt' not in api().resources({'role':'controller'}).paths


def test_peer_backup_components_match_the_actual_installer_and_running_daemon():
    import yaml
    root=Path(__file__).resolve().parents[1]
    tasks=yaml.safe_load((root/'roles/client/tasks/main.yml').read_text())
    task=next(item for item in tasks if item['name']=='Install client and daemon')
    installed={entry['dest'].lstrip('/') for entry in task['loop']}
    assert set(api().binary_paths({'role':'peer'}))==installed
    unit=(root/'roles/client/templates/tailscaled.service.j2').read_text()
    daemon=next(line.split('=',1)[1].split()[0].lstrip('/') for line in unit.splitlines() if line.startswith('ExecStart='))
    assert daemon in api().binary_paths({'role':'peer'})

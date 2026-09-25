import importlib
import pytest
from test_nextcloud_contracts import profile
from test_setup_contracts import manifest
from setup_contracts import local_ownership


def settings():
    from nextcloud_contracts import ownership,image_pins
    return {'schema_version':1,'ownership':ownership(profile(),local_ownership(manifest())),'bind_address':'100.64.0.23','components':image_pins()}


def test_steady_application_cannot_rewrite_code_or_expose_database():
    m=importlib.import_module('nextcloud_runtime');data=settings()
    command=m.container_command('nextcloud',data)
    assert '--user=33:33' in command and '--read-only' in command
    assert '--entrypoint=apache2-foreground' in command
    assert '/opt/rdc-nextcloud-app:/var/www/html:ro' in command
    assert '/etc/rdc-nextcloud/config:/var/www/html/config:ro' in command
    assert '/var/lib/rdc-nextcloud/files:/var/www/data:rw' in command
    assert '--privileged' not in command and '--cap-drop=ALL' in command
    assert 'listen_addresses=127.0.0.1' in m.container_command('postgres',data)
    assert 'port=5434' in m.container_command('postgres',data)
    with pytest.raises(ValueError):m.container_command('shell',data)


def test_bootstrap_and_accounts_keep_passwords_off_process_arguments():
    m=importlib.import_module('nextcloud_runtime')
    command=m.maintenance_command(settings(),'install')
    assert '--entrypoint=php' in command and '-r' in command
    assert any('php://stdin' in item for item in command)
    assert not any(item.startswith('--admin-pass=') or item.startswith('--database-pass=') for item in command)
    with pytest.raises(ValueError):m.maintenance_command(settings(),'shell')

from pathlib import Path
import importlib
import json
import pytest
from test_nextcloud_contracts import profile
from test_setup_contracts import manifest
from setup_contracts import local_ownership
from nextcloud_contracts import ownership


def owner():
    from backup_scope import include
    network=local_ownership(manifest())
    return include(network,ownership(profile(),network))


def test_nextcloud_backup_scope_is_distinct_and_captures_database_files_and_identity():
    from backup_scope import tag
    from backup_contracts import resources,binary_paths
    scope=owner();catalogue=resources(scope)
    assert tag(scope)=='nextcloud'
    assert 'etc/rdc-nextcloud' in catalogue.paths and 'var/lib/rdc-nextcloud' in catalogue.paths
    assert 'etc/rdc-services' not in catalogue.paths and 'opt/rdc-nextcloud-app' not in catalogue.paths
    assert catalogue.services==('rdc-nextcloud-cron.timer','rdc-nextcloud-proxy','rdc-nextcloud','rdc-nextcloud-postgres','tailscaled')
    assert 'usr/local/lib/rdc-nextcloud/nextcloud_runtime.py' in binary_paths(scope)
    from restore_runtime import guard_files
    guards=guard_files(scope)
    assert Path('/etc/systemd/system/rdc-nextcloud-cron.service.d/20-rdc-restore-guard.conf') in guards
    assert not any('.timer.service.' in str(path) for path in guards)


def test_nextcloud_scope_cannot_be_mislabelled_matrix():
    from backup_scope import include
    network=local_ownership(manifest());application=ownership(profile(),network);application['packages']=['matrix']
    with pytest.raises(ValueError):include(network,application)


def snapshot(tmp_path):
    from nextcloud_contracts import image_pins
    from nextcloud_rendering import application_config,apache_ports,apache_site,proxy
    application=owner()['applications'];base=tmp_path/'etc/rdc-nextcloud';state=tmp_path/'var/lib/rdc-nextcloud'
    (base/'config').mkdir(parents=True);(state/'postgres/global').mkdir(parents=True);(state/'files').mkdir()
    identity={'instanceid':'oc1234567890','passwordsalt':'a'*32,'secret':'b'*48,'version':'35.0.1.0','dbpassword':'c'*64,
              'dbuser':'oc_admin','installed':True,'data_fingerprint':'d'*32}
    settings={'schema_version':1,'ownership':application,'bind_address':'100.64.0.23','components':image_pins()}
    data={'ownership.json':json.dumps(application),'runtime.json':json.dumps(settings),'database-password':'e'*64+'\n',
          'identity.json':json.dumps(identity),'code-seeded.json':json.dumps({'image':image_pins()['nextcloud']['image']}),
          'config/config.php':application_config(profile(),identity),'ports.conf':apache_ports(),'site.conf':apache_site(),
          'Caddyfile':proxy(profile(),'100.64.0.23')}
    for name,content in data.items():(base/name).write_text(content)
    (state/'postgres/PG_VERSION').write_text('17\n');(state/'postgres/global/pg_control').write_bytes(b'control')
    (state/'files/.ncdata').write_text('# Nextcloud data directory\n# Do not change this file')
    return application,base,state


def test_restore_rejects_executable_config_changes_and_live_database(tmp_path):
    m=importlib.import_module('nextcloud_backup');application,base,state=snapshot(tmp_path)
    m.validate_data(tmp_path,application)
    (state/'postgres/postmaster.pid').write_text('42')
    with pytest.raises(ValueError):m.validate_data(tmp_path,application)
    (state/'postgres/postmaster.pid').unlink()
    (base/'config/config.php').write_text('<?php system("unapproved");')
    with pytest.raises(ValueError):m.validate_data(tmp_path,application)


def test_recovered_config_changes_client_fingerprint_but_retains_instance_and_secrets(tmp_path):
    m=importlib.import_module('nextcloud_backup');application,base,state=snapshot(tmp_path)
    before=json.loads((base/'identity.json').read_text());m.refresh_client_fingerprint(base,application)
    after=json.loads((base/'identity.json').read_text())
    assert before['data_fingerprint']!=after['data_fingerprint']
    assert {k:v for k,v in before.items() if k!='data_fingerprint'}=={k:v for k,v in after.items() if k!='data_fingerprint'}
    m.validate_data(tmp_path,application)

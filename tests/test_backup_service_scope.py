import importlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_service_contracts import profile
from test_setup_contracts import manifest
from service_contracts import ownership
from setup_contracts import local_ownership


def fixture():
    network=local_ownership(manifest())
    return network,ownership(profile(),network)


def test_explicit_scope_preserves_network_identity_and_orders_shutdown():
    m=importlib.import_module('backup_scope')
    from backup_contracts import resources,binary_paths
    network,application=fixture();owner=m.include(network,application)
    assert m.network_owner(owner)==network
    assert owner['applications']==application and 'applications' not in network
    catalogue=resources(owner)
    assert 'etc/rdc-services' in catalogue.paths and 'var/lib/rdc-services' in catalogue.paths
    assert catalogue.services==('rdc-service-proxy','rdc-element','rdc-synapse','rdc-postgres','tailscaled')
    assert 'usr/local/lib/rdc-services/service_images.json' in binary_paths(owner)
    assert 'etc/rdc-service-tls' not in catalogue.paths


def test_unknown_or_changed_application_scope_is_rejected():
    m=importlib.import_module('backup_scope');network,application=fixture()
    for key,value in [('node_name','another'),('images',{}),('packages',['unknown'])]:
        changed=dict(application,**{key:value})
        with pytest.raises(ValueError):m.include(network,changed)
    with pytest.raises(ValueError):m.include(dict(network,role='controller'),application)


def test_network_only_scope_never_implicitly_adopts_service_data():
    from backup_contracts import resources
    network,_=fixture()
    assert 'etc/rdc-services' not in resources(network).paths


def test_backup_transport_filters_application_snapshots():
    from backup_transport import Restic
    from test_backup_contracts import profile as backup_profile
    transport=Restic(backup_profile(),scope='matrix')
    calls=[]
    transport.execute=lambda args,**kwargs:calls.append(args) or '[]'
    assert transport.snapshots()==[]
    assert 'rdc-v1,rdc-matrix-v1' in calls[0]


def application_files(root):
    from service_rendering import synapse,logging_config,element,element_nginx,proxy
    from service_contracts import image_pins
    network,application=fixture();base=root/'etc/rdc-services';state=root/'var/lib/rdc-services'
    (base/'synapse').mkdir(parents=True);(state/'postgres/global').mkdir(parents=True);(state/'synapse').mkdir()
    generated={name:'a'*64 for name in ('database_password','registration_secret','macaroon_secret','form_secret')}
    settings={'schema_version':1,'ownership':application,'bind_address':'100.64.0.22','components':image_pins()}
    values={'ownership.json':json.dumps(application),'runtime.json':json.dumps(settings),'secrets.json':json.dumps(generated),
            'database-password':generated['database_password']+'\n','synapse/homeserver.yaml':synapse(profile(),generated),
            'synapse/log.config':logging_config(),'element.json':element(profile()),'element-nginx.conf':element_nginx(),
            'Caddyfile':proxy(profile(),'100.64.0.22')}
    for name,content in values.items():(base/name).write_text(content)
    (state/'postgres/PG_VERSION').write_text('17\n');(state/'postgres/global/pg_control').write_bytes(b'database control')
    (state/'synapse/server.signing.key').write_text('ed25519 example '+'a'*64)
    (root/'etc/server-connectivity-profile.json').write_text(json.dumps(network))
    return network,application


def test_snapshot_rejects_unreviewed_configuration_and_running_database(tmp_path):
    from service_backup import validate_data
    _,application=application_files(tmp_path);validate_data(tmp_path,application)
    path=tmp_path/'var/lib/rdc-services/postgres/postmaster.pid';path.write_text('10')
    with pytest.raises(ValueError,match='shut down'):validate_data(tmp_path,application)
    path.unlink()
    path=tmp_path/'etc/rdc-services/synapse/homeserver.yaml';path.write_text(path.read_text()+'extra: true\n')
    with pytest.raises(ValueError,match='configuration differs'):validate_data(tmp_path,application)


def test_application_snapshot_stops_writers_before_database_and_restarts_dependencies_first(tmp_path):
    from backup_scope import include
    from backup_contracts import resources,binary_paths
    from backup_snapshot import capture
    from backup_operations import validate_restore
    from test_backup_snapshot import Services
    root=tmp_path/'source';network,application=application_files(root);owner=include(network,application)
    (root/'var/lib/tailscale').mkdir()
    for name in binary_paths(owner):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixed identity')
    services=Services(active=resources(owner).services)
    stage=tmp_path/'snapshot';capture(root,stage,owner,services=services)
    assert services.events[:5]==[('stop',n) for n in resources(owner).services]
    assert services.events[5:]==[('start',n) for n in reversed(resources(owner).services)]
    assert validate_restore(stage,owner)['ownership']['applications']==application

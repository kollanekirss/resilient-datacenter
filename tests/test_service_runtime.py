import importlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_service_contracts import profile
from test_setup_contracts import manifest
from setup_contracts import local_ownership
from service_contracts import ownership,image_pins


def api():return importlib.import_module('service_runtime')


def settings():
    return {'schema_version':1,'ownership':ownership(profile(),local_ownership(manifest())),'bind_address':'100.64.0.22','components':image_pins()}


def test_container_commands_use_fixed_images_and_no_public_port_mapping():
    m=api()
    for name in ('postgres','synapse','element','proxy'):
        command=m.container_command(name,settings())
        assert '--network=host' in command and '--pull=never' in command
        assert '--privileged' not in command and '--publish' not in command and '-p' not in command
        assert '--cap-drop=ALL' in command and '--security-opt=no-new-privileges' in command
        assert settings()['components'][name]['image'] in command
        assert not any('PASSWORD=' in a for a in command)
    command=m.container_command('element',settings())
    assert '--entrypoint=nginx' in command
    assert '--user=991:991' in m.container_command('synapse',settings())
    with pytest.raises(ValueError):m.container_command('shell',settings())


def test_existing_container_requires_matching_owner_component_and_image():
    m=api();config=settings();digest=m.owner_digest(config)
    record={'Config':{'Labels':{'org.rdc.owner':digest,'org.rdc.component':'synapse'}},'Image':config['components']['synapse']['config_digest']}
    m.validate_container(record,'synapse',config)
    for wrong in ('owner','image','component'):
        changed=json.loads(json.dumps(record))
        if wrong=='image':changed['Image']='sha256:'+'0'*64
        else:changed['Config']['Labels']['org.rdc.'+wrong]='different'
        with pytest.raises(ValueError):m.validate_container(changed,'synapse',config)


def test_unit_readiness_precedes_dependent_proxy_and_database_is_not_public():
    m=api();unit=m.unit('proxy')
    assert 'After=' in unit and 'rdc-synapse.service' in unit and 'rdc-element.service' in unit
    assert 'ready proxy' in unit and 'stop proxy' in unit
    postgres=m.container_command('postgres',settings())
    assert 'listen_addresses=127.0.0.1' in postgres and 'port=5433' in postgres

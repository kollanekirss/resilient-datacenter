import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from setup_contracts import local_ownership
from test_setup_contracts import manifest


def profile():
    return {'kind':'matrix-services','schema_version':1,'institution_id':'south','node_name':'home-services',
            'matrix_hostname':'matrix.south.test','element_hostname':'chat.south.test','tls_mode':'supplied',
            'tls_certificate':'/private/services.crt','tls_private_key':'/private/services.key'}


def api():return importlib.import_module('service_contracts')


def test_service_identity_is_separate_but_bound_to_exact_enrolled_node():
    m=api();data=profile();network=local_ownership(manifest())
    assert m.validate(data)==[]
    owner=m.ownership(data,network)
    assert owner['network']==network and owner['role']=='services'
    with pytest.raises(ValueError):m.ownership(dict(data,node_name='different'),network)
    assert m.validate(dict(data,element_hostname=data['matrix_hostname']))

@pytest.mark.parametrize('extra',[{'command':'id'},{'image':'evil/image:latest'},{'admin_password':'secret'},{'listen_address':'0.0.0.0'},{'podman_options':['--privileged']}])
def test_profile_never_accepts_commands_image_overrides_or_secrets(extra):
    assert api().validate(dict(profile(),**extra))


def test_stable_hostname_and_network_changes_require_migration():
    m=api();p=profile();network=local_ownership(manifest());owner=m.ownership(p,network)
    assert m.same_installation(p,network,owner)
    for changed in (dict(p,matrix_hostname='new.south.test'),dict(p,element_hostname='new.south.test')):
        assert not m.same_installation(changed,network,owner)
    assert not m.same_installation(p,dict(network,controller_hostname='new.south.test'),owner)


def test_component_catalogue_uses_only_fixed_immutable_amd64_images():
    pins=api().image_pins()
    assert set(pins)=={'synapse','element','postgres','proxy'}
    for item in pins.values():
        assert '@sha256:' in item['image'] and item['platform']=='linux/amd64'
        assert ':latest' not in item['image']

"""The portable profile must be explicit and bound to one site's LAN identity."""
import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


def access():
    return {'mode': 'portable-lan', 'site': 'south', 'site_sha256': 'a' * 64,
            'backend_address': '10.76.40.10', 'frontend_address': '10.76.30.11'}


def api():
    return importlib.import_module('application_access')


def test_explicit_portable_identity_and_roundtrip():
    m = api()
    profile = {'institution_id': 'south', 'node_name': 'south-chat', 'access': access()}
    owner = m.portable_owner(profile)
    assert owner['role'] == 'portable'
    assert owner['access'] == access()
    assert m.validate_portable_owner(owner) == owner
    assert m.bind_address(owner) == '10.76.40.10'
    assert m.frontend_address(owner) == '10.76.30.11'
    assert 'controller_hostname' not in owner
    owner['access']['backend_address'] = '10.76.40.20'
    assert profile['access']['backend_address'] == '10.76.40.10'


@pytest.mark.parametrize('change', [
    {'mode': 'overlay'}, {'site_sha256': '../invalid'}, {'site': 'x;id'},
    {'backend_address': '0.0.0.0'}, {'backend_address': '100.64.0.1'},
    {'backend_address': '127.0.0.1'}, {'backend_address': '8.8.8.8'},
    {'backend_address': '::1'}, {'backend_address': '10.076.40.10'},
    {'frontend_address': '10.76.40.10'}, {'frontend_address': None},
    {'command': 'id'},
])
def test_unsafe_access_is_rejected(change):
    with pytest.raises(ValueError):
        api().validate_access(dict(access(), **change))


def test_owner_fields_and_types_are_exact():
    m = api()
    owner = m.portable_owner({'institution_id': 'south', 'node_name': 'chat', 'access': access()})
    for change in ({'role': 'peer'}, {'schema_version': True}, {'node_name': '../chat'},
                   {'controller_hostname': 'headscale.example.org'}, {'institution_id': ''}):
        with pytest.raises(ValueError):
            m.validate_portable_owner(dict(owner, **change))


def test_overlay_never_silently_accepts_lan_addresses():
    m = api()
    m.validate_binding({'role': 'peer'}, '100.64.0.1')
    with pytest.raises(ValueError):
        m.validate_binding({'role': 'peer'}, '10.76.40.10')
    owner = m.portable_owner({'institution_id': 'south', 'node_name': 'chat', 'access': access()})
    m.validate_binding(owner, '10.76.40.10')
    with pytest.raises(ValueError):
        m.validate_binding(owner, '10.76.40.11')
    with pytest.raises(ValueError):
        m.validate_binding(owner, '100.64.0.1')
    with pytest.raises(ValueError):
        m.validate_binding({'role': 'unknown'}, '100.64.0.1')


@pytest.mark.parametrize('value', [None, [], 'portable', True])
def test_non_object_profile_fails_as_validation_error(value):
    with pytest.raises(ValueError):
        api().portable_owner(value)


@pytest.mark.parametrize('module', ['service_contracts', 'nextcloud_contracts'])
def test_profiles_require_matching_portable_identity_and_roundtrip(module):
    import service_contracts
    import nextcloud_contracts
    import backup_scope
    from test_service_contracts import profile as matrix_profile
    from test_nextcloud_contracts import profile as files_profile
    m = importlib.import_module(module)
    profile = (matrix_profile() if module == 'service_contracts' else files_profile())
    profile['access'] = access()
    assert m.validate(profile) == []
    network = api().portable_owner(profile)
    owner = m.ownership(profile, network)
    restored = backup_scope.application_profile(owner)
    assert restored['access'] == profile['access']
    assert m.ownership(restored, network) == owner
    changed = dict(network, access=dict(access(), frontend_address='10.76.30.12'))
    with pytest.raises(ValueError):
        m.ownership(profile, changed)
    legacy = dict(profile)
    del legacy['access']
    with pytest.raises(ValueError):
        m.ownership(legacy, network)


def test_portable_profiles_are_derived_from_site_plan():
    import json
    root = Path(__file__).resolve().parents[1]
    plan = json.loads((root/'examples/portable-site.json').read_text())
    m = importlib.import_module('portable_applications')
    profiles = m.profiles(plan)
    assert set(profiles) == {'chat', 'files'}
    for role, profile in profiles.items():
        assert profile['access']['backend_address'] == plan['vms'][role]['address']
        assert profile['access']['frontend_address'] == plan['vms']['nginx']['address']
        assert profile['institution_id'] == plan['site']
        assert profile['node_name'] == role

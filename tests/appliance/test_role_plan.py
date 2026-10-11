import copy

import pytest

from appliance.contracts import ApplianceError
from appliance.plan import validate_site


def select(site, role):
    vm = copy.deepcopy(site['vms']['probe'])
    vm.update(role=role, vmid=103, name='pilot-' + role)
    vm['nics'] = [{'zone': 'infrastructure', 'mac': '02:bb:00:00:00:06',
                   'address': '10.77.1.10', 'connected': False}]
    site['vms'][role] = vm
    site['roles'][role] = {'selected': True}


def test_selected_connector_requires_controller(site, release):
    select(site, 'connector')
    with pytest.raises(ApplianceError, match='role-settings-missing'):
        validate_site(site, release)


def test_connector_has_no_hosting_settings(site, release):
    select(site, 'connector')
    site['roles']['connector'].update(controller='https://control.example.org', authority='oops')
    with pytest.raises(ApplianceError, match='unknown-field'):
        validate_site(site, release)


@pytest.mark.parametrize('controller', ['https://control.example.org/path', 'https://127.0.0.1',
                                         'https://control.example.org/../'])
def test_controller_must_be_a_hostname_origin(site, release, controller):
    select(site, 'connector')
    site['roles']['connector']['controller'] = controller
    with pytest.raises(ApplianceError):
        validate_site(site, release)


def test_headscale_accepts_declared_upstream_dnat(site, release):
    select(site, 'headscale')
    site['roles']['headscale'].update(authority='school', hostname='control.example.org',
        public_ipv4='8.8.4.4', certificate_ref='school-tls', exposure='upstream-dnat',
        upstream_owner='network-team')
    assert validate_site(site, release) == site


def test_headscale_dnat_needs_owned_upstream(site, release):
    select(site, 'headscale')
    site['roles']['headscale'].update(authority='school', hostname='control.example.org',
        public_ipv4='8.8.4.4', certificate_ref='school-tls', exposure='upstream-dnat')
    with pytest.raises(ApplianceError, match='upstream-owner-required'):
        validate_site(site, release)

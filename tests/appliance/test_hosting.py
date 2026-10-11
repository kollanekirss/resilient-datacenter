import copy
import time

import pytest

from appliance.contracts import ApplianceError, identity
from appliance.hosting import eligibility, endpoint_owners, prerequisites
from hosting_fixtures import hosting_site
from hosting_fixtures import certificates


def test_real_tls_checks_key_chain_name_and_expiry(tmp_path):
    from appliance.guest.hosting import validate_tls
    credentials = certificates()
    result = validate_tls('control.example.net', credentials)
    assert result['valid'] is True
    assert result['renewal_due'] is False
    assert 'PRIVATE' not in str(result)
    for mutation in ('name', 'key', 'trust', 'expiry'):
        bad = dict(credentials)
        name = 'wrong.example.net' if mutation == 'name' else 'control.example.net'
        if mutation == 'key': bad['private_key_pem'] = certificates()['private_key_pem']
        if mutation == 'trust': bad['trust_pem'] = certificates()['trust_pem']
        if mutation == 'expiry': bad = certificates(lifetime_days=-1)
        with pytest.raises(ApplianceError, match='hosting-tls-invalid'):
            validate_tls(name, bad)


def test_renewal_warning_is_separate_from_validity():
    from appliance.guest.hosting import validate_tls
    result = validate_tls('control.example.net', certificates(lifetime_days=10))
    assert result['valid'] is True
    assert result['renewal_due'] is True


def test_two_names_cannot_share_public_443(site):
    plan = hosting_site(site)
    plan['roles']['derp']['public_ipv4'] = plan['roles']['headscale']['public_ipv4']
    with pytest.raises(ApplianceError, match='public-endpoint-conflict'):
        endpoint_owners(plan)


def test_other_endpoint_owners_also_collide(site):
    plan = hosting_site(site)
    plan['publications'] = [{'public_ipv4': '8.8.4.4', 'protocol': 'tcp', 'port': 443, 'owner': 'router-administration'}]
    with pytest.raises(ApplianceError, match='public-endpoint-conflict'):
        endpoint_owners(plan)


@pytest.mark.parametrize('address', ['192.168.1.5', '100.64.1.2', '198.51.100.10', '127.0.0.1', '224.0.0.1', '0.0.0.0'])
def test_reserved_or_private_public_endpoint_is_ineligible(site, address):
    plan = hosting_site(site, both=False)
    plan['roles']['headscale']['public_ipv4'] = address
    result = eligibility(plan, {}, 'headscale')
    assert result['state'] == 'blocked'
    assert 'public-ipv4-required' in result['reasons']


def test_absence_never_means_success_or_erases_configured_identity(site):
    plan = hosting_site(site)
    original = copy.deepcopy(plan)
    for role in ('headscale', 'derp'):
        result = eligibility(plan, {}, role)
        assert result['state'] == 'unknown'
        assert result['prerequisites'] is True
        assert result['configured'] is False
        assert result['verified'] is False
    assert plan == original


def test_nat_headscale_can_qualify_without_qualifying_nat_relay(site):
    plan = hosting_site(site)
    assert prerequisites(plan, 'headscale') == []
    plan['vms']['derp']['nics'][0]['address'] = '10.77.1.15'
    assert 'derp-public-address-on-guest-required' in prerequisites(plan, 'derp')
    assert eligibility(plan, {}, 'headscale')['prerequisites'] is True


def test_selected_false_is_not_selected(site):
    assert eligibility(site, {}, 'headscale')['state'] == 'not-selected'


def test_forged_unbound_or_expired_evidence_does_not_verify(site):
    plan = hosting_site(site)
    for proof in ({'state': 'verified'}, {'state': 'verified', 'plan_id': identity(plan), 'checked_at': 1}):
        result = eligibility(plan, {'probe_evidence': proof}, 'headscale')
        assert result['verified'] is False


def test_direct_headscale_requires_actual_router_public_address(site):
    plan = hosting_site(site, both=False)
    plan['roles']['headscale']['exposure'] = 'direct'
    assert 'headscale-direct-wan-mismatch' in prerequisites(plan, 'headscale')


def test_verified_proof_must_match_current_role_endpoint_cert_config_and_service(site):
    from appliance.probes import REQUIREMENTS
    plan = hosting_site(site)
    guest = {'plan_id': identity(plan), 'role': 'headscale', 'configured': True,
        'running': True, 'identity': 'a' * 64, 'config_id': 'b' * 64, 'policy_id': 'c' * 64,
        'certificate_id': 'd' * 64, 'tls': {'valid': True}, 'checked_at': int(time.time())}
    proof = {'schema': 1, 'state': 'verified', 'capability': 'controller',
        'plan_id': identity(plan), 'build_id': 'e' * 64, 'probe_id': 'independent-one',
        'checked_at': int(time.time()), 'observations': dict.fromkeys(REQUIREMENTS['controller'], True),
        'dependencies': {'plan': identity(plan), 'role_identity': 'a' * 64, 'config': 'b' * 64,
                         'policy': 'c' * 64, 'certificate': 'd' * 64},
        'targets': [{'expect': 'public-tls', 'url': 'https://control.example.net/health',
                     'expected_ipv4': '8.8.4.4', 'tls_sha256': 'd' * 64}]}
    assert eligibility(plan, {'guest': guest, 'probe_evidence': proof}, 'headscale')['state'] == 'verified'
    for fault in ('url', 'public-address', 'cert', 'config', 'policy', 'stopped', 'expired', 'stale'):
        local, remote = copy.deepcopy(guest), copy.deepcopy(proof)
        if fault == 'url': remote['targets'][0]['url'] = 'https://unrelated.example.net/health'
        if fault == 'public-address': remote['targets'][0]['expected_ipv4'] = '8.8.8.8'
        if fault == 'cert': local['certificate_id'] = 'e' * 64
        if fault == 'config': local['config_id'] = 'f' * 64
        if fault == 'policy': local['policy_id'] = 'a' * 64
        if fault == 'stopped': local['running'] = False
        if fault == 'expired': local['tls']['valid'] = False
        if fault == 'stale': local['checked_at'] -= 61
        assert eligibility(plan, {'guest': local, 'probe_evidence': remote}, 'headscale')['state'] != 'verified'

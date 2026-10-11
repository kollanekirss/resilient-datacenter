import importlib
import json

import pytest


def checks():
    return importlib.import_module('appliance.checks')


def test_generic_pass_cannot_verify_missing_network_observations(site):
    result = checks().evaluate('router', {'passed': True, 'clock_trusted': True}, site, 'build-one', now=100)
    assert result['state'] == 'blocked'


def test_valid_dns_evidence_requires_query_and_server_control(site):
    observations = {'clock_trusted': True, 'dependencies': {'router_boot': 'boot-a', 'policy': 'a' * 64},
                    'server_listener': True, 'query_answer': True}
    result = checks().evaluate('dns', observations, site, 'build-one', now=100)
    assert result['state'] == 'verified'
    assert checks().current(result, result['dependencies'], now=101)
    assert not checks().current(result, {**result['dependencies'], 'router_boot': 'boot-b'}, now=101)
    observations['server_listener'] = False
    assert checks().evaluate('dns', observations, site, 'build-one', now=100)['state'] == 'blocked'


@pytest.mark.parametrize('now', [99, 401])
def test_stale_or_future_evidence_is_not_current(site, now):
    evidence = checks().evaluate('time', {'clock_trusted': True, 'ntp_listener': True, 'ntp_response': True,
        'dependencies': {'router_boot': 'a', 'policy': 'b'}}, site, 'build-one', now=100)
    assert not checks().current(evidence, evidence['dependencies'], now=now)


def test_unsynchronized_clock_cannot_produce_verified_status(site):
    result = checks().evaluate('time', {'ntp_listener': True, 'ntp_response': True,
        'clock_trusted': False}, site, 'build-one', now=100)
    assert result['state'] == 'unknown'


def test_diagnostics_are_allowlists_not_redacted_private_dicts(site):
    observations = {'clock_trusted': True, 'password': 'TOP_SECRET',
                    'dependencies': {'password': 'TOP_SECRET'}, 'stderr': 'TOP_SECRET'}
    result = checks().evaluate('router', observations, site, 'build-one', now=100)
    site['roles']['connector']['auth_key'] = 'TOP_SECRET'
    assert 'TOP_SECRET' not in json.dumps(result)
    assert 'TOP_SECRET' not in json.dumps(checks().attachment(site))


def test_missing_negative_control_cannot_verify_isolation(site):
    observations = {'clock_trusted': True, 'source_control': True, 'destination_control': False,
                    'denied_probe': True, 'dependencies': {'host_boot': 'a', 'policy': 'b'}}
    assert checks().evaluate('isolation', observations, site, 'build-one', now=100)['state'] == 'blocked'


def test_release_requires_all_cases_and_rejects_fixture_evidence():
    assert not checks().base_release_allowed([], physical=True, now=100)
    records = [{'schema': 1, 'capability': case, 'state': 'verified', 'checked_at': 100,
        'plan_id': 'a' * 64, 'build_id': 'b' * 64, 'dependencies': {'plan': 'a' * 64, 'build': 'b' * 64},
        'environment': 'physical', 'source': 'acceptance-runner', 'test_only': True}
        for case in checks().BASE_CASES]
    assert not checks().base_release_allowed(records, physical=True, now=100)
    for record in records: record['test_only'] = False
    # A label with no case assertions, runtime identities or captured evidence
    # is not acceptance, even if its author removes the fixture marker.
    assert not checks().base_release_allowed(records, physical=True, now=100)
    records[0]['state'] = 'unknown'
    assert not checks().base_release_allowed(records, physical=True, now=100)

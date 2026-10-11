import copy
import hashlib

import pytest

from appliance import checks
from appliance.acceptance import required_assertions


@pytest.fixture
def qualification(tmp_path):
    # Fabricated records exercise integrity rules only. No machine was tested.
    base, roles = [], []
    for name, assertions in [(n, required_assertions(n)) for n in sorted(checks.BASE_CASES)] + \
                            [(n, checks.ROLE_REQUIREMENTS[n]) for n in sorted(checks.ROLE_REQUIREMENTS)]:
        path = tmp_path / (name + '.log'); path.write_text('Unit contract fixture only.')
        record = {'schema': 1, 'capability': name, 'case_id': name, 'state': 'verified', 'status': 'PASS',
            'checked_at': 100, 'plan_id': 'a' * 64, 'build_id': 'b' * 64, 'source': 'acceptance-runner',
            'method': 'real-execution', 'test_only': False, 'environment': 'physical',
            'dependencies': {'plan': 'a' * 64, 'build': 'b' * 64, 'source': 'c' * 64,
                             'spec': 'd' * 64, 'run': 'e' * 64, 'host_boot': 'boot-one'},
            'assertions': [{'name': n, 'passed': True} for n in assertions],
            'evidence': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]}
        (base if name in checks.BASE_CASES else roles).append(record)
    summary = {'schema': 1, 'build_id': 'b' * 64, 'source_id': 'c' * 64, 'spec_id': 'd' * 64,
        'lock_id': 'f' * 64, 'test_only': False, 'physical_profile': 'two-port-x86-uefi',
        'independent_endpoint': {'id': 'remote-one', 'host_id': 'remote-host', 'admin_id': 'remote-owner',
                                 'appliance_host_id': 'local-host', 'appliance_admin_id': 'local-owner',
                                 'key_sha256': '1' * 64},
        'resources': {name: {'memory_mib': 1024, 'disk_bytes': 1024, 'measured': True}
                      for name in ('host', 'router', 'probe', 'connector', 'headscale', 'derp')}}
    for item in roles:
        item['dependencies'].update(lock='f' * 64, probe=checks.identity(summary['independent_endpoint']))
    return base, roles, summary


def test_base_only_cannot_qualify_v1():
    assert not checks.v1_release_allowed([], [], {})


def test_complete_integrity_contract_does_not_claim_actual_execution(qualification):
    assert checks.v1_release_allowed(*qualification, now=100)


@pytest.mark.parametrize('fault', ['missing-role', 'not-run', 'fixture', 'changed-source', 'missing-assertion',
    'missing-resources', 'same-endpoint', 'same-admin', 'no-physical', 'wrong-lock', 'changed-probe', 'stale'])
def test_whole_product_gate_rejects_partial_or_stale_evidence(qualification, fault):
    base, roles, summary = qualification
    if fault == 'missing-role': roles.pop()
    elif fault == 'not-run': roles[0]['state'] = 'unknown'
    elif fault == 'fixture': roles[0]['test_only'] = True
    elif fault == 'changed-source': roles[0]['dependencies']['source'] = '0' * 64
    elif fault == 'missing-assertion': roles[0]['assertions'].pop()
    elif fault == 'missing-resources': summary['resources'].pop('derp')
    elif fault == 'same-endpoint': summary['independent_endpoint']['host_id'] = 'local-host'
    elif fault == 'same-admin': summary['independent_endpoint']['admin_id'] = 'local-owner'
    elif fault == 'no-physical': base[:] = [r for r in base if r['case_id'] != 'physical-operator']
    elif fault == 'wrong-lock': roles[0]['dependencies']['lock'] = '0' * 64
    elif fault == 'changed-probe': roles[0]['dependencies']['probe'] = '0' * 64
    elif fault == 'stale': roles[0]['checked_at'] = -90000
    assert not checks.v1_release_allowed(base, roles, summary, now=100)

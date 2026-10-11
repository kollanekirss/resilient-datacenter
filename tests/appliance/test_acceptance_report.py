"""Acceptance result integrity is necessary, never evidence authenticity."""
import copy
import hashlib
from pathlib import Path

import pytest


def sample(tmp_path):
    path = tmp_path / 'observations.json'
    path.write_bytes(b'{"captured":"observations"}\n')
    return {'schema': 1, 'case_id': 'offline-install', 'capability': 'offline-install',
            'state': 'verified', 'status': 'PASS', 'checked_at': 100,
            'plan_id': 'a' * 64, 'build_id': 'b' * 64,
            'dependencies': {'plan': 'a' * 64, 'build': 'b' * 64, 'source': 'c' * 64,
                             'spec': 'd' * 64, 'run': 'e' * 64, 'host_boot': 'boot-one'},
            'source': 'acceptance-runner', 'method': 'real-execution', 'test_only': False,
            'environment': 'nested', 'assertions': [{'name': 'disk-only-boot', 'passed': True}],
            'evidence': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]}


def test_case_requires_exact_assertions_and_captured_bytes(tmp_path):
    from appliance.acceptance_report import case_problems
    record = sample(tmp_path)
    assert case_problems(record, {'disk-only-boot'}, now=100) == []
    assert 'assertion-membership' in case_problems(record, {'disk-only-boot', 'usb-removed'}, now=100)
    Path(record['evidence'][0]['path']).write_bytes(b'changed')
    assert 'evidence-content' in case_problems(record, {'disk-only-boot'}, now=100)


@pytest.mark.parametrize('change,reason', [
    ({'test_only': True}, 'synthetic-result'),
    ({'fixture': True}, 'synthetic-result'),
    ({'method': 'unit-fixture'}, 'synthetic-result'),
    ({'environment': 'nested-fixture'}, 'synthetic-result'),
    ({'checked_at': 101}, 'timestamp'),
    ({'checked_at': -90000}, 'timestamp'),
    ({'checked_at': True}, 'timestamp'),
    ({'status': 'NOT RUN'}, 'case-not-passed'),
    ({'state': 'unknown'}, 'case-not-passed'),
    ({'evidence': []}, 'evidence-missing'),
    ({'assertions': [{'name': 'disk-only-boot', 'passed': 1}]}, 'assertion-failed'),
    ({'assertions': [{'name': 'disk-only-boot', 'passed': True}] * 2}, 'assertion-membership'),
    ({'assertions': [{'name': 'disk-only-boot', 'passed': True}, {'name': 'unexpected', 'passed': True}]}, 'assertion-membership'),
])
def test_unproven_case_is_rejected(tmp_path, change, reason):
    from appliance.acceptance_report import case_problems
    record = sample(tmp_path); record.update(change)
    assert reason in case_problems(record, {'disk-only-boot'}, now=100)


def test_runtime_and_configuration_dependencies_required(tmp_path):
    from appliance.acceptance_report import case_problems
    record = sample(tmp_path)
    for key in ('plan', 'build', 'source', 'spec', 'run', 'host_boot'):
        changed = copy.deepcopy(record); del changed['dependencies'][key]
        assert case_problems(changed, {'disk-only-boot'}, now=100), key
    record['dependencies']['plan'] = 'f' * 64
    assert 'dependency-identity' in case_problems(record, {'disk-only-boot'}, now=100)


def test_physical_case_cannot_be_satisfied_by_a_vm(tmp_path):
    from appliance.acceptance_report import case_problems
    record = sample(tmp_path); record['case_id'] = record['capability'] = 'physical-operator'
    assert 'physical-evidence-required' in case_problems(record, {'disk-only-boot'}, now=100)


@pytest.mark.parametrize('bad', [None, [], 'yes', {'assertions': None}, {'dependencies': []}])
def test_malformed_records_fail_closed(bad):
    from appliance.acceptance_report import case_problems
    assert case_problems(bad, {'disk-only-boot'}, now=100)


def test_public_report_does_not_print_private_observations():
    from appliance.acceptance_report import human_report, exit_code
    report = {'suite': 'all', 'status': 'PARTIAL', 'qualification': 'NOT RUN',
              'identities': {'build_id': 'b' * 64, 'secret': 'DO-NOT-PRINT'},
              'cases': [{'case_id': 'offline-install', 'status': 'PASS',
                         'observations': {'password': 'DO-NOT-PRINT'}},
                        {'case_id': 'physical-operator', 'status': 'NOT RUN'}]}
    text = human_report(report)
    assert 'offline-install: PASS' in text and 'physical-operator: NOT RUN' in text
    assert 'DO-NOT-PRINT' not in text
    assert exit_code(report) == 2


def test_complete_report_requires_common_context_even_when_individual_cases_pass(tmp_path):
    import time
    from appliance.acceptance import required_assertions
    from appliance.acceptance_report import exit_code
    from appliance.lab import SUITES
    baseline = sample(tmp_path)
    cases = []
    for case in SUITES['automated']:
        record = copy.deepcopy(baseline)
        record.update(case_id=case, capability=case, checked_at=int(time.time()),
                      assertions=[{'name': name, 'passed': True} for name in required_assertions(case)])
        cases.append(record)
    report = {'suite': 'automated', 'status': 'PASS', 'cases': cases,
              'identities': {key + '_id': baseline['dependencies'][key] for key in ('plan', 'build', 'source', 'spec', 'run')}}
    assert exit_code(report) == 0
    cases[-1]['dependencies']['run'] = 'f'*64
    assert exit_code(report) == 2
    report['status'] = 'FAIL'
    assert exit_code(report) == 1
    # A PASS label without verified cases cannot yield a successful exit.
    report['status'] = 'PASS'
    assert exit_code(report) == 2

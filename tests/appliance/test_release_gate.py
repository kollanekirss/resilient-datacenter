import copy
import hashlib
import time

import pytest

from appliance.acceptance import required_assertions
from appliance.checks import BASE_CASES, base_release_allowed


@pytest.fixture
def records(tmp_path):
    result = []
    for case in sorted(BASE_CASES):
        path = tmp_path / (case + '.log')
        path.write_text('Fixture bytes used only to test the integrity validator.\n')
        result.append({'schema': 1, 'capability': case, 'case_id': case,
                       'state': 'verified', 'status': 'PASS', 'checked_at': 100,
                       'plan_id': 'a' * 64, 'build_id': 'b' * 64,
                       'source': 'acceptance-runner', 'method': 'real-execution', 'test_only': False,
                       'environment': 'physical', 'dependencies': {'plan': 'a' * 64, 'build': 'b' * 64,
                           'source': 'c' * 64, 'spec': 'd' * 64, 'run': 'e' * 64, 'host_boot': 'boot-' + case},
                       'assertions': [{'name': name, 'passed': True} for name in required_assertions(case)],
                       'evidence': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]})
    return result


def test_integrity_validator_requires_all_cases_but_does_not_authenticate_author(records):
    # Deliberately constructed labels test validation. Executing adapters force
    # fixture markers; this test is not a physical acceptance submission.
    assert base_release_allowed(records, physical=True, now=100)
    records[0]['test_only'] = True
    assert not base_release_allowed(records, physical=True, now=100)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'failed-assertion', 'missing-assertion',
    'extra-assertion', 'stale', 'different-run', 'different-build', 'different-spec', 'different-source',
    'missing-boot', 'missing-evidence', 'unrun', 'nested-physical', 'changed-file'])
def test_release_rejects_incomplete_or_mixed_runs(records, mutation):
    first = records[0]
    if mutation == 'missing': records.pop()
    elif mutation == 'duplicate': records.append(copy.deepcopy(first))
    elif mutation == 'failed-assertion': first['assertions'][0]['passed'] = False
    elif mutation == 'missing-assertion': first['assertions'].pop()
    elif mutation == 'extra-assertion': first['assertions'].append({'name': 'unreviewed', 'passed': True})
    elif mutation == 'stale': first['checked_at'] = -90000
    elif mutation.startswith('different-'):
        key = mutation.removeprefix('different-'); first['dependencies'][key] = 'f' * 64
        if key == 'build': first['build_id'] = 'f' * 64
    elif mutation == 'missing-boot': del first['dependencies']['host_boot']
    elif mutation == 'missing-evidence': first['evidence'] = []
    elif mutation == 'unrun': first['status'] = 'NOT RUN'
    elif mutation == 'nested-physical': first['environment'] = 'nested'
    elif mutation == 'changed-file':
        from pathlib import Path
        Path(first['evidence'][0]['path']).write_text('changed')
    assert not base_release_allowed(records, physical=True, now=100)


def test_complete_nested_run_does_not_satisfy_physical_acceptance(records):
    records = [r for r in records if r['case_id'] != 'physical-operator']
    for record in records: record['environment'] = 'nested'
    assert base_release_allowed(records, physical=False, now=100)
    assert not base_release_allowed(records, physical=True, now=100)

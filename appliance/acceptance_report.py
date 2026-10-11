"""Strict captured-result integrity and allowlisted public acceptance reports.

This checks records from the executing driver. It does not authenticate supplied
JSON, authorize a machine, or certify that an external author ran a test.
"""
from pathlib import Path
import re
import time

from .lab import file_sha256

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_AGE_SECONDS = 24 * 60 * 60


def _digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) is not None


def case_problems(record, expected_assertions, *, now=None, max_age_s=MAX_AGE_SECONDS):
    """Reject missing assertions, fixture provenance and altered evidence files."""
    now = int(time.time()) if now is None else now
    if type(record) is not dict:
        return ['case-record']
    problems = []
    case = record.get('case_id')
    if record.get('schema') != 1 or not _identifier(case) or record.get('capability') != case:
        problems.append('case-identity')
    if record.get('state') != 'verified' or record.get('status') != 'PASS':
        problems.append('case-not-passed')
    if (record.get('source') != 'acceptance-runner' or record.get('test_only') is not False
            or record.get('method') != 'real-execution' or record.get('environment') not in ('nested', 'physical')
            or any(record.get(key) for key in ('fixture', 'mock', 'simulated'))):
        problems.append('synthetic-result')
    if case == 'physical-operator' and record.get('environment') != 'physical':
        problems.append('physical-evidence-required')
    checked = record.get('checked_at')
    if (type(checked) is not int or type(now) is not int or type(max_age_s) is not int
            or not 0 <= now - checked <= max_age_s):
        problems.append('timestamp')
    deps = record.get('dependencies')
    if (type(deps) is not dict or not all(_digest(deps.get(key)) for key in ('plan', 'build', 'source', 'spec', 'run'))
            or deps.get('plan') != record.get('plan_id') or deps.get('build') != record.get('build_id')):
        problems.append('dependency-identity')
    if type(deps) is not dict or not _identifier(deps.get('host_boot')):
        problems.append('runtime-identity')
    assertions = record.get('assertions')
    expected = set(expected_assertions)
    if (not expected or type(assertions) is not list or not assertions
            or any(type(item) is not dict or not _identifier(item.get('name')) for item in assertions)):
        problems.append('assertion-membership')
    else:
        names = [item['name'] for item in assertions]
        if len(names) != len(set(names)) or set(names) != expected:
            problems.append('assertion-membership')
        if any(item.get('passed') is not True for item in assertions):
            problems.append('assertion-failed')
    evidence = record.get('evidence')
    if type(evidence) is not list or not evidence or len(evidence) > 128:
        problems.append('evidence-missing')
    else:
        paths = set()
        for item in evidence:
            if (type(item) is not dict or type(item.get('path')) is not str
                    or not _digest(item.get('sha256')) or item['path'] in paths):
                problems.append('evidence-record')
                continue
            paths.add(item['path'])
            try:
                path = Path(item['path'])
                # file_sha256 independently checks every ancestor, owner, inode,
                # regular-file type and unchanged metadata while hashing.
                if path.stat().st_size > MAX_EVIDENCE_BYTES or file_sha256(path) != item['sha256']:
                    problems.append('evidence-content')
            except (OSError, ValueError):
                problems.append('evidence-content')
    return list(dict.fromkeys(problems))


def human_report(report):
    """Never render arbitrary observations, commands, console logs or secrets."""
    status = report.get('status')
    status = status if status in ('PASS', 'FAIL', 'PARTIAL', 'NOT RUN') else 'NOT RUN'
    suite = report.get('suite')
    lines = ['Appliance acceptance: ' + status,
             'Suite: ' + (suite if _identifier(suite) else 'unknown'),
             'Physical qualification: NOT RUN']
    identifiers = report.get('identities', {})
    if type(identifiers) is dict:
        for key in ('build_id', 'plan_id', 'spec_id', 'source_id', 'run_id'):
            if _digest(identifiers.get(key)):
                lines.append(key.replace('_', ' ') + ': ' + identifiers[key])
    for case in report.get('cases', []):
        if type(case) is not dict or not _identifier(case.get('case_id')):
            continue
        value = case.get('status')
        lines.append(case['case_id'] + ': ' + (value if value in ('PASS', 'FAIL', 'OBSERVED', 'NOT RUN') else 'NOT RUN'))
    lines.append('Unit fixtures and unrun cases cannot satisfy machine acceptance.')
    return '\n'.join(lines) + '\n'


def exit_code(report):
    if report.get('status') == 'FAIL' or any(item.get('status') == 'FAIL' for item in report.get('cases', []) if type(item) is dict):
        return 1
    if report.get('status') != 'PASS':
        return 2
    from .lab import SUITES
    cases = report.get('cases', [])
    required = SUITES.get(report.get('suite'), ())
    if (not required or type(cases) is not list or any(type(item) is not dict for item in cases)
            or sorted(item.get('case_id', '') for item in cases) != sorted(required)):
        return 2
    from .acceptance import required_assertions
    identifiers = report.get('identities')
    if type(identifiers) is not dict:
        return 2
    expected = {key: identifiers.get(key + '_id') for key in ('plan', 'build', 'source', 'spec', 'run')}
    if not all(_digest(value) for value in expected.values()):
        return 2
    for item in cases:
        if (case_problems(item, required_assertions(item['case_id']))
                or any(item['dependencies'].get(key) != value for key, value in expected.items())):
            return 2
    return 0

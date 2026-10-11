import copy
import hashlib
import json
from pathlib import Path

import pytest

from appliance.contracts import canonical, identity
from test_lab_runner import execution


def full(config, tmp_path):
    config = copy.deepcopy(config)
    config['execution'].update(memory_mib=16384, vcpus=4)
    tools = {}
    for name in ('openssl', 'ssh', 'ssh-keygen'):
        path = tmp_path / name; path.write_bytes(b'fixture-not-executable'); path.chmod(0o700)
        tools[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    config['acceptance'] = {'enabled': True, 'case_timeout_seconds': 3600, 'tools': tools}
    return config


def test_missing_full_profile_tools_fail_before_worker(execution, tmp_path):
    from appliance.lab_acceptance_runner import inspect_full_execution
    config, platform = execution; config = full(config, tmp_path)
    del config['acceptance']['tools']['ssh']
    reasons = inspect_full_execution(config, {**platform, 'nested_kvm': True})
    assert 'acceptance-tools-required' in reasons


@pytest.mark.parametrize('key,value,reason', [
    ('enabled', False, 'acceptance-not-authorized'),
    ('case_timeout_seconds', 0, 'acceptance-timeout'),
    ('case_timeout_seconds', True, 'acceptance-timeout'),
])
def test_full_profile_has_no_implicit_execution(execution, tmp_path, key, value, reason):
    from appliance.lab_acceptance_runner import inspect_full_execution
    config, platform = execution; config = full(config, tmp_path)
    config['acceptance'][key] = value
    assert reason in inspect_full_execution(config, {**platform, 'nested_kvm': True})


def test_prelaunch_blocking_is_not_a_failed_guest(execution, tmp_path):
    from appliance.lab_acceptance_runner import execute_full_lab
    config, platform = execution; config = full(config, tmp_path)
    config['acceptance']['enabled'] = False
    def forbidden(*args, **kwargs): raise AssertionError('No worker may start')
    result = execute_full_lab(config, 'all', config_sha256=identity(config), _platform=platform, _worker_factory=forbidden)
    assert result['status'] == 'NOT RUN' and result['qualification'] == 'NOT RUN'
    assert all(case['status'] == 'NOT RUN' for case in result['cases'])


def test_full_execution_needs_nested_virtualization(execution, tmp_path):
    from appliance.lab_acceptance_runner import inspect_full_execution
    config, platform = execution; config = full(config, tmp_path)
    assert 'nested-kvm-unavailable' in inspect_full_execution(config, {**platform, 'nested_kvm': False})


def test_every_automated_case_gets_fresh_worker_and_fixtures_never_pass(execution, tmp_path, monkeypatch):
    from appliance import acceptance, lab_acceptance_runner as runner
    from appliance.lab import SUITES
    config, platform = execution; config = full(config, tmp_path)
    monkeypatch.setattr(runner, 'inspect_full_execution', lambda *args: [])
    workers = []
    class Worker:
        launched = True
        def __init__(self, config, context, directory, handles):
            self.context, self.directory, self.closed = context, directory, False
            workers.append(self)
        def close(self):
            self.closed = True
            return {'stopped': True}
    def case(case_id, worker, context):
        assert worker.context['case_id'] == case_id and not worker.closed
        return {'case_id': case_id, 'state': 'verified', 'status': 'PASS', 'reasons': [],
                'test_only': False, 'method': 'real-execution', 'assertions': [], 'evidence': []}
    monkeypatch.setattr(acceptance, 'run_case', case)
    result = runner.execute_full_lab(config, 'automated', config_sha256=identity(config),
                                     _platform=platform, _worker_factory=Worker)
    assert len(workers) == len(SUITES['automated']) and all(worker.closed for worker in workers)
    assert len({worker.directory for worker in workers}) == len(workers)
    assert result['status'] == 'NOT RUN'
    assert all(item['status'] == 'NOT RUN' and item['test_only'] is True for item in result['cases'])
    assert all(item['same_file'] and item['initial'] == item['final'] for item in result['input_digests'].values())
    assert Path(result['evidence_directory'], 'report.txt').is_file()


@pytest.mark.parametrize('failure', ['execution', 'cleanup'])
def test_worker_failure_closes_resources_and_preserves_synthetic_provenance(execution, tmp_path, monkeypatch, failure):
    from appliance import acceptance, lab_acceptance_runner as runner
    config, platform = execution; config = full(config, tmp_path)
    monkeypatch.setattr(runner, 'inspect_full_execution', lambda *args: [])
    closed = []
    class Worker:
        launched = True
        def __init__(self, *args): pass
        def close(self):
            closed.append(True)
            if failure == 'cleanup': raise TimeoutError()
            return {'stopped': True}
    def case(*args):
        if failure == 'execution': raise ValueError('PRIVATE-DIAGNOSTIC')
        return {'case_id': 'boot-menu-cancel', 'state': 'verified', 'status': 'PASS', 'reasons': []}
    monkeypatch.setattr(acceptance, 'run_case', case)
    result = runner.execute_full_lab(config, 'media-gate', config_sha256=identity(config),
                                     _platform=platform, _worker_factory=Worker)
    from appliance.lab import SUITES
    assert closed == [True] * len(SUITES['media-gate']) and result['status'] == 'NOT RUN'
    assert 'PRIVATE-DIAGNOSTIC' not in json.dumps(result)
    assert result['cases'][0]['test_only'] is True
    reason = 'lab-worker-unavailable' if failure == 'execution' else 'lab-worker-cleanup-failed'
    assert reason in result['cases'][0]['reasons']

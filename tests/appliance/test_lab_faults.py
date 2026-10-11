from pathlib import Path
from subprocess import CompletedProcess

import pytest

from appliance import state


@pytest.mark.parametrize('stage,changed', [('network-before-reload', False), ('network-after-reload', True),
                                        ('vm-create-response', True), ('vm-start-response', True)])
def test_real_child_exits_at_selected_boundary_without_unwinding(tmp_path, stage, changed):
    from appliance.lab_faults import run_interrupted, BoundaryRunner
    effect = tmp_path / 'effect'; unwound = tmp_path / 'finally'
    class Target:
        def run(self, argv, **kwargs):
            effect.write_text('observed mutation')
            return CompletedProcess(argv, 0, b'', b'')
    def operation(cut):
        wrapped = BoundaryRunner(Target(), stage, cut)
        command = ['/usr/sbin/ifreload', '-a'] if stage.startswith('network') else ['/usr/sbin/qm', 'create' if stage.startswith('vm-create') else 'start', '901']
        try: wrapped.run(command)
        finally: unwound.write_text('unwound')
    result = run_interrupted(tmp_path / 'fault', stage, operation, timeout_s=5)
    assert result['child_exit'] == 86 and result['boundary'] == stage
    assert effect.exists() is changed and not unwound.exists()
    assert result['mutation_counts'] == {stage: int(changed)}


def test_missing_boundary_is_failure_not_a_simulated_interruption(tmp_path):
    from appliance.lab_faults import run_interrupted
    from appliance.contracts import ApplianceError
    with pytest.raises(ApplianceError, match='lab-fault-boundary-not-reached'):
        run_interrupted(tmp_path / 'fault', 'vm-create-response', lambda cut: None, timeout_s=5)


def test_wrong_command_does_not_trigger_fault(tmp_path):
    from appliance.lab_faults import BoundaryRunner
    called = []
    class Target:
        def run(self, argv, **kwargs): return CompletedProcess(argv, 0, b'actual output', b'')
    wrapped = BoundaryRunner(Target(), 'router-policy-response', lambda *args: called.append(args))
    result = wrapped.run(['/usr/bin/ssh', 'root@router'], stdin=b'{"action":"inspect"}')
    assert result.stdout == b'actual output' and called == []


def test_child_error_records_only_stable_error_code(tmp_path):
    from appliance.lab_faults import run_interrupted
    from appliance.contracts import ApplianceError
    def fail(cut): raise RuntimeError('PRIVATE_CONFIGURATION')
    with pytest.raises(ApplianceError, match='lab-fault-operation-failed'):
        run_interrupted(tmp_path / 'fault', 'vm-create-response', fail, timeout_s=5)
    assert 'PRIVATE_CONFIGURATION' not in (tmp_path / 'fault' / 'result.json').read_text()


def test_resume_mutation_counter_measures_actual_attempt_even_when_command_fails(tmp_path):
    from appliance.lab_faults import ResumeRunner
    receipt = tmp_path / 'result.json'
    state.write(receipt, {'mutation_counts': {'vm-create-response': 1}})
    class Target:
        def run(self, argv, **kwargs):
            if argv[1] == 'create': raise ValueError('command failed')
            return CompletedProcess(argv, 0, b'{}', b'')
    runner = ResumeRunner(Target(), receipt)
    runner.run(['/usr/sbin/qm', 'config', '901'])
    assert state.read(receipt)['mutation_counts'] == {'vm-create-response': 1}
    with pytest.raises(ValueError): runner.run(['/usr/sbin/qm', 'create', '901'])
    assert state.read(receipt)['mutation_counts'] == {'vm-create-response': 1, 'resume_mutations': 1}


def test_resume_allows_rollback_reload_but_observes_new_application(tmp_path):
    from appliance.lab_faults import ResumeRunner
    receipt = tmp_path / 'result.json'; state.write(receipt, {'mutation_counts': {'network-after-reload': 1}})
    class Target:
        def run(self, argv, **kwargs): return CompletedProcess(argv, 0, b'', b'')
    runner = ResumeRunner(Target(), receipt)
    runner.run(['/usr/sbin/ifreload', '-a'])
    assert state.read(receipt)['mutation_counts'] == {'network-after-reload': 1}
    runner.run(['/usr/bin/systemctl', 'restart', 'rdc-network-rollback.timer'])
    assert state.read(receipt)['mutation_counts']['resume_mutations'] == 1

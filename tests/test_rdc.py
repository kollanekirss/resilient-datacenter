import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from test_setup_contracts import ROOT, manifest


def api(): return importlib.import_module('rdc')


def test_launcher_works_from_another_directory(tmp_path):
    result=subprocess.run([str(ROOT/'rdc'),'--help'],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==0 and 'infrastructure' in result.stdout and 'doctor' in result.stdout


def test_launcher_missing_environment_does_not_install(tmp_path):
    shutil.copy2(ROOT/'rdc',tmp_path/'rdc')
    result=subprocess.run([str(tmp_path/'rdc')],capture_output=True,text=True)
    assert result.returncode==3 and '.venv' in result.stderr
    assert sorted(p.name for p in tmp_path.iterdir())==['rdc']


def test_launcher_symlink_is_refused(tmp_path):
    (tmp_path/'alias').symlink_to(ROOT/'rdc')
    result=subprocess.run([str(tmp_path/'alias'),'version'],capture_output=True,text=True)
    assert result.returncode==3


def test_launcher_project_path_with_spaces(tmp_path):
    project=tmp_path/'project with spaces'; project.mkdir()
    shutil.copy2(ROOT/'rdc',project/'rdc')
    shutil.copytree(ROOT/'scripts',project/'scripts',ignore=shutil.ignore_patterns('__pycache__'))
    (project/'.venv').symlink_to(ROOT/'.venv',target_is_directory=True)
    result=subprocess.run([str(project/'rdc'),'version'],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==0 and 'unknown/unreleased' in result.stdout

@pytest.mark.parametrize('argv',[['node','apply','manifest','--extra-vars','SECRET'],['infrastructure','apply','manifest','--limit','a'],['setup','--out','x'],['unknown']])
def test_no_arbitrary_options_or_abbreviations(argv,capsys):
    assert api().main(argv)==2
    assert 'SECRET' not in capsys.readouterr().out


def test_node_status_preserves_pending_code(monkeypatch,tmp_path,capsys):
    m=api()
    from operation_results import result_for_state
    def status(action,path):
        assert action=='status' and path==tmp_path/'node'
        return result_for_state('awaiting_enrollment')
    monkeypatch.setattr(m,'execute_local',status)
    assert m.main(['node','status',str(tmp_path/'node')])==4
    assert 'approval' in capsys.readouterr().out.lower()


def test_setup_wizard_runs_without_any_install(tmp_path,monkeypatch):
    m=api(); replies=iter(['join','south','control.pilot.test','home-services','tag:home-services','yes'])
    monkeypatch.setattr('builtins.input',lambda _:next(replies))
    assert m.main(['setup','--output-dir',str(tmp_path)])==0
    assert json.loads((tmp_path/'BUNDLE.json').read_text())['state']=='prepared'
    assert (tmp_path/'node-home-services.yml').exists()


def test_noargs_noninteractive_prints_help(monkeypatch,capsys):
    monkeypatch.setattr(sys,'stdin',io.StringIO())
    assert api().main([])==0
    assert 'doctor' in capsys.readouterr().out


def test_menu_dispatches_same_node_status(monkeypatch,tmp_path):
    m=api()
    class Terminal(io.StringIO):
        def isatty(self): return True
    monkeypatch.setattr(sys,'stdin',Terminal())
    answers=iter(['7',str(tmp_path/'node')])
    monkeypatch.setattr('builtins.input',lambda _:next(answers))
    from operation_results import result_for_state
    def execute(action,path):
        assert action=='status' and path==tmp_path/'node'
        return result_for_state('enrolled')
    monkeypatch.setattr(m,'execute_local',execute)
    assert m.main([])==0


def test_doctor_report_does_not_include_manifest_or_raw_error(tmp_path,monkeypatch,capsys):
    m=api(); path=tmp_path/'manifest.json'; path.write_text(json.dumps(manifest()))
    from operation_results import check
    monkeypatch.setattr(m,'diagnose',lambda _: (check('dns.resolve','fail'),))
    report=tmp_path/'report.json'
    assert m.main(['doctor',str(path),'--report',str(report)])==1
    content=report.read_text()
    for value in ('control.pilot.test','home-services',str(tmp_path)):
        assert value not in content


def test_report_write_failure_does_not_hide_diagnostics(tmp_path,monkeypatch,capsys):
    m=api(); path=tmp_path/'manifest.json'; path.write_text(json.dumps(manifest()))
    from operation_results import check
    monkeypatch.setattr(m,'diagnose',lambda _: (check('ownership.mismatch','fail'),))
    assert m.main(['doctor',str(path),'--report',str(tmp_path/'absent'/'report')])==1
    assert 'Ownership' in capsys.readouterr().out


def test_doctor_pending_returns_pending_exit_code():
    from operation_results import Check
    assert api().doctor_exit((Check('client.awaiting_enrollment','unknown','contact-controller-admin'),))==4


def test_release_download_requires_exact_identity_and_never_deploys(tmp_path,monkeypatch,capsys):
    m=api(); calls=[]
    monkeypatch.setattr(m,'fetch_release',lambda version,commit,dest: calls.append((version,commit,dest)))
    assert m.main(['release','fetch','0.2.0-alpha.1','--commit','a'*40,'--output-dir',str(tmp_path/'release')])==0
    assert calls==[('0.2.0-alpha.1','a'*40,tmp_path/'release')]
    assert 'No servers' in capsys.readouterr().out


def test_backup_routing_preserves_explicit_actions_without_install_passthrough(monkeypatch,tmp_path):
    m=api();calls=[]
    monkeypatch.setattr(m,'backup_action',lambda args:calls.append(args) or {'state':'snapshot-present'})
    assert m.main(['backup','status'])==0 and calls[0].action=='status'
    assert m.main(['backup','run','--extra-vars','unsafe'])==2


def test_cancelled_backup_preparation_is_not_reported_as_success(monkeypatch,tmp_path):
    m=api();monkeypatch.setattr(m,'backup_action',lambda args:{'state':'cancelled'})
    assert m.main(['backup','setup','--output-file',str(tmp_path/'profile.json')])==4

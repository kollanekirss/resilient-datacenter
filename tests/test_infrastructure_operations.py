import importlib
import json
import os
from pathlib import Path
import subprocess
import pytest
from test_setup_contracts import infrastructure, ROOT


def api(): return importlib.import_module('infrastructure_operations')


def test_inherited_ansible_overrides_are_removed(monkeypatch):
    m=importlib.import_module('operation_environment')
    monkeypatch.setenv('ANSIBLE_INVENTORY','/PRIVATE/redirect')
    monkeypatch.setenv('ANSIBLE_CONFIG','/PRIVATE/config')
    env=m.ansible_environment(ROOT)
    assert 'ANSIBLE_INVENTORY' not in env
    assert env['ANSIBLE_CONFIG']==str(ROOT/'ansible.cfg')


def test_invalid_inventory_never_invokes_ansible(tmp_path):
    path=tmp_path/'invalid'; path.write_text('{"kind":"local-node"}')
    from operation_results import OperationError
    with pytest.raises(OperationError) as caught:
        api().run_infrastructure('apply',path,runner=lambda *a,**kw:pytest.fail('Executed invalid inventory'))
    assert caught.value.exit_code==2


def configured(tmp_path,monkeypatch):
    m=api(); original=m.validate_infrastructure
    monkeypatch.setattr(m,'validate_infrastructure',lambda d,check_files:original(d,check_files=False))
    path=tmp_path/'inventory.json'; path.write_text(json.dumps(infrastructure()))
    return m,path


def test_apply_snapshots_reviewed_targets_and_cleans_up(tmp_path,monkeypatch):
    m,path=configured(tmp_path,monkeypatch); paths=[]
    def confirm(prompt):
        path.write_text('{"changed":"PRIVATE"}')
        return 'yes'
    def runner(argv,**kw):
        snapshot=Path(argv[argv.index('-i')+1]); paths.append(snapshot)
        data=json.loads(snapshot.read_text())
        assert set(data['all']['children'])=={'controller','relay'}
        assert 'PRIVATE' not in snapshot.read_text()
        assert snapshot.stat().st_mode & 0o777 == 0o600
        assert argv[-1].endswith('infrastructure-deploy.yml')
        return subprocess.CompletedProcess(argv,0)
    assert m.run_infrastructure('apply',path,runner=runner,confirm_fn=confirm).exit_code==0
    assert paths and not paths[0].exists()


def test_cancel_does_not_execute(tmp_path,monkeypatch):
    m,path=configured(tmp_path,monkeypatch)
    result=m.run_infrastructure('apply',path,confirm_fn=lambda _: 'no',runner=lambda *a,**k:pytest.fail('Cancelled apply executed'))
    assert result.exit_code==4


def test_check_is_noninteractive_and_uses_preflight(tmp_path,monkeypatch):
    m,path=configured(tmp_path,monkeypatch)
    def runner(argv,**kw):
        assert argv[-1].endswith('infrastructure-preflight.yml')
        assert '--ask-become-pass' not in argv
        assert kw['stdin']==subprocess.DEVNULL
        return subprocess.CompletedProcess(argv,0)
    assert m.run_infrastructure('check',path,runner=runner,confirm_fn=lambda _:pytest.fail('Check asked')).exit_code==0


def test_check_rejects_privilege_prompt(tmp_path):
    from operation_results import OperationError
    with pytest.raises(OperationError) as caught:
        api().run_infrastructure('check',tmp_path/'missing',ask_become_pass=True)
    assert caught.value.exit_code==2

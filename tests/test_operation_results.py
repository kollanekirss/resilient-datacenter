import importlib
import json
import pytest
from test_setup_contracts import manifest


def api():
    return importlib.import_module('operation_results')

@pytest.mark.parametrize('state,expected', [('installed',0),('enrolled',0),('draft',0),('awaiting_enrollment',4),('cancelled',4),('client_not_running',3),('failed',1)])
def test_action_states_have_explicit_exit_codes(state,expected):
    assert api().result_for_state(state).exit_code == expected


def test_unknown_state_never_becomes_success():
    with pytest.raises(api().OperationError) as caught:
        api().result_for_state('PRIVATE_UNKNOWN')
    assert caught.value.exit_code == 1
    assert 'PRIVATE' not in str(caught.value)


def test_structured_platform_check_preserves_legacy_message(monkeypatch):
    import local_checks as checks
    monkeypatch.setattr(checks.platform,'system',lambda:'Darwin')
    result=checks.inspect_local_checks(manifest())
    assert [(c.code,c.outcome) for c in result]==[('platform.unsupported','fail')]
    assert 'Ubuntu 24.04' in checks.check_local(manifest())[0]


def test_new_pending_result_does_not_register_during_status(tmp_path,monkeypatch):
    import local_node
    import local_enrollment
    path=tmp_path/'node.json'; path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(local_node,'inspect_local_checks',lambda *a,**kw:[])
    def action(m,r,*,start_requested):
        assert start_requested is False
        return {'status':'awaiting_enrollment','overlay_ip':None,'node_id':None}
    monkeypatch.setattr(local_enrollment,'enrollment_action',action)
    result=local_node.execute_local('status',path)
    assert result.exit_code==4 and result.state=='awaiting_enrollment'


def test_invalid_local_action_never_inspects_machine(tmp_path,monkeypatch):
    import local_node
    monkeypatch.setattr(local_node,'inspect_local_checks',lambda *a,**kw:pytest.fail('Unexpected machine inspection'))
    with pytest.raises(api().OperationError) as caught:
        local_node.execute_local('PRIVATE_ACTION',tmp_path/'missing')
    assert caught.value.exit_code==2


def test_new_status_never_requests_sudo(tmp_path,monkeypatch):
    import local_node, local_enrollment
    path=tmp_path/'node.json'; path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(local_node,'inspect_local_checks',lambda *a,**kw:[])
    monkeypatch.setattr(local_enrollment.os,'geteuid',lambda:1000)
    def action(m,r,*,start_requested):
        assert not start_requested
        assert r._prefix()==[]
        return {'status':'awaiting_enrollment'}
    monkeypatch.setattr(local_enrollment,'enrollment_action',action)
    assert local_node.execute_local('status',path).exit_code==4


def local_machine(tmp_path,monkeypatch,status):
    import local_checks as m
    import subprocess
    from setup_contracts import local_ownership
    marker=tmp_path/'marker.json'; marker.write_text(json.dumps(local_ownership(manifest())))
    monkeypatch.setattr(m,'MARKER',marker)
    monkeypatch.setattr(m,'STATE',tmp_path/'state')
    monkeypatch.setattr(m,'RESERVED',[])
    monkeypatch.setattr(m.platform,'system',lambda:'Linux')
    monkeypatch.setattr(m.platform,'machine',lambda:'x86_64')
    monkeypatch.setattr(m.platform,'freedesktop_os_release',lambda:{'ID':'ubuntu','VERSION_ID':'24.04'})
    monkeypatch.setattr(m,'platform_errors',lambda *a:[])
    real_stat=type(marker).stat
    from types import SimpleNamespace
    def stat(path,*a,**kw):
        result=real_stat(path,*a,**kw)
        if path==marker:
            return SimpleNamespace(st_uid=0,st_mode=result.st_mode)
        return result
    monkeypatch.setattr(type(marker),'stat',stat)
    def run(argv,**kwargs):
        assert 'sudo' not in argv
        if argv[0]=='/bin/systemctl': return subprocess.CompletedProcess(argv,0,'active','')
        value={'ControlURL':'https://control.pilot.test'} if argv[-1]=='prefs' else status
        return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
    monkeypatch.setattr(m.subprocess,'run',run)
    return m


def test_structured_check_rejects_wrong_runtime_node_name(tmp_path,monkeypatch):
    status={'BackendState':'Running','TailscaleIPs':['100.64.0.4'],'Self':{'HostName':'wrong-node','Tags':['tag:home-services']}}
    m=local_machine(tmp_path,monkeypatch,status)
    checks=m.inspect_local_checks(manifest(),check_tls=False)
    assert any(c.code=='client.state_mismatch' and c.outcome=='fail' for c in checks)


def test_pending_state_is_visible_but_does_not_block_enrollment(tmp_path,monkeypatch):
    m=local_machine(tmp_path,monkeypatch,{'BackendState':'NeedsMachineAuth'})
    checks=m.inspect_local_checks(manifest(),check_tls=False)
    assert any(c.code=='client.awaiting_enrollment' for c in checks)
    assert m.check_local(manifest(),check_tls=False)==[]


def test_malformed_runtime_state_returns_sanitized_error(tmp_path,monkeypatch):
    import local_node, local_enrollment
    path=tmp_path/'node.json'; path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(local_node,'inspect_local_checks',lambda *a,**kw:[])
    def broken(*a,**kw): raise AttributeError('PRIVATE_RUNTIME_VALUE')
    monkeypatch.setattr(local_enrollment,'enrollment_action',broken)
    with pytest.raises(api().OperationError) as caught:
        local_node.execute_local('status',path)
    assert caught.value.exit_code==3 and 'PRIVATE' not in str(caught.value)

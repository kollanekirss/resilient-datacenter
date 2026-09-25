import importlib
import pytest
from test_setup_contracts import ROOT, manifest

class Runtime:
    def __init__(self,status=None,fail=False):
        self.status=status or {'BackendState':'Running','TailscaleIPs':['100.64.0.4'],'Self':{'ID':'safe-node','HostName':'home-services','Tags':['tag:home-services']}}
        self.started_commands=[]; self.cancelled=False; self.fail=fail; self.displayed=[]
    def read_status(self): return self.status
    def read_preferences(self): return {'ControlURL':'https://control.pilot.test'}
    def start_registration(self,argv):
        self.started_commands.append(argv)
        if self.fail: raise KeyboardInterrupt()
        self.status={'BackendState':'NeedsMachineAuth','AuthURL':'https://control.pilot.test/SECRET_SENTINEL'}
    def cancel_registration(self): self.cancelled=True
    def display_registration_url(self,url): self.displayed.append(url)

def module():
    assert (ROOT/'scripts/local_enrollment.py').exists(),'Enrollment workflow not implemented'
    return importlib.import_module('local_enrollment')

def test_enrolled_node_does_not_restart_registration():
    r=Runtime(); result=module().enrollment_action(manifest(),r,start_requested=True)
    assert result['status']=='enrolled' and r.started_commands==[]

def test_pending_resume_does_not_restart_or_save_auth_url():
    r=Runtime({'BackendState':'NeedsMachineAuth','AuthURL':'https://control.pilot.test/SECRET_SENTINEL'})
    result=module().enrollment_action(manifest(),r,start_requested=True)
    assert result['status']=='awaiting_enrollment' and r.started_commands==[]
    assert 'SECRET_SENTINEL' not in str(result) and r.displayed

def test_status_never_launches_registration():
    r=Runtime({'BackendState':'NeedsLogin'})
    assert module().enrollment_action(manifest(),r,start_requested=False)['status']=='awaiting_enrollment'
    assert not r.started_commands

def test_fresh_enrollment_uses_safe_arguments_and_pending_result():
    r=Runtime({'BackendState':'NeedsLogin'})
    result=module().enrollment_action(manifest(),r,start_requested=True)
    assert result['status']=='awaiting_enrollment'
    command=r.started_commands[0]
    assert '--ssh=false' in command and '--accept-routes=false' in command
    assert '--reset' not in command and '--force-reauth' not in command
    assert 'SECRET_SENTINEL' not in str(result)

def test_cancel_preserves_daemon_and_returns_pending_status():
    r=Runtime({'BackendState':'NeedsLogin'},fail=True)
    assert module().enrollment_action(manifest(),r,start_requested=True)['status']=='cancelled'
    assert r.cancelled

def test_wrong_host_identity_requires_inspection():
    r=Runtime(); r.status['Self']['HostName']='other-node'
    with pytest.raises(ValueError): module().enrollment_action(manifest(),r,start_requested=True)
    assert not r.started_commands

def test_native_registration_refuses_redirected_output(monkeypatch):
    import sys
    m=module(); monkeypatch.setattr(sys.stdout,'isatty',lambda:False)
    with pytest.raises(ValueError): m.NativeRuntime().display_registration_url('https://control.pilot.test/SECRET_SENTINEL')

def test_invalid_registration_url_error_omits_sensitive_value():
    r=Runtime({'BackendState':'NeedsMachineAuth','AuthURL':'https://control.pilot.test:SECRET_SENTINEL/'})
    with pytest.raises(ValueError) as e: module().enrollment_action(manifest(),r,start_requested=True)
    assert 'SECRET_SENTINEL' not in str(e.value)

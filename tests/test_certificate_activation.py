import hashlib
import importlib
import os
from pathlib import Path
import sys
import pytest
from test_tls import certs
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('certificate_lifecycle')

class Runtime:
    def __init__(self,fail=0): self.restarts=0; self.fail=fail; self.probes=[]
    def restart(self,service): self.restarts+=1
    def verify(self,hostname,fingerprint):
        self.probes.append(fingerprint)
        if self.fail:
            self.fail-=1; raise ValueError('activation failed')


def validate(cert,key,hostname):
    if key==b'bad': raise ValueError('invalid key')
    return {'fingerprint':hashlib.sha256(cert).hexdigest(),'expires_at':'2027-01-01T00:00:00+00:00'}


def activate(base,cert=b'new',key=b'key',runtime=None,initial=False):
    return api().activate(base,'control.pilot.test','controller',cert,key,gid=os.getgid(),
                         validator=validate,runtime=runtime or Runtime(),initial=initial)


def test_initial_stage_does_not_start_missing_service(tmp_path):
    runtime=Runtime(); result=activate(tmp_path,runtime=runtime,initial=True)
    assert result['state']=='staged' and runtime.restarts==0
    assert (tmp_path/'active/tls.key').read_bytes()==b'key'
    assert (tmp_path/'active/tls.key').stat().st_mode & 0o777==0o640


def test_invalid_material_never_replaces_existing_certificate(tmp_path):
    activate(tmp_path,cert=b'old',initial=True)
    previous=(tmp_path/'active').readlink()
    with pytest.raises(ValueError): activate(tmp_path,key=b'bad')
    assert (tmp_path/'active').readlink()==previous


def test_failed_activation_restores_and_checks_previous_certificate(tmp_path):
    activate(tmp_path,cert=b'old',initial=True)
    runtime=Runtime(fail=1)
    with pytest.raises(api().ActivationError) as error: activate(tmp_path,runtime=runtime)
    assert error.value.recovered is True
    assert (tmp_path/'active/tls.crt').read_bytes()==b'old'
    assert runtime.restarts==2 and len(runtime.probes)==2


def test_failed_recovery_is_reported_as_failed_not_success(tmp_path):
    activate(tmp_path,cert=b'old',initial=True)
    with pytest.raises(api().ActivationError) as error: activate(tmp_path,runtime=Runtime(fail=2))
    assert error.value.recovered is False


def test_success_probes_new_certificate_and_retains_previous(tmp_path):
    activate(tmp_path,cert=b'old',initial=True)
    runtime=Runtime(); result=activate(tmp_path,runtime=runtime)
    assert result['state']=='active' and runtime.restarts==1
    assert (tmp_path/'active/tls.crt').read_bytes()==b'new'
    assert (tmp_path/'previous/tls.crt').read_bytes()==b'old'


def test_unchanged_certificate_is_verified_without_restart(tmp_path):
    activate(tmp_path,initial=True)
    runtime=Runtime(); result=activate(tmp_path,runtime=runtime)
    assert result['state']=='active' and runtime.restarts==0 and len(runtime.probes)==1


def test_renewal_without_existing_managed_certificate_is_blocked(tmp_path):
    with pytest.raises(ValueError): activate(tmp_path)
    assert not list(tmp_path.iterdir())


def test_symlink_outside_generation_directory_is_refused(tmp_path):
    (tmp_path/'active').symlink_to('/etc')
    with pytest.raises(ValueError): activate(tmp_path)


def test_expired_previous_material_does_not_block_new_valid_certificate(tmp_path):
    activate(tmp_path,cert=b'old',initial=True)
    def validator(cert,key,hostname):
        if cert==b'old': raise ValueError('old certificate expired')
        return validate(cert,key,hostname)
    result=api().activate(tmp_path,'control.pilot.test','controller',b'new',b'key',gid=os.getgid(),validator=validator,runtime=Runtime())
    assert result['state']=='active'


def test_actual_material_rejects_untrusted_chain(certs):
    import subprocess
    cp,kp=certs
    with pytest.raises(subprocess.CalledProcessError): api().validate_material(cp.read_bytes(),kp.read_bytes(),'a.pilot.test')


def test_actual_material_rejects_wrong_hostname_before_activation(certs):
    cp,kp=certs
    with pytest.raises(ValueError): api().validate_material(cp.read_bytes(),kp.read_bytes(),'wrong.pilot.test')


def test_actual_material_rejects_mismatched_private_key(certs):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    cp,kp=certs
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key=other.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    with pytest.raises(ValueError): api().validate_material(cp.read_bytes(),key,'a.pilot.test')


def test_retry_completes_activation_after_interrupted_pointer_switch(tmp_path):
    activate(tmp_path,initial=True)
    runtime=Runtime(fail=1)
    result=activate(tmp_path,runtime=runtime)
    assert result['state']=='active' and runtime.restarts==1 and len(runtime.probes)==2


def test_failed_status_never_writes_status_or_restarts(monkeypatch,tmp_path):
    m=api(); monkeypatch.setattr(m,'BASE',tmp_path)
    monkeypatch.setattr(m,'configuration',lambda:{'hostname':'control.pilot.test','role':'controller'})
    def forbidden(*args,**kwargs): raise AssertionError('read-only status attempted mutation')
    monkeypatch.setattr(m,'record',forbidden)
    monkeypatch.setattr(m.Runtime,'restart',forbidden)
    assert m.main(['status'])==1
    assert list(tmp_path.iterdir())==[]


def test_offline_coverage_checks_chain_at_end_of_window(certs,monkeypatch):
    import subprocess
    from datetime import datetime,timedelta,timezone
    import portable_application_install as installer
    cp,kp=certs;calls=[]
    def verify(argv,**kwargs):
        calls.append(argv)
        if '-attime' in argv:raise subprocess.CalledProcessError(2,argv)
    monkeypatch.setattr(api().subprocess,'run',verify)
    before=int((datetime.now(timezone.utc)+timedelta(days=8)).timestamp())
    with pytest.raises(subprocess.CalledProcessError):
        installer.coverage(cp.read_bytes(),kp.read_bytes(),'a.pilot.test',8)
    assert len(calls)==2
    assert int(calls[1][calls[1].index('-attime')+1])>=before

import importlib
import json
import subprocess
import pytest
from test_setup_contracts import manifest


def api(): return importlib.import_module('doctor')


def test_invalid_manifest_never_probes():
    checks=api().diagnose({'kind':'bad'},probe_runner=lambda *a,**kw:pytest.fail('Probe launched'))
    assert checks[0].code=='manifest.invalid'


def test_probe_timeout_is_fixed_and_private(monkeypatch):
    m=api(); monkeypatch.setattr(m,'inspect_local_checks',lambda *a,**kw:[])
    def timeout(*args,**kwargs):
        assert kwargs['timeout']==15
        raise subprocess.TimeoutExpired('PRIVATE_COMMAND',15,output='PRIVATE_OUTPUT')
    checks=m.diagnose(manifest(),probe_runner=timeout)
    assert any(c.code=='probe.timeout' for c in checks)
    assert 'PRIVATE_' not in repr(checks)


def test_mac_still_checks_network_but_marks_services_not_applicable(monkeypatch):
    m=api()
    from operation_results import check
    monkeypatch.setattr(m,'inspect_local_checks',lambda *a,**kw:[check('platform.unsupported','fail')])
    def runner(argv,**kw):
        assert argv[-2:]==['--hostname','control.pilot.test']
        return subprocess.CompletedProcess(argv,0,json.dumps([{'code':'dns.resolve','outcome':'pass'}]),'')
    result=m.diagnose(manifest(),probe_runner=runner)
    assert result[0].outcome=='not-applicable'
    assert any(c.code=='dns.resolve' and c.outcome=='pass' for c in result)

@pytest.mark.parametrize('payload',['not json','[{}]', '[{"code":"PRIVATE_TOKEN","outcome":"pass"}]','{}','x'*20000])
def test_worker_output_is_validated_without_leaks(payload,monkeypatch):
    m=api(); monkeypatch.setattr(m,'inspect_local_checks',lambda *a,**kw:[])
    result=m.diagnose(manifest(),probe_runner=lambda *a,**k:subprocess.CompletedProcess([],0,payload,'PRIVATE_STDERR'))
    assert result[-1].code=='probe.unavailable'
    assert 'PRIVATE_' not in repr(result)


def test_dns_failure_has_no_private_exception(monkeypatch):
    m=importlib.import_module('diagnostic_probe')
    def fail(*a,**kw): raise m.socket.gaierror('PRIVATE_DOMAIN')
    monkeypatch.setattr(m.socket,'getaddrinfo',fail)
    checks=m.probe_controller('control.pilot.test')
    assert checks[0].code=='dns.resolve' and checks[0].outcome=='fail'
    assert 'PRIVATE_' not in repr(checks)


def test_connection_refusal_has_no_false_tls_failure(monkeypatch):
    m=importlib.import_module('diagnostic_probe')
    monkeypatch.setattr(m.socket,'getaddrinfo',lambda *a,**kw:[(2,1,6,'',('127.0.0.1',1))])
    class Refused:
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def settimeout(self,*a): pass
        def connect(self,*a): raise ConnectionRefusedError('PRIVATE_ADDRESS')
    monkeypatch.setattr(m.socket,'socket',lambda *a:Refused())
    result=m.probe_controller('control.pilot.test')
    assert [(c.code,c.outcome) for c in result]==[('dns.resolve','pass'),('tcp.connect','fail')]

import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def contract():return importlib.import_module('ci_national_contract')


def test_cut_has_default_deny_underlay_and_only_domestic_bootstrap():
    rules=contract().cut_rules(['172.29.10.2','172.29.10.51','172.29.10.200'])
    assert 'oifname "wan0"' in rules
    assert 'ct state established,related' not in rules # even existing outside sessions must stop
    assert '172.29.10.250' not in rules
    assert 'tcp dport { 53, 443 }' in rules
    assert 'udp dport { 53, 3478 }' in rules
    assert 'counter drop' in rules


def test_cut_rejects_external_or_injected_addresses():
    for addresses in ([],['1.1.1.1'],['172.29.10.250'],['172.29.10.2; accept']):
        with pytest.raises(ValueError):contract().cut_rules(addresses)


def test_restarting_retains_state_without_enrollment_arguments():
    argv=contract().restart_command('north-user','/private/fixture')
    assert '--state=/private/fixture/north-user/tailscaled.state' in argv
    assert not any('auth-key' in s or 'login-server' in s for s in argv)
    assert argv[:4]==['ip','netns','exec','north-user']


def test_evidence_requires_all_core_phases_and_retains_boundaries():
    api=contract()
    with pytest.raises(ValueError):api.evidence({'baseline':True},{})
    phases={name:True for name in api.REQUIRED}
    result=api.evidence(phases,{'north':'unavailable','south':'not-exercised'})
    assert result['public_certificate_device_acceptance']=='not-tested'
    assert result['physical_carrier_diversity']=='not-tested'
    assert result['controller_loss']['north']=='unavailable'
    assert result['state']=='domestic-isolation-lab-passed'
    phases['field_restart']=False
    with pytest.raises(ValueError):api.evidence(phases,{})


@pytest.mark.parametrize('responses,expected',[
    ([{'status':401,'body':{}}],False),
    ([{'status':200,'body':{'room_id':'!r:x'}},{'status':200,'body':{'event_id':'$e'}},{'status':200,'body':{'content':{'body':'wrong'}}}],False),
    ([{'status':200,'body':{'room_id':'!r:x'}},{'status':200,'body':{'event_id':'$e'}},{'status':200,'body':{'content':{'body':'proof'}}}],True),
])
def test_controller_observation_requires_authenticated_saved_message(monkeypatch,responses,expected):
    module=importlib.import_module('ci_national_isolation');results=iter(responses)
    monkeypatch.setattr(module.matrix,'request',lambda *args,**kwargs:next(results))
    assert module.authenticated_available({'user':'north-user','hostname':'matrix.north.ci.test'},'fixture-token','proof') is expected


def test_partner_cut_accepts_only_overlay_peer_addresses():
    for address in ('1.1.1.1','172.29.10.2','100.64.0.1; accept'):
        with pytest.raises(ValueError):contract().partner_rules(address)
    assert '100.64.0.2' in contract().partner_rules('100.64.0.2')


def test_continuing_session_checks_do_not_reauthenticate(monkeypatch):
    module=importlib.import_module('ci_national_isolation')
    monkeypatch.setattr(module,'ready',lambda app:None)
    def unexpected(*args):raise AssertionError('A continuing session must not trigger another login')
    monkeypatch.setattr(module,'login',unexpected)
    monkeypatch.setattr(module.matrix,'api',lambda *args:{'room_id':'!room:ci.test'})
    monkeypatch.setattr(module,'send',lambda *args:'$event')
    monkeypatch.setattr(module.matrix,'wait_event',lambda *args:{'content':{'body':'relay-loss'}})
    assert module.field_proof({'user':'north-user','hostname':'matrix.north.ci.test'},{},'relay-loss',token='existing')=='existing'


def test_outage_observation_allows_late_reconnect_and_bounds_failure():
    api=contract();ticks=[0];attempts=[]
    def clock():return ticks[0]
    def pause(seconds):ticks[0]+=seconds
    def late():attempts.append(1);return len(attempts)==3
    result=api.observe(late,5,clock=clock,pause=pause)
    assert result['available'] is True and result['observed_seconds']==2
    ticks[0]=0
    result=api.observe(lambda:False,5,clock=clock,pause=pause)
    assert result['available'] is False and result['observed_seconds']==5

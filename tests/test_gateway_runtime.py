import importlib
import json
from copy import deepcopy
import pytest
from test_gateway_contracts import profile
from test_regional_agreements import agreement


def test_gateway_runtime_requires_exact_regional_membership_and_no_advertised_routes():
    m=importlib.import_module('gateway_runtime');_,own,_=agreement();p=profile()
    network={'schema_version':2,'deployment_mode':'join','institution_id':'north','role':'peer','controller_hostname':'regional.example.test','node_name':'north-gateway','node_tag':'tag:gateway','install_method':'local'}
    status={'BackendState':'Running','Self':{'TailscaleIPs':['100.64.0.10','fd7a:115c:a1e0::10']}}
    prefs={'ControlURL':'https://regional.example.test','AdvertiseRoutes':[],'ExitNodeID':''}
    m.validate_network(p,own,network,status,prefs)
    for changes in ({'ControlURL':'https://internal.example.test'},{'AdvertiseRoutes':['10.203.1.0/24']},{'ExitNodeID':'peer'}):
        with pytest.raises(ValueError):m.validate_network(p,own,network,status,dict(prefs,**changes))
    with pytest.raises(ValueError):m.validate_network(p,own,network,dict(status,BackendState='NeedsLogin'),prefs)
    changed=deepcopy(status);changed['Self']['TailscaleIPs']=['100.64.0.20']
    with pytest.raises(ValueError):m.validate_network(p,own,network,changed,prefs)


def test_gateway_container_is_owned_pinned_and_has_no_admin_listener_or_forwarder():
    m=importlib.import_module('gateway_runtime');_,own,_=agreement()
    command=m.container_command(own)
    assert '--network=host' in command and '--read-only' in command and '--cap-drop=ALL' in command
    assert '--rm' not in command and '--privileged' not in command
    assert '--cap-add=NET_BIND_SERVICE' in command and 'NET_ADMIN' not in json.dumps(command)
    assert '--label' in command and '--pull=never' in command
    assert '/usr/local/bin/envoy' in command


def test_gateway_clock_cannot_move_backwards_and_revive_expired_approval(tmp_path,monkeypatch):
    m=importlib.import_module('gateway_runtime')
    from gateway_store import Store
    _,own,_=agreement();store=Store(tmp_path/'gateway');store.initialize(profile(),own)
    current=[1800000000]
    monkeypatch.setattr(m.time,'time',lambda:current[0])
    clock=m.policy_time(store)
    assert clock==1800000000
    current[0]+=10;assert m.policy_time(store)==1800000010
    current[0]-=30
    with pytest.raises(ValueError):m.policy_time(store)
    assert json.loads((store.base/'clock.json').read_text())['latest_utc']==1800000010


def test_gateway_guard_timer_rechecks_clock_membership_and_interrupted_changes():
    m=importlib.import_module('gateway_runtime')
    assert 'gateway_entry.py guard' in m.guard_unit()
    assert 'OnUnitActiveSec=5s' in m.guard_timer()


def test_clock_checkpoint_serializes_startup_and_guard(tmp_path,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    m=importlib.import_module('gateway_runtime')
    from gateway_store import Store
    _,own,_=agreement();store=Store(tmp_path/'gateway');store.initialize(profile(),own)
    writing=Event();release=Event();second_read=Event();original=m.private_write
    reads=[]
    def clock():
        reads.append(1800000000+len(reads))
        if len(reads)>1:second_read.set()
        return reads[-1]
    def write(path,raw,**kwargs):
        if not writing.is_set():
            writing.set();assert release.wait(3)
        return original(path,raw,**kwargs)
    monkeypatch.setattr(m.time,'time',clock);monkeypatch.setattr(m,'private_write',write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(m.policy_time,store);assert writing.wait(3)
        second=pool.submit(m.policy_time,store)
        try:assert not second_read.wait(.1),'Concurrent guard read an unlocked old checkpoint'
        finally:release.set()
        assert first.result()==1800000000
        assert second.result()==1800000001
    assert json.loads((store.base/'clock.json').read_text())['latest_utc']==1800000001


def test_gateway_cannot_open_while_certificate_activation_is_unverified(tmp_path):
    from test_gateway_store import fixture
    from regional_workspace import private_write
    m=importlib.import_module('gateway_runtime');store,_=fixture(tmp_path)
    private_write(store.base/'certificate-pending.json',json.dumps({'schema_version':1,'material_digest':'a'*64}).encode())
    with pytest.raises(ValueError,match='certificate'):
        m.Runtime(store).open(store.state())

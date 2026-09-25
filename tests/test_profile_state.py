import importlib
from pathlib import Path
import sys
import pytest
from test_profiles import ROOT
sys.path.insert(0,str(ROOT/'scripts'))

def inspect(status=None,prefs=None,tag='tag:south-services'):
    assert (ROOT/'scripts/profile_state.py').exists(),'Profile state inspection not implemented'
    m=importlib.import_module('profile_state')
    if status is None: status={'BackendState':'Running','TailscaleIPs':['100.64.0.5'],'Self':{'ID':'node1','Tags':[tag]}}
    if prefs is None: prefs={'ControlURL':'https://control.pilot.test'}
    return m.inspect_peer(status,prefs,'control.pilot.test',tag)

def test_enrolled_identity():
    assert inspect()=={'status':'enrolled','overlay_ip':'100.64.0.5','node_id':'node1'}

def test_fresh_client_waits_for_approval():
    assert inspect({'BackendState':'NeedsLogin'},{'ControlURL':'https://controlplane.tailscale.com'})['status']=='awaiting_enrollment'

@pytest.mark.parametrize('backend',['Running','Stopped','NeedsLogin'])
def test_wrong_controller_not_excused_by_client_state(backend):
    with pytest.raises(ValueError): inspect({'BackendState':backend},{'ControlURL':'https://other.pilot.test'})

@pytest.mark.parametrize('status',[
    {'BackendState':'Running','TailscaleIPs':['1.1.1.1'],'Self':{'Tags':['tag:south-services']}},
    {'BackendState':'Running','TailscaleIPs':['100.64.0.5'],'Self':{'Tags':['tag:unexpected']}},
    {'BackendState':'Running','TailscaleIPs':['100.64.0.5'],'Self':{'Tags':['tag:south-services','tag:extra']}},
    {'BackendState':'Running','TailscaleIPs':['100.2.3.4'],'Self':{'Tags':['tag:south-services']}},
])
def test_running_requires_exact_tag_and_real_overlay_address(status):
    with pytest.raises(ValueError): inspect(status)

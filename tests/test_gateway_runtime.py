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

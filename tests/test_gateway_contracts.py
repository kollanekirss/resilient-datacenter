import importlib
from copy import deepcopy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_regional_agreements import pair,agreement,NOW


def profile():
    return {'kind':'regional-gateway','schema_version':1,'institution_id':'north','node_name':'north-gateway',
            'regional_controller':'regional.example.test','lan_address':'10.203.1.1','lan_subnet':'10.203.1.0/24',
            'identity_file':'/root/public-identity.json','tls_certificate':'/root/gateway.crt','tls_private_key':'/root/gateway.key',
            'upstreams':{'matrix':'10.203.1.10','nextcloud':'10.203.1.11'}}


def test_gateway_uses_one_regional_identity_and_only_dedicated_lan_upstreams():
    m=importlib.import_module('gateway_contracts');_,_,own,_=pair()
    assert m.validate(profile(),own)==[]
    for update in ({'lan_address':'127.0.0.1'},{'lan_subnet':'0.0.0.0/0'},{'node_name':'other'},
                   {'upstreams':{'matrix':'169.254.169.254','nextcloud':'10.203.1.11'}},
                   {'upstreams':{'matrix':'100.64.0.10','nextcloud':'10.203.1.11'}},
                   {'upstreams':{'matrix':'10.203.1.1','nextcloud':'10.203.1.11'}},
                   {'forward_subnets':['10.0.0.0/8']},{'identity_file':'relative.json'}):
        assert m.validate(dict(profile(),**update),own)


def test_only_current_nonrevoked_exact_local_agreements_produce_peer_rules():
    m=importlib.import_module('gateway_contracts');document,own,peer=agreement();identifier=document['offer']['payload']['agreement_id']
    rules=m.peer_rules(own,[document],[],now=NOW+2)
    assert len(rules)==1 and rules[0]['address']=='100.64.0.11' and rules[0]['services']==['matrix','nextcloud']
    assert m.peer_rules(own,[document],[identifier],now=NOW+2)==[]
    assert m.peer_rules(own,[document],[],now=NOW+3600)==[]
    assert m.peer_rules(own,[document],[],now=NOW)==[]
    with pytest.raises(ValueError):m.peer_rules(own,[document,document],[],now=NOW+2)
    changed=deepcopy(own);changed['payload']['gateway_ipv4']='100.64.0.77'
    with pytest.raises(ValueError):m.peer_rules(changed,[document],[],now=NOW+2)

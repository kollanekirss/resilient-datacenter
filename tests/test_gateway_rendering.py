import importlib
import json
import pytest
from test_gateway_contracts import profile
from test_regional_agreements import agreement,NOW


def inputs():
    from gateway_contracts import peer_rules
    document,own,_=agreement()
    return profile(),own,peer_rules(own,[document],[],now=NOW+2)


def test_gateway_has_fixed_tls_upstreams_no_admin_or_dynamic_forwarding():
    m=importlib.import_module('gateway_rendering');p,own,peers=inputs()
    config=m.envoy(p,own,peers)
    assert 'admin' not in config
    listeners=config['static_resources']['listeners']
    assert [(x['address']['socket_address']['address'],x['address']['socket_address']['port_value']) for x in listeners]==[('100.64.0.10',443),('10.203.1.1',3128)]
    clusters=config['static_resources']['clusters']
    assert all(x['type']=='STATIC' for x in clusters)
    matrix=next(x for x in clusters if x['name']=='local_matrix')
    tls=matrix['transport_socket']['typed_config']
    assert tls['sni']==own['payload']['services']['matrix']
    assert tls['common_tls_context']['validation_context']['trusted_ca']['filename']=='/etc/ssl/certs/ca-certificates.crt'
    text=json.dumps(config)
    assert 'direct_remote_ip' in text and 'connect_matcher' in text
    assert 'ORIGINAL_DST' not in text and 'dynamic_forward_proxy' not in text
    # Nextcloud paths remain closed until its exact federation API is accepted.
    assert 'local_nextcloud' not in text
    assert '/_matrix/client' not in text and '/_synapse/admin' not in text


def test_empty_approval_still_denies_and_firewall_expires_existing_connections():
    m=importlib.import_module('gateway_rendering');p,own,peers=inputs()
    config=m.envoy(p,own,[])
    assert 'direct_response' in json.dumps(config)
    rules=m.firewall(p,peers,lan_interface='rdc-lan',now=NOW+2,replace=False)
    assert 'flush ruleset' not in rules and 'timeout 3598s' in rules
    assert 'tcp sport 443' in rules and 'tcp dport 443' in rules
    assert 'ct state established' not in rules
    assert 'iifname "rdc-lan"' in rules and 'iifname "tailscale0"' in rules
    assert 'add chain inet rdc_gateway forward' in rules
    assert 'delete table inet rdc_gateway' not in rules
    assert m.firewall(p,peers,lan_interface='rdc-lan',now=NOW+3600,replace=True).startswith('delete table inet rdc_gateway\n')
    for name in ('eth0; flush ruleset','tailscale0','lo','x"'):
        with pytest.raises(ValueError):m.firewall(p,peers,lan_interface=name,now=NOW+2,replace=False)


def test_regional_endpoints_cannot_fall_back_to_an_unrelated_interface():
    m=importlib.import_module('gateway_rendering');p,own,peers=inputs()
    text=m.firewall(p,peers,lan_interface='rdc-lan',now=NOW+2,replace=False)
    for selector in ('tcp dport 443','tcp sport 443'):
        assert 'output oifname != "tailscale0" ip daddr 100.64.0.0/10 '+selector+' drop' in text

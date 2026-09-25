import importlib
from copy import deepcopy
import pytest
from test_regional_agreements import agreement,NOW


def bundle():
    document,own,_=agreement()
    return {'kind':'regional-service-link','schema_version':1,'package':'matrix','gateway_identity':own,
            'gateway_lan_address':'10.203.1.1','service_lan_address':'10.203.1.10','lan_subnet':'10.203.1.0/24','agreements':[document]}


def settings():return {'ownership':{'packages':['matrix'],'institution_id':'north','matrix_hostname':'matrix.north.test','network':{'controller_hostname':'internal.north.test'}}}


def test_service_link_requires_exact_application_and_confirmed_institution_key():
    m=importlib.import_module('service_link');b=bundle()
    from regional_agreements import fingerprint
    config=m.prepare(b,settings(),expected_fingerprint=fingerprint(b['gateway_identity']),now=NOW+2)
    assert config['peers']==[{'hostname':'matrix.south.test','expires_at':NOW+3600}]
    assert m.prepare(b,settings(),expected_fingerprint=fingerprint(b['gateway_identity']),now=NOW+3600)['peers']==[]
    with pytest.raises(ValueError):m.prepare(b,settings(),expected_fingerprint='0'*64,now=NOW+2)
    changed=deepcopy(b);changed['agreements'][0]['offer']['payload']['services']=['matrix']
    with pytest.raises(ValueError):m.prepare(changed,settings(),expected_fingerprint=fingerprint(b['gateway_identity']),now=NOW+2)
    other=settings();other['ownership']['network']['controller_hostname']='regional.example.test'
    with pytest.raises(ValueError):m.prepare(b,other,expected_fingerprint=fingerprint(b['gateway_identity']),now=NOW+2)

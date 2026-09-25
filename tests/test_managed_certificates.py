import copy
import importlib
from test_setup_contracts import infrastructure,setup_api
import pytest


def managed():
    data=infrastructure(); v=data['all']['vars']
    v.update(schema_version=3,tls_mode='managed-acme',acme_email='admin@institution.test',acme_terms_accepted=True)
    for group in data['all']['children'].values():
        for host in group['hosts'].values():
            host.pop('tls_certificate'); host.pop('tls_private_key')
    return data


def test_explicit_managed_mode_requires_no_operator_private_key():
    assert setup_api().validate_infrastructure(managed(),check_files=False)==[]
    normalized=setup_api().normalize_infrastructure(managed())
    assert all(v['schema_version']==3 and v['tls_mode']=='managed-acme' for v in normalized['ownership'].values())

@pytest.mark.parametrize('field,value',[('acme_terms_accepted',False),('acme_terms_accepted','yes'),('tls_mode','self-signed'),('acme_email','--evil'),('acme_server','https://other-ca.test')])
def test_managed_mode_rejects_implicit_terms_and_issuer_override(field,value):
    data=managed(); data['all']['vars'][field]=value
    assert setup_api().validate_infrastructure(data,check_files=False)


def test_supplied_and_managed_inputs_cannot_be_mixed():
    data=managed()
    next(iter(data['all']['children']['controller']['hosts'].values()))['tls_private_key']='/tmp/key'
    assert setup_api().validate_infrastructure(data,check_files=False)
    data=infrastructure(); data['all']['vars']['tls_mode']='managed-acme'
    assert setup_api().validate_infrastructure(data,check_files=False)


def test_existing_schema_two_ownership_is_preserved():
    normalized=setup_api().normalize_infrastructure(infrastructure())
    assert all(v['schema_version']==2 and 'tls_mode' not in v for v in normalized['ownership'].values())


def test_relay_certificate_identity_is_part_of_ownership():
    data=managed(); old=setup_api().normalize_infrastructure(data)['ownership']
    data['all']['vars']['derp_hostname']='other.pilot.test'
    new=setup_api().normalize_infrastructure(data)['ownership']
    assert old!=new

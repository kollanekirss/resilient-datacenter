import importlib
import sys
from pathlib import Path
import pytest
from test_profiles import ROOT, independent, api
sys.path.insert(0,str(ROOT/'scripts'))

def setup_api():
    assert (ROOT/'scripts/setup_contracts.py').exists(), 'Setup contracts not implemented'
    return importlib.import_module('setup_contracts')

def infrastructure():
    d=independent(); v=d['all']['vars']; v['schema_version']=2
    peers=d['all']['children'].pop('peers')['hosts']
    v['enrollment_nodes']=[{'name':n,'node_tag':h['node_tag']} for n,h in peers.items()]
    return d

def manifest():
    return {'kind':'local-node','schema_version':1,'institution_id':'south','node_name':'home-services','headscale_hostname':'control.pilot.test','node_tag':'tag:home-services'}

def test_infrastructure_excludes_home_targets():
    m=setup_api(); d=infrastructure()
    assert m.validate_infrastructure(d,check_files=False)==[]
    n=m.normalize_infrastructure(d)
    assert set(n['roles'].values())=={'controller','relay'} and len(n['roles'])==2
    assert n['policy']['grants']==[] and n['enrollment_requests']
    assert all(r['schema_version']==2 for r in n['ownership'].values())

def test_versions_and_kinds_cannot_cross():
    m=setup_api()
    assert api().validate_profile(infrastructure(),check_files=False)
    assert m.validate_infrastructure(independent(),check_files=False)
    assert m.validate_local_manifest(infrastructure())
    assert m.validate_infrastructure(manifest(),check_files=False)

@pytest.mark.parametrize('value',[[],None,[{'name':'south-services','node_tag':'tag:south-services'}]*2,[{'name':'north-control','node_tag':'tag:a'}],[{'name':'x','node_tag':'tag:a','command':'SECRET_SENTINEL'}]])
def test_bad_enrollment_declarations(value):
    d=infrastructure(); d['all']['vars']['enrollment_nodes']=value
    errors=setup_api().validate_infrastructure(d,check_files=False)
    assert errors and 'SECRET_SENTINEL' not in str(errors)

@pytest.mark.parametrize('field,value',[('ansible_connection','local'),('command','SECRET_SENTINEL'),('schema_version',True),('node_name','../bad'),('node_tag','tag:*'),('headscale_hostname','control.example.com'),('node_name','{{ bad }}'),('kind','setup-draft')])
def test_manifest_rejects_unsafe_fields(field,value):
    d=manifest(); d[field]=value
    errors=setup_api().validate_local_manifest(d)
    assert errors and 'SECRET_SENTINEL' not in str(errors)

def test_manifest_and_local_ownership():
    m=setup_api(); d=manifest(); assert m.validate_local_manifest(d)==[]
    assert m.local_ownership(d)=={'schema_version':2,'deployment_mode':'join','institution_id':'south','role':'peer','controller_hostname':'control.pilot.test','node_name':'home-services','node_tag':'tag:home-services','install_method':'local'}

@pytest.mark.parametrize('data',[None,[],{}, {'all':[]}])
def test_malformed_contracts_fail(data):
    assert setup_api().validate_infrastructure(data,check_files=False)
    assert setup_api().validate_local_manifest(data)

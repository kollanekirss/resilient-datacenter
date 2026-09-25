import copy
import importlib
from pathlib import Path
import sys
import pytest
import yaml
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))

def api():
    assert (ROOT/'scripts/profile_config.py').exists(), 'Profile validator not implemented'
    return importlib.import_module('profile_config')

def host(ip, **extras):
    return dict(ansible_host=ip, ansible_user='ubuntu', **extras)

def join():
    return {'all':{'vars':{'schema_version':1,'deployment_mode':'join','institution_id':'south','headscale_hostname':'control.pilot.test'},'children':{'peers':{'hosts':{'south-services':host('9.9.9.9',node_tag='tag:south-services')}}}}}

def independent(pair=False):
    d=join(); v=d['all']['vars']; v.update(deployment_mode='independent',derp_hostname='relay.pilot.test',enrollment_admin='lab-admin',derper_artifact='/local/derper',derper_sha256='a'*64)
    g=d['all']['children']; g['controller']={'hosts':{'north-control':host('1.1.1.1',tls_certificate='/local/control.crt',tls_private_key='/local/control.key')}}
    g['relay']={'hosts':{'west-relay':host('8.8.8.8',tls_certificate='/local/relay.crt',tls_private_key='/local/relay.key')}}
    if pair:
        g['peers']['hosts']['second-peer']=host('8.8.4.4',node_tag='tag:second-peer')
        g['peers']['hosts']['third-peer']=host('208.67.222.222',node_tag='tag:third-peer')
        v['connectivity_test']={'nodes':['south-services','second-peer'],'ca_certificate':'/local/ca.crt'}
        for name in v['connectivity_test']['nodes']:
            g['peers']['hosts'][name].update(test_dns_name=name+'.pilot.test',tls_certificate='/local/'+name+'.crt',tls_private_key='/local/'+name+'.key')
    return d

def test_join_no_remote_management_or_certificates():
    assert api().validate_profile(join(),check_files=True)==[]
    n=api().normalize_profile(join())
    assert n['controller_host'] is None and n['relay_host'] is None and n['policy'] is None
    assert n['test_pair']==[]

def test_independent_arbitrary_names_and_default_deny():
    d=independent(); assert api().validate_profile(d,check_files=False)==[]
    n=api().normalize_profile(d)
    assert n['controller_host']=='north-control' and n['relay_host']=='west-relay'
    assert n['policy']['grants']==[]
    assert n['policy']['tagOwners']=={'tag:south-services':['lab-admin@']}

def test_explicit_pair_never_grants_third_peer():
    n=api().normalize_profile(independent(True))
    assert len(n['policy']['grants'])==2
    assert all(g['ip']==['tcp:8443'] for g in n['policy']['grants'])
    assert 'tag:third-peer' not in str(n['policy']['grants'])

def test_join_can_request_pair_without_managing_policy():
    d=independent(True); v=d['all']['vars']; v['deployment_mode']='join'
    for key in ['derp_hostname','enrollment_admin','derper_artifact','derper_sha256']: del v[key]
    for group in ['controller','relay']: del d['all']['children'][group]
    n=api().normalize_profile(d)
    assert n['policy'] is None and len(n['requested_grants'])==2

@pytest.mark.parametrize('field,value',[
    ('schema_version',True),('schema_version',2),('deployment_mode','federate'),('institution_id','bad institution'),('institution_id','{{ dangerous }}'),('headscale_hostname','control.example.com'),('headscale_hostname','https://control.test'),('password','SECRET_SENTINEL'),('derper_artifact','/tmp/binary'),('federation',{}),
])
def test_bad_common_or_forbidden_join_variables(field,value):
    d=join(); d['all']['vars'][field]=value
    errors=api().validate_profile(d,check_files=False)
    assert errors and 'SECRET_SENTINEL' not in str(errors)

@pytest.mark.parametrize('field,value',[
    ('ansible_host','127.0.0.1'),('ansible_host','192.0.2.1'),('ansible_host','10.0.0.1'),('ansible_host','::1'),('ansible_user','bad;user'),('ansible_port',True),('ansible_port',65536),('ansible_connection','local'),('ansible_password','SECRET_SENTINEL'),('node_tag','tag:*'),('node_tag','autogroup:member'),('tls_private_key','/local/unneeded.key'),
])
def test_bad_host_inputs(field,value):
    d=join(); d['all']['children']['peers']['hosts']['south-services'][field]=value
    errors=api().validate_profile(d,check_files=False)
    assert errors and 'SECRET_SENTINEL' not in str(errors)

@pytest.mark.parametrize('names',[[],['south-services'],['south-services','south-services'],['south-services','missing'],['south-services','second-peer','third-peer']])
def test_invalid_test_pairs(names):
    d=independent(True); d['all']['vars']['connectivity_test']['nodes']=names
    assert api().validate_profile(d,check_files=False)

@pytest.mark.parametrize('data',[None,[],{}, {'all':None},{'all':{'vars':[],'children':{}}}])
def test_bad_shapes_return_errors(data):
    assert api().validate_profile(data,check_files=False)

def test_duplicate_host_names_addresses_and_tags():
    for which in ['name','address','tag']:
        d=independent(True); g=d['all']['children']
        if which=='name': g['controller']['hosts']={'south-services':next(iter(g['controller']['hosts'].values()))}
        if which=='address': g['peers']['hosts']['second-peer']['ansible_host']='9.9.9.9'
        if which=='tag': g['peers']['hosts']['second-peer']['node_tag']='tag:south-services'
        assert api().validate_profile(d,check_files=False)

def test_join_rejects_controller_host():
    d=join(); d['all']['children']['controller']={'hosts':{'external':{}}}
    assert api().validate_profile(d,check_files=False)

def test_ownership_includes_mode_role_and_controller():
    n=api().normalize_profile(join()); record=api().expected_ownership(n,'south-services')
    assert record=={'schema_version':1,'deployment_mode':'join','institution_id':'south','role':'peer','controller_hostname':'control.pilot.test'}
    with pytest.raises(ValueError): api().expected_ownership(n,'external')

def test_normalize_rejects_invalid_data():
    with pytest.raises(ValueError): api().normalize_profile({})

def test_loader_rejects_duplicates_aliases_and_sanitizes_errors(tmp_path):
    for body in ['all: {}\nall: SECRET_SENTINEL\n','all: &a [*a]','all: [SECRET_SENTINEL']:
        f=tmp_path/'input.yml'; f.write_text(body)
        with pytest.raises(ValueError) as error: api().load_profile(str(f))
        assert 'SECRET_SENTINEL' not in str(error.value)

def test_independent_files_required():
    assert api().validate_profile(independent(),check_files=True)

def test_profile_cli_emits_only_nonsecret_metadata(tmp_path):
    import subprocess
    p=tmp_path/'join.yml'; p.write_text(yaml.safe_dump(join()))
    result=subprocess.run([sys.executable,str(ROOT/'scripts/validate_profile.py'),str(p),'--json'],capture_output=True,text=True)
    assert result.returncode==0
    assert 'tls_private_key' not in result.stdout and 'ownership' in result.stdout

@pytest.mark.parametrize('name',['localhost','all','peers','controller','relay','profile-test-peers'])
def test_reserved_names_cannot_be_targets(name):
    d=join(); h=d['all']['children']['peers']['hosts'].pop('south-services'); d['all']['children']['peers']['hosts'][name]=h
    assert api().validate_profile(d,check_files=False)

def test_management_address_must_be_text_not_integer():
    d=join(); d['all']['children']['peers']['hosts']['south-services']['ansible_host']=16843009
    assert api().validate_profile(d,check_files=False)

import importlib
import json
from test_setup_contracts import manifest
from setup_contracts import local_ownership
import pytest


def profile():
    return {'kind':'nextcloud-services','schema_version':1,'institution_id':'south','node_name':'home-services',
            'nextcloud_hostname':'files.pilot.test','tls_mode':'supplied','tls_certificate':'/root/chain.crt','tls_private_key':'/root/key.pem'}


def test_nextcloud_has_distinct_owned_package_and_fixed_images():
    m=importlib.import_module('nextcloud_contracts');p=profile();network=local_ownership(manifest())
    assert m.validate(p)==[]
    owner=m.ownership(p,network)
    assert owner['packages']==['nextcloud'] and owner['network']==network
    assert set(m.image_pins())=={'postgres','nextcloud','proxy'}
    for item in m.image_pins().values():
        assert '@sha256:' in item['image'] and item['platform']=='linux/amd64'
    from service_contracts import ownership as matrix_owner
    with pytest.raises(ValueError):matrix_owner(p,network)
    network['node_name']='different'
    with pytest.raises(ValueError):m.ownership(p,network)


@pytest.mark.parametrize('key,value',[('kind','matrix-services'),('schema_version',True),('nextcloud_hostname','localhost'),
    ('nextcloud_hostname','files.example.com'),('tls_certificate','relative'),('image','unreviewed'),('password','secret'),('command','run')])
def test_nextcloud_rejects_unsafe_or_cross_package_inputs(key,value):
    m=importlib.import_module('nextcloud_contracts');p=profile();p[key]=value
    assert m.validate(p)


def test_configuration_rendering_preserves_literals_without_executable_input():
    m=importlib.import_module('nextcloud_rendering')
    data={'instanceid':'oc1234567890','passwordsalt':'a'*32,'secret':'b'*48,'version':'35.0.1.0',
          'dbpassword':'c'*64,'dbuser':'oc_admin','installed':True,'data_fingerprint':'d'*32}
    output=m.application_config(profile(),data)
    assert 'files.pilot.test' not in output  # Values encoded, never interpolated into PHP code.
    decoded=m.configuration_values(profile(),data)
    assert decoded['trusted_domains']==['files.pilot.test'] and decoded['trusted_proxies']==['127.0.0.1']
    assert decoded['dbhost']=='127.0.0.1:5434' and 'dbport' not in decoded
    assert decoded['dbuser']=='oc_admin' and decoded['dbpassword']==data['dbpassword']
    assert decoded['config_is_read_only'] and not decoded['appstoreenabled']
    assert decoded['datadirectory']=='/var/www/data' and decoded['overwriteprotocol']=='https'
    with pytest.raises(ValueError):m.application_config(profile(),dict(data,extra='executable'))


def test_file_service_wizard_only_prepares_private_configuration(tmp_path):
    m=importlib.import_module('nextcloud_setup')
    answers=iter(['south','home-services','files.pilot.test','/root/chain.crt','/root/key.pem','SAVE'])
    path=tmp_path/'files.json'
    result=m.wizard(path,input_fn=lambda _:next(answers),output_fn=lambda _:None)
    assert result['state']=='prepared' and result['installation']=='not-performed'
    assert json.loads(path.read_text())==profile()
    assert path.stat().st_mode&0o077==0


def test_file_service_wizard_cancel_writes_nothing(tmp_path):
    m=importlib.import_module('nextcloud_setup');path=tmp_path/'files.json'
    assert m.wizard(path,input_fn=lambda _:':cancel',output_fn=lambda _:None)['state']=='cancelled'
    assert not path.exists()

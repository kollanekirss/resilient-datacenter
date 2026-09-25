import importlib
import json
from copy import deepcopy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def configuration():
    return {'schema_version':1,'package':'matrix','application_owner':{'packages':['matrix'],'matrix_hostname':'matrix.north.test'},
            'gateway_fingerprint':'a'*64,'gateway_lan_address':'10.203.1.1','service_lan_address':'10.203.1.10','lan_subnet':'10.203.1.0/24',
            'peers':[{'hostname':'matrix.south.test','expires_at':1800003600}]}


def test_connector_keeps_client_config_and_uses_only_reviewed_proxy_and_federation_routes():
    m=importlib.import_module('service_regional');config=configuration()
    settings={'ownership':config['application_owner']}
    m.validate(config,settings)
    override=json.loads(m.synapse(config,now=1800000000))
    assert override['federation_domain_whitelist']==['matrix.south.test']
    assert override['https_proxy']=='http://10.203.1.1:3128'
    assert override['no_proxy_hosts']==[] and override['federation_verify_certificates'] is True
    assert 'database' not in override and 'listeners' not in override
    assert json.loads(m.synapse(config,now=1800003600))['federation_domain_whitelist']==[]
    original='original internal HTTPS configuration\n'
    text=m.proxy(original,config)
    assert text.startswith(original) and 'bind 10.203.1.10' in text and ':8443' in text
    assert 'remote_ip 10.203.1.1' in text and '/_matrix/federation/*' in text
    assert '/_matrix/client/' not in text and '/_synapse/admin' not in text


def test_connector_rejects_wrong_application_identity_and_arbitrary_targets():
    m=importlib.import_module('service_regional');config=configuration();settings={'ownership':config['application_owner']}
    for change in ({'gateway_lan_address':'169.254.169.254'},{'service_lan_address':'100.64.0.8'},
                   {'peers':[{'hostname':'https://attacker.test/path','expires_at':1800003600}]},
                   {'peers':[{'hostname':'matrix.south.test','expires_at':True}]},
                   {'application_owner':{'packages':['matrix'],'matrix_hostname':'another.test'}},
                   {'package':'nextcloud'},{'extra_directive':'allow all'}):
        with pytest.raises(ValueError):m.validate(dict(config,**change),settings)


def test_restore_permanently_suspends_connector_until_review(tmp_path,monkeypatch):
    m=importlib.import_module('service_regional');base=tmp_path/'connector';base.mkdir(mode=0o750)
    config=configuration();settings={'ownership':config['application_owner']}
    m.write(base/'configuration.json',json.dumps(config))
    pending=tmp_path/'restore-pending.json';pending.write_text('{}')
    monkeypatch.setattr(m,'BASE',base);monkeypatch.setattr(m,'RESTORE',pending)
    m.materialize(settings,'internal config\n')
    assert (base/'disabled.json').exists() and m.active(settings) is None
    pending.unlink()
    assert m.active(settings) is None
    (base/'disabled.json').unlink();m.materialize(settings,'internal config\n')
    assert m.active(settings)==config and (base/'Caddyfile').read_text().startswith('internal config\n')


def test_matrix_runtime_adds_connector_without_replacing_its_home_configuration(tmp_path,monkeypatch):
    m=importlib.import_module('service_regional');runtime=importlib.import_module('service_runtime')
    from test_service_runtime import settings
    current=settings();config=configuration();config['application_owner']=current['ownership'];config['peers'][0]['hostname']='matrix.north.test'
    base=tmp_path/'connector';base.mkdir(mode=0o750);m.write(base/'configuration.json',json.dumps(config))
    monkeypatch.setattr(m,'BASE',base);monkeypatch.setattr(m,'RESTORE',tmp_path/'absent')
    command=runtime.container_command('synapse',current)
    assert command[-5:]==['run','--config-path','/config/homeserver.yaml','--config-path','/regional/synapse.json']
    assert str(base)+':/regional:ro' in command and '/etc/ssl/certs:/etc/ssl/certs:ro' in command
    assert str(base/'Caddyfile')+':/etc/caddy/Caddyfile:ro' in runtime.container_command('proxy',current)
    m.write(base/'disabled.json','{}',mode=0o600)
    assert '/regional/synapse.json' not in runtime.container_command('synapse',current)


def test_interrupted_connector_preparation_keeps_home_service_configuration(tmp_path,monkeypatch):
    m=importlib.import_module('service_regional');base=tmp_path/'connector';base.mkdir(mode=0o750)
    monkeypatch.setattr(m,'BASE',base);monkeypatch.setattr(m,'RESTORE',tmp_path/'absent')
    m.write(base/'pending.json','{}',mode=0o600)
    settings={'ownership':configuration()['application_owner']}
    assert m.active(settings) is None
    m.materialize(settings,'internal configuration')
    assert not (base/'Caddyfile').exists()

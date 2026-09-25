import importlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
ROOT=Path(__file__).resolve().parents[1]


def fixture():
    plan=json.loads((ROOT/'examples/portable-site.json').read_text())
    plan['domains']={name:name+'.south.test' for name in ('chat','element','files')}
    network=json.loads((ROOT/'examples/portable-network.json').read_text())
    return plan,network


def api():return importlib.import_module('portable_frontend')


def test_frontend_pins_tls_names_addresses_and_replaces_spoofable_headers():
    plan,network=fixture();config=api().configuration(plan,network)
    text=api().nginx(config)
    assert 'proxy_ssl_verify on;' in text and 'proxy_ssl_server_name on;' in text
    for name in ('chat','element','files'):
        assert 'server_name '+plan['domains'][name]+';' in text
        assert 'proxy_ssl_name '+plan['domains'][name]+';' in text
    assert 'proxy_pass https://10.76.40.10;' in text
    assert 'proxy_pass https://10.76.40.11;' in text
    assert 'proxy_set_header X-Forwarded-For $remote_addr;' in text
    assert '$proxy_add_x_forwarded_for' not in text
    assert 'ssl_reject_handshake on;' in text
    assert 'if ($ssl_server_name != $host) { return 421; }' in text
    assert 'proxy_set_header Forwarded "";' in text
    assert 'resolver ' not in text


def test_frontend_firewall_keeps_admin_and_staff_separate_from_backends():
    config=api().configuration(*fixture())
    entries=api().firewall(config)
    text=json.dumps(entries)
    assert '"addr": "10.76.20.0", "len": 24' in text
    assert '10.76.10.20' in text
    assert '10.76.40.10' in text and '10.76.40.11' in text
    for name in ('input','output','forward'):
        chain=next(item['chain'] for item in entries if item.get('chain',{}).get('name')==name)
        assert chain['policy']=='drop'


def test_configuration_binds_plan_settings_and_exact_shapes():
    m=api();config=m.configuration(*fixture())
    assert m.validate(config)==config
    for changed in (dict(config,backend='8.8.8.8'),dict(config,address='0.0.0.0'),dict(config,schema_version=True)):
        with pytest.raises(ValueError):m.validate(changed)


def test_application_kit_verifies_rendered_files_and_rejects_tampering(tmp_path):
    import portable_application_bundle as bundle
    plan,settings=fixture();tmp_path.chmod(0o700);target=tmp_path/'kit'
    assert bundle.prepare(plan,settings,target)['state']=='applications-prepared'
    assert bundle.verify(target,plan,settings)['state']=='application-kit-verified'
    assert (target/'chat.json').is_file() and (target/'nginx.conf').is_file()
    (target/'nginx.conf').write_text('proxy_ssl_verify off;')
    with pytest.raises(ValueError):bundle.verify(target,plan,settings)
    with pytest.raises(ValueError):bundle.prepare(plan,settings,target)


def test_same_generation_renewal_restarts_to_finish_an_interrupted_activation(tmp_path,monkeypatch):
    import portable_application_install as m
    calls=[]
    monkeypatch.setattr(m,'BASE',tmp_path)
    monkeypatch.setattr(m,'directory',lambda path,**kwargs:path.mkdir(mode=0o700,exist_ok=True))
    monkeypatch.setattr(m,'write',lambda path,raw,**kwargs:path.write_bytes(raw))
    monkeypatch.setattr(m.subprocess,'run',lambda argv,**kwargs:calls.append(argv))
    values={'chat.crt':b'fixture-cert','chat.key':b'fixture-key'}
    m.activate_frontend_tls({},values)
    assert calls==[]
    m.activate_frontend_tls({},values,replace=True)
    assert calls==[['/bin/systemctl','restart','rdc-frontend.service']]


def test_firewall_check_accepts_kernel_chain_grouping_but_rejects_rule_reordering(monkeypatch):
    import portable_frontend_runtime as runtime
    config=api().configuration(*fixture());entries=api().firewall(config)
    reported=[entries[0]]
    for name in ('input','output','forward'):
        reported.extend(item for item in entries if item.get('chain',{}).get('name')==name)
        reported.extend(item for item in entries if item.get('rule',{}).get('chain')==name)
    def nft(*args,**kwargs):
        if args==('-j','list','tables'):return {'nftables':[entries[0]]}
        return {'nftables':reported}
    monkeypatch.setattr(runtime,'nft',nft)
    runtime.ingress(config)
    indices=[i for i,item in enumerate(reported) if item.get('rule',{}).get('chain')=='input']
    reported[indices[0]],reported[indices[-1]]=reported[indices[-1]],reported[indices[0]]
    with pytest.raises(ValueError):runtime.ingress(config)


def test_cli_prepares_private_kit_without_server_credentials(tmp_path,capsys):
    import rdc
    plan,settings=fixture();tmp_path.chmod(0o700)
    p=tmp_path/'site.json';n=tmp_path/'network.json'
    p.write_text(json.dumps(plan));n.write_text(json.dumps(settings))
    args=[str(p),'--settings',str(n),'--output-dir',str(tmp_path/'kit'),'--json']
    assert rdc.main(['portable','applications-prepare',*args])==0
    assert json.loads(capsys.readouterr().out)['deployment']=='not-performed'
    assert rdc.main(['portable','applications-verify',*args])==0
    assert json.loads(capsys.readouterr().out)['state']=='application-kit-verified'


def test_wizard_step_uses_saved_network_and_resumes_verification(tmp_path):
    from portable_state import write
    from portable_application_commands import wizard_step
    plan,settings=fixture();tmp_path.chmod(0o700);write(tmp_path/'network.json',settings)
    messages=[]
    assert wizard_step(plan,tmp_path,input_fn=lambda _: 'yes',output_fn=messages.append)['state']=='applications-prepared'
    assert wizard_step(plan,tmp_path,input_fn=lambda _:pytest.fail('Resume must not ask again'),output_fn=messages.append)['state']=='application-kit-verified'


def test_frontend_accepts_actual_ubuntu_nft_json_dump(monkeypatch):
    import portable_frontend_runtime as runtime
    observed=json.loads((ROOT/'tests/fixtures/portable/frontend-nft.json').read_text())
    monkeypatch.setattr(runtime,'nft',lambda *args,**kwargs:{'nftables':observed['nftables']})
    runtime.ingress(observed['configuration'])

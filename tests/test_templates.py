"""Structural checks are deliberately separate from Headscale's runtime parser."""
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml
ROOT=Path(__file__).resolve().parents[1]

def render(role,name,**values):
    e=Environment(loader=FileSystemLoader(ROOT/'roles'/role/'templates'),undefined=StrictUndefined)
    return e.get_template(name).render(**values)

def test_only_expected_bidirectional_application_grants():
    p=json.loads(render('controller','policy.json.j2',enrollment_admin='lab-admin'))
    a='tag:institution-a-server'; b='tag:institution-b-server'
    assert p['grants']==[{'src':[a],'dst':[b],'ip':['tcp:8443']},{'src':[b],'dst':[a],'ip':['tcp:8443']}]
    assert p['tagOwners']=={a:['lab-admin@'],b:['lab-admin@']}
    assert not set(p)-{'tagOwners','grants'}

def test_controller_has_explicit_policy_and_no_public_relay_fallback():
    c=yaml.safe_load(render('controller','config.yaml.j2',headscale_hostname='control.pilot.test'))
    assert c['policy']=={'mode':'file','path':'/etc/headscale/policy.json'}
    assert c['derp']['urls']==[] and c['derp']['paths']==['/etc/headscale/derp-map.yml']
    assert not c['derp']['server']['enabled']
    assert c['metrics_listen_addr'].startswith('127.0.0.1:')
    assert c['grpc_listen_addr'].startswith('127.0.0.1:')
    assert c['noise']['private_key_path'].startswith('/var/lib/headscale/')
    assert c['database']['sqlite']['path'].startswith('/var/lib/headscale/')
    assert not c['dns']['override_local_dns']

def test_relay_fail_closed_and_state_is_persistent():
    unit=render('relay','sc-derp.service.j2',derp_hostname='relay.pilot.test',headscale_hostname='control.pilot.test')
    assert '-verify-client-url=https://control.pilot.test/verify' in unit
    assert '-verify-client-url-fail-open=false' in unit
    assert '-c=/var/lib/sc-derp/derper.key' in unit
    assert '-http-port=-1' in unit

def test_private_relay_map_contains_exactly_one_node():
    m=yaml.safe_load(render('controller','derp-map.yml.j2',derp_hostname='relay.pilot.test',hostvars={'relay-01':{'ansible_host':'192.0.2.1'}}))
    assert list(m['regions'])==[901]
    assert len(m['regions'][901]['nodes'])==1
    assert m['regions'][901]['nodes'][0]['hostname']=='relay.pilot.test'

def test_test_service_binds_only_selected_overlay_address():
    unit=render('test_service','sc-test.service.j2',overlay_ip='100.64.0.1',inventory_hostname='server-a')
    assert '--bind=100.64.0.1' in unit and '0.0.0.0' not in unit

def test_deployment_does_not_enroll_or_reset_peers():
    text=(ROOT/'roles/client/tasks/main.yml').read_text()
    for forbidden in ['tailscale up','tailscale logout','--reset','--force-reauth','state: absent','--advertise-routes','--advertise-exit-node']:
        assert forbidden not in text

def verification_text(filename):
    text=(ROOT/'playbooks'/filename).read_text()
    plays=yaml.safe_load(text)
    for task in plays[1]['tasks']:
        if 'ansible.builtin.import_tasks' in task:
            text += (ROOT/'playbooks'/task['ansible.builtin.import_tasks']).read_text()
    return text

def test_verification_requires_valid_tls_identity_and_does_not_infer_outages():
    text=verification_text('verify.yml')
    assert '--cacert' in text and '--insecure' not in text
    assert '(health.stdout | from_json).server == peer_name' in text
    assert "'controller_outage': 'not-run'" in text
    assert "'forced_relay': 'not-run'" in text
    assert "'restore': 'not-run'" in text

def test_negative_probe_requires_listener_and_cleans_up():
    text=verification_text('verify-deny.yml')
    assert 'local_health.rc == 0' in text
    assert 'denied_probe.rc != 2' in text
    assert 'always:' in text and 'state: stopped' in text
    assert '--property=RuntimeMaxSec=120' in text

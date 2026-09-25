import importlib
import json
import yaml
from test_setup_contracts import ROOT

def wizard():
    assert (ROOT/'scripts/setup_wizard.py').exists(),'Setup wizard not implemented'
    return importlib.import_module('setup_wizard')

def test_join_wizard_generates_manifest_without_running_commands(tmp_path):
    replies=iter(['join','south','control.pilot.test','home-services','tag:home-services','yes'])
    messages=[]
    result=wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=messages.append)
    assert result=='prepared'
    m=yaml.safe_load((tmp_path/'node-home-services.yml').read_text())
    assert m['node_name']=='home-services' and m['kind']=='local-node'
    assert not (tmp_path/'infrastructure.yml').exists()

def test_draft_is_distinct_and_resumable(tmp_path):
    replies=iter(['join','south',':save'])
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='draft'
    draft=tmp_path/'draft.yml'; assert yaml.safe_load(draft.read_text())['kind']=='setup-draft'
    assert json.loads((tmp_path/'BUNDLE.json').read_text())['state']=='draft'
    # Resume presents saved answers for confirmation; remaining answers follow.
    replies=iter(['','','control.pilot.test','home-services','tag:home-services','yes','yes'])
    assert wizard().run_wizard(tmp_path,resume=draft,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='prepared'

def test_back_and_invalid_input_do_not_require_editing_yaml(tmp_path):
    replies=iter(['invalid','join','south',':back','north','control.pilot.test','home-services','tag:home-services','yes'])
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='prepared'
    assert yaml.safe_load((tmp_path/'node-home-services.yml').read_text())['institution_id']=='north'

def test_cancel_does_not_write(tmp_path):
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:':cancel',output_fn=lambda _:None)=='cancelled'
    assert not list(tmp_path.iterdir())

def test_independent_wizard_generates_infrastructure_and_two_manifests(tmp_path,monkeypatch):
    m=wizard()
    # Wizard test isolates prerequisite availability; TLS/file checks are tested separately.
    original=m.validate_infrastructure
    monkeypatch.setattr(m,'validate_infrastructure',lambda d,check_files=True:original(d,check_files=False))
    replies=iter(['independent','my-home','control.pilot.test','1.1.1.1','ubuntu','relay.pilot.test','8.8.8.8','ubuntu','lab-admin','supplied','/local/control.crt','/local/control.key','/local/relay.crt','/local/relay.key','/local/derper','a'*64,'2','home-services','tag:home-services','recovery-services','tag:recovery-services','yes'])
    assert m.run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='prepared'
    infra=yaml.safe_load((tmp_path/'infrastructure.yml').read_text())
    assert set(infra['all']['children'])=={'controller','relay'}
    assert len(infra['all']['vars']['enrollment_nodes'])==2
    assert (tmp_path/'node-home-services.yml').exists() and (tmp_path/'node-recovery-services.yml').exists()

def test_missing_infrastructure_files_save_draft_not_ready_output(tmp_path):
    replies=iter(['independent','my-home','control.pilot.test','1.1.1.1','ubuntu','relay.pilot.test','8.8.8.8','ubuntu','lab-admin','supplied','/absent/control.crt','/absent/control.key','/absent/relay.crt','/absent/relay.key','/absent/derper','a'*64,'1','home-services','tag:home-services'])
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='draft'
    assert not (tmp_path/'infrastructure.yml').exists()

def test_final_review_can_go_back_and_correct_tag(tmp_path):
    replies=iter(['join','south','control.pilot.test','home-services','tag:old',':back','tag:home-services','yes'])
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='prepared'
    assert yaml.safe_load((tmp_path/'node-home-services.yml').read_text())['node_tag']=='tag:home-services'

def test_final_review_can_save_draft(tmp_path):
    replies=iter(['join','south','control.pilot.test','home-services','tag:home-services',':save'])
    assert wizard().run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='draft'
    assert (tmp_path/'draft.yml').exists()


def test_managed_wizard_records_explicit_terms_without_requesting_keys(tmp_path,monkeypatch):
    m=wizard(); original=m.validate_infrastructure
    monkeypatch.setattr(m,'validate_infrastructure',lambda d,check_files=True:original(d,check_files=False))
    replies=iter(['independent','my-home','control.pilot.test','1.1.1.1','ubuntu','relay.pilot.test','8.8.8.8','ubuntu','lab-admin','managed-acme','admin@institution.test','accept','/local/derper','a'*64,'1','home-services','tag:home-services','yes'])
    assert m.run_wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=lambda _:None)=='prepared'
    infra=yaml.safe_load((tmp_path/'infrastructure.yml').read_text())
    assert infra['all']['vars']['schema_version']==3 and infra['all']['vars']['acme_terms_accepted'] is True
    assert 'tls_private_key' not in (tmp_path/'infrastructure.yml').read_text()


def test_acme_terms_require_literal_acceptance():
    assert wizard().acceptable('terms','accept')
    assert not wizard().acceptable('terms','yes')
    assert not wizard().acceptable('terms','')

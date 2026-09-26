import importlib
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))


def answers():
    return {
        'institution':'north', 'site':'tallinn',
        'proxmox_endpoint':'https://pve.north.example.org:8006',
        'node':'pve', 'storage':'local-lvm',
        'wan_bridge':'vmbr0', 'management_bridge':'vmbr1',
        'services_bridge':'vmbr2', 'partner_bridge':'vmbr3',
        'private_network':'10.76.0.0/16',
        'institution_controller_placement':'local',
        'institution_controller_url':'https://control.north.example.org',
        'institution_controller_location':'domestic',
        'institution_relay_placement':'external',
        'institution_relay_url':'https://relay.north.example.org',
        'institution_relay_location':'domestic',
        'partner_controller_placement':'existing',
        'partner_controller_url':'https://control.region.example.org',
        'partner_controller_location':'domestic',
        'partner_relay_placement':'existing',
        'partner_relay_url':'https://relay.region.example.org',
        'partner_relay_location':'domestic',
    }


def test_plan_keeps_two_networks_and_no_application_vms():
    m=importlib.import_module('connectivity_plan')
    data=m.record(answers())
    assert data['state']=='prepared' and data['deployment']=='not-performed'
    assert data['networks']['institution']['controller'] != data['networks']['partner']['controller']
    assert data['networks']['institution']['members']==['field-devices','opnsense']
    assert data['networks']['partner']['members']==['partner-gateway']
    assert {r['role'] for r in data['roles']}=={'opnsense','naming-time','partner-gateway','test-target',
        'institution_controller','institution_relay','partner_controller','partner_relay'}
    assert data['stages'][0]['state']=='planned'
    assert all(stage['state']=='unsupported' for stage in data['stages'][1:])
    assert all(stage['verified']==[] for stage in data['stages'])
    assert 'private CA' in m.render(data)


@pytest.mark.parametrize('field,value',[
    ('proxmox_endpoint','https://operator:SECRET@pve.example.org:8006'),
    ('proxmox_endpoint','http://pve.example.org'),
    ('proxmox_endpoint','https://pve:8006'),
    ('institution_controller_url','https://control.example.org:8006'),
    ('institution_controller_url','https://control.example.org/path'),
    ('wan_bridge','bad\nSECRET'),
    ('private_network','100.64.0.0/16'),
    ('private_network','10.76.1.0/16'),
    ('institution_relay_placement','wireguard'),
    ('institution_controller_location','somewhere'),
])
def test_unsafe_plan_inputs_are_rejected_without_echo(field,value):
    m=importlib.import_module('connectivity_plan');a=answers();a[field]=value
    with pytest.raises(ValueError) as error:m.record(a)
    assert 'SECRET' not in str(error.value)


def test_duplicate_authorities_and_bridge_names_are_rejected():
    m=importlib.import_module('connectivity_plan')
    for field,value in [('partner_controller_url','https://control.north.example.org/'),
                        ('services_bridge','vmbr1')]:
        a=answers();a[field]=value
        with pytest.raises(ValueError):m.record(a)


def test_foreign_dependencies_and_single_controller_are_not_called_resilient():
    m=importlib.import_module('connectivity_plan');a=answers()
    a['institution_relay_location']='foreign'
    data=m.record(a);report=m.render(data)
    assert 'foreign' in report and 'controller continuity' in report
    assert data['deployment']=='not-performed'
    assert data['limitations'] and 'not verified' in report


def test_incomplete_and_forged_records_cannot_claim_success():
    m=importlib.import_module('connectivity_plan')
    draft=m.record({'institution':'north'})
    assert draft['state']=='draft'
    with pytest.raises(ValueError):m.record({'site':'tallinn'})
    for change in ('stage','kind','extra','schema'):
        data=m.record(answers())
        if change=='stage':data['stages'][2]['state']='verified'
        if change=='kind':data['kind']='portable-site'
        if change=='extra':data['secret']='SECRET'
        if change=='schema':data['schema_version']=True
        with pytest.raises(ValueError):m.validate(data)


def test_save_resume_is_private_and_rejects_stale_writer(tmp_path):
    m=importlib.import_module('connectivity_plan');s=importlib.import_module('connectivity_state')
    folder=tmp_path/'connection';data=m.record({'institution':'north'})
    path=s.save(folder,data)
    assert folder.stat().st_mode&0o777==0o700
    assert path.stat().st_mode&0o777==0o600
    original=s.load(path);assert original==data
    changed=m.record({'institution':'north','site':'tallinn'})
    s.save(folder,changed,expected=original)
    with pytest.raises(ValueError):s.save(folder,data,expected=original)
    assert s.load(path)==changed
    with pytest.raises(ValueError):s.save(folder,data)


def test_state_refuses_symlinks_unrelated_files_and_concurrent_operation(tmp_path):
    m=importlib.import_module('connectivity_plan');s=importlib.import_module('connectivity_state')
    storage=importlib.import_module('portable_state');data=m.record({'institution':'north'})
    folder=tmp_path/'site';folder.mkdir(mode=0o700)
    foreign=folder/'site.json';foreign.write_text('do not change')
    with pytest.raises(ValueError):s.save(folder,data)
    assert foreign.read_text()=='do not change'
    second=tmp_path/'second';path=s.save(second,data)
    link=tmp_path/'link.json';link.symlink_to(path)
    with pytest.raises(ValueError):s.load(link)
    with storage.lock(second):
        with pytest.raises(ValueError):s.save(second,data,expected=data)
    path.chmod(0o644)
    with pytest.raises(ValueError):s.load(path)


def test_opening_screen_precedes_input_and_exit_writes_nothing(tmp_path):
    m=importlib.import_module('connectivity_wizard');events=[]
    def reply(prompt):
        assert events and 'Connectivity installer' in events[0]
        assert any('No servers' in e for e in events)
        events.append(prompt);return 'exit'
    result=m.wizard(tmp_path/'site',input_fn=reply,output_fn=events.append)
    assert result['state']=='cancelled'
    assert not (tmp_path/'site').exists()


def test_wizard_saves_draft_resumes_and_stops_at_unavailable_deployment(tmp_path):
    m=importlib.import_module('connectivity_wizard');s=importlib.import_module('connectivity_state')
    folder=tmp_path/'site';reply=iter(['start','north',':save'])
    result=m.wizard(folder,input_fn=lambda _:next(reply),output_fn=lambda _:None)
    assert result['state']=='draft'
    path=folder/'connectivity.json';assert s.load(path)['answers']=={'institution':'north'}
    # Resume revisits saved answers so the operator can review or correct them.
    reply=iter(['resume']+list(answers().values())+['SAVE']);output=[]
    result=m.wizard(folder,resume=path,input_fn=lambda _:next(reply),output_fn=output.append)
    assert result['state']=='prepared'
    assert s.load(path)['deployment']=='not-performed'
    assert 'Built/configured: none' in '\n'.join(output)
    assert 'Next step:' in '\n'.join(output)
    assert 'unsupported' in '\n'.join(output)


def test_back_clears_dependent_answers_and_cancel_preserves_saved_record(tmp_path):
    m=importlib.import_module('connectivity_wizard');s=importlib.import_module('connectivity_state')
    folder=tmp_path/'site';reply=iter(['start','north','tallinn',':back','tartu',':save'])
    m.wizard(folder,input_fn=lambda _:next(reply),output_fn=lambda _:None)
    path=folder/'connectivity.json';before=path.read_bytes()
    assert s.load(path)['answers']=={'institution':'north','site':'tartu'}
    reply=iter(['resume',':cancel'])
    assert m.wizard(folder,resume=path,input_fn=lambda _:next(reply),output_fn=lambda _:None)['state']=='cancelled'
    assert path.read_bytes()==before


def test_cli_scope_and_eof_do_not_install_or_create_outputs(tmp_path):
    result=subprocess.run([str(ROOT/'rdc'),'connectivity','install','--output-dir',str(tmp_path/'site')],
                          input='',text=True,capture_output=True)
    assert result.returncode==4
    assert 'Connectivity installer' in result.stdout
    assert 'Services are installed separately' in result.stdout
    assert 'No servers' in result.stdout
    assert not (tmp_path/'site').exists()

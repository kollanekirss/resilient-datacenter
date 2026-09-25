import json
from pathlib import Path
import subprocess
import sys
import yaml
import pytest
from test_profiles import ROOT, api, independent, join
from test_templates import render

def read(relative):
    p=ROOT/relative
    assert p.exists(), 'Profile deployment file not implemented: '+relative
    return yaml.safe_load(p.read_text())

def test_join_entry_point_has_only_peer_installation():
    plays=read('playbooks/profile-join.yml')
    installs=[p for p in plays if 'roles' in p]
    assert [p['hosts'] for p in installs]==['peers']
    assert installs[0]['roles']==['client']
    assert all('controller' not in str(p.get('roles',[])) and 'relay' not in str(p.get('roles',[])) for p in plays)
    assert installs[0]['pre_tasks'][0]['ansible.builtin.import_role']['name']=='profile_guard'

def test_independent_entry_point_and_guard():
    plays=read('playbooks/profile-independent.yml')
    installs=[p for p in plays if 'roles' in p]
    assert [p['hosts'] for p in installs]==['controller','relay','peers']
    assert all(p['pre_tasks'][0]['ansible.builtin.import_role']['name']=='profile_guard' for p in installs)

def test_guard_requires_validation_and_exact_ownership_before_claiming():
    tasks=read('roles/profile_guard/tasks/main.yml')
    text=json.dumps(tasks)
    assert 'profile_validated' in text and 'server-connectivity-profile.json' in text
    claim=next(i for i,t in enumerate(tasks) if 'ansible.builtin.copy' in t)
    assert claim>0
    assert any('expected_profile_ownership' in str(t.get('ansible.builtin.assert',{})) for t in tasks[:claim])
    assert 'profile_claim' in str(tasks[claim].get('when'))
    assert 'state: absent' not in text

def test_wrong_mode_cli_rejected_before_connections(tmp_path):
    api(); p=tmp_path/'join.yml'; p.write_text(yaml.safe_dump(join()))
    cli=ROOT/'scripts/validate_profile.py'; assert cli.exists()
    result=subprocess.run([sys.executable,str(cli),str(p),'--mode','independent'],capture_output=True,text=True)
    assert result.returncode==1 and 'mode' in result.stdout

def test_stopped_client_ownership_is_checked_without_liveness_exception():
    text=(ROOT/'roles/profile_guard/tasks/main.yml')
    assert text.exists(), 'Ownership guard missing'
    value=text.read_text()
    assert '(profile_marker.content | b64decode | from_json) == expected_profile_ownership' in value
    assert "BackendState != 'Running' or" not in value

def test_render_profile_policy_and_custom_relay():
    n=api().normalize_profile(independent())
    p=json.loads(render('controller','policy.json.j2',enrollment_admin='lab-admin',profile_policy=n['policy']))
    assert p==n['policy']
    relay=yaml.safe_load(render('controller','derp-map.yml.j2',derp_hostname='relay.pilot.test',profile_relay_host='west-relay',hostvars={'west-relay':{'ansible_host':'8.8.8.8'}}))
    assert relay['regions'][901]['nodes'][0]['ipv4']=='8.8.8.8'

def run_local_play(tmp_path, plays, inventory='localhost,'):
    import os
    path=tmp_path/'check.yml'; path.write_text(yaml.safe_dump(plays,sort_keys=False))
    env=dict(os.environ,ANSIBLE_CONFIG=str(ROOT/'ansible.cfg'),ANSIBLE_HOME=str(ROOT/'.cache/ansible'),ANSIBLE_LOCAL_TEMP=str(ROOT/'.work/ansible-tmp'),ANSIBLE_NOCOLOR='1')
    return subprocess.run([str(Path(sys.executable).parent/'ansible-playbook'),'-i',inventory,str(path)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=40)

@pytest.mark.parametrize('field',['deployment_mode','institution_id','role','controller_hostname'])
def test_ansible_ownership_assertion_rejects_each_mismatch_even_stopped(tmp_path,field):
    import base64
    expected=api().expected_ownership(api().normalize_profile(join()),'south-services')
    actual=dict(expected); actual[field]='different'
    task=next(t for t in read('roles/profile_guard/tasks/main.yml') if t['name']=='Require the exact same profile, institution, role and controller')
    result=run_local_play(tmp_path,[{'hosts':'localhost','connection':'local','gather_facts':False,'vars':{'expected_profile_ownership':expected,'profile_marker':{'content':base64.b64encode(json.dumps(actual).encode()).decode()},'profile_marker_stat':{'stat':{'exists':True}},'profile_daemon':{'rc':3}},'tasks':[task]}])
    assert result.returncode!=0 and 'Ownership differs' in result.stdout, result.stdout+result.stderr


def test_local_pair_selection_excludes_third_node(tmp_path):
    data=independent(True); n=api().normalize_profile(data)
    tasks=read('playbooks/tasks/profile-select-pair.yml')
    tasks.append({'name':'Assert exact selected membership','ansible.builtin.assert':{'that':["groups.profile_test_peers | sort == ['second-peer', 'south-services']", "'third-peer' not in groups.profile_test_peers", "hostvars['south-services'].peer_name == 'second-peer'"]}})
    result=run_local_play(tmp_path,[{'hosts':'localhost','connection':'local','gather_facts':False,'vars':{'profile':n,'profile_validated':True,'connectivity_test':data['all']['vars']['connectivity_test']},'tasks':tasks}])
    assert result.returncode==0,result.stdout+result.stderr


def test_local_pair_selection_requires_explicit_pair(tmp_path):
    result=run_local_play(tmp_path,[{'hosts':'localhost','connection':'local','gather_facts':False,'vars':{'profile':api().normalize_profile(join()),'profile_validated':True},'tasks':read('playbooks/tasks/profile-select-pair.yml')}])
    assert result.returncode!=0 and 'Configure connectivity_test' in result.stdout,result.stdout+result.stderr


def test_shared_verification_matches_legacy_behavior():
    assert read('playbooks/tasks/verify-positive.yml')==read('playbooks/'+read('playbooks/verify.yml')[1]['tasks'][0]['ansible.builtin.import_tasks'])
    assert read('playbooks/tasks/verify-negative.yml')==read('playbooks/'+read('playbooks/verify-deny.yml')[1]['tasks'][0]['ansible.builtin.import_tasks'])


def test_local_guard_fails_before_remote_access_without_validation(tmp_path):
    task=read('roles/profile_guard/tasks/main.yml')[0]
    result=run_local_play(tmp_path,[{'hosts':'localhost','connection':'local','gather_facts':False,'tasks':[task]}])
    assert result.returncode!=0 and 'Local validation must run first' in result.stdout,result.stdout+result.stderr

def test_legacy_preflight_rejects_versioned_owned_hosts():
    tasks=read('playbooks/preflight.yml')[1]['tasks']
    assert any(t.get('ansible.builtin.stat',{}).get('path')=='/etc/server-connectivity-profile.json' for t in tasks)
    assert any('legacy_profile_marker' in str(t.get('ansible.builtin.assert',{})) for t in tasks)


def test_policy_renders_with_actual_ansible_filters(tmp_path):
    output=tmp_path/'policy.json'; n=api().normalize_profile(independent())
    tasks=[{'name':'Render actual controller template','ansible.builtin.template':{'src':str(ROOT/'roles/controller/templates/policy.json.j2'),'dest':str(output),'mode':'0600'}}]
    result=run_local_play(tmp_path,[{'hosts':'localhost','connection':'local','gather_facts':False,'vars':{'profile_policy':n['policy']},'tasks':tasks}])
    assert result.returncode==0,result.stdout+result.stderr
    assert json.loads(output.read_text())==n['policy']

@pytest.mark.parametrize('case',['invalid','wrong-mode'])
def test_real_entry_point_rejects_bad_input_before_any_ssh(tmp_path,case):
    import os
    inventory=tmp_path/'inventory.yml'
    data=join()
    if case=='invalid': data['all']['vars']['password']='SECRET_SENTINEL'
    inventory.write_text(yaml.safe_dump(data))
    evidence=tmp_path/'ssh-called'
    stub=tmp_path/'ssh-stub.py'
    stub.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath('+repr(str(evidence))+').write_text("unexpected")\nraise SystemExit(99)\n')
    stub.chmod(0o700)
    env=dict(os.environ,ANSIBLE_CONFIG=str(ROOT/'ansible.cfg'),ANSIBLE_HOME=str(ROOT/'.cache/ansible'),ANSIBLE_LOCAL_TEMP=str(ROOT/'.work/ansible-tmp'),ANSIBLE_SSH_EXECUTABLE=str(stub),ANSIBLE_NOCOLOR='1')
    play='profile-independent.yml' if case=='wrong-mode' else 'profile-join.yml'
    result=subprocess.run([str(Path(sys.executable).parent/'ansible-playbook'),'-i',str(inventory),str(ROOT/'playbooks'/play)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=40)
    assert result.returncode!=0 and not evidence.exists(),result.stdout+result.stderr
    assert 'ERROR:' in result.stdout and 'SECRET_SENTINEL' not in result.stdout,result.stdout+result.stderr

def test_legacy_and_profiles_share_one_verification_implementation():
    for name,target in [('verify.yml','tasks/verify-positive.yml'),('verify-deny.yml','tasks/verify-negative.yml')]:
        tasks=read('playbooks/'+name)[1]['tasks']
        assert len(tasks)==1 and tasks[0].get('ansible.builtin.import_tasks')==target

def test_tag_filter_cannot_silently_skip_profile_validation(tmp_path):
    import os
    inventory=tmp_path/'inventory.yml'; inventory.write_text(yaml.safe_dump(join()))
    env=dict(os.environ,ANSIBLE_CONFIG=str(ROOT/'ansible.cfg'),ANSIBLE_HOME=str(ROOT/'.cache/ansible'),ANSIBLE_LOCAL_TEMP=str(ROOT/'.work/ansible-tmp'),ANSIBLE_SSH_EXECUTABLE='/usr/bin/false',ANSIBLE_NOCOLOR='1')
    result=subprocess.run([str(Path(sys.executable).parent/'ansible-playbook'),'-i',str(inventory),'playbooks/profile-join.yml','--tags','not-a-stage'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=40)
    assert result.returncode!=0 and 'tag filters' in result.stdout,result.stdout+result.stderr

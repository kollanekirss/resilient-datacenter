from pathlib import Path
import yaml
from test_profiles import ROOT

def test_only_two_managed_infrastructure_roles():
    p=ROOT/'playbooks/infrastructure-deploy.yml'
    assert p.exists(),'Infrastructure entry point not implemented'
    plays=yaml.safe_load(p.read_text())
    assert [p['hosts'] for p in plays if 'roles' in p]==['controller','relay']
    assert [p['roles'] for p in plays if 'roles' in p]==[['controller'],['relay']]
    assert 'peers' not in p.read_text()

def test_invalid_infrastructure_fails_before_ssh(tmp_path):
    import os,subprocess,sys
    from test_setup_contracts import infrastructure
    data=infrastructure(); data['all']['vars']['enrollment_nodes'][0]['command']='SECRET_SENTINEL'
    inv=tmp_path/'inventory.yml'; inv.write_text(yaml.safe_dump(data))
    called=tmp_path/'ssh-called'; stub=tmp_path/'ssh.py'
    stub.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath('+repr(str(called))+').write_text("unexpected")\nraise SystemExit(99)\n'); stub.chmod(0o700)
    env=dict(os.environ,ANSIBLE_CONFIG=str(ROOT/'ansible.cfg'),ANSIBLE_HOME=str(ROOT/'.cache/ansible'),ANSIBLE_LOCAL_TEMP=str(ROOT/'.work/ansible-tmp'),ANSIBLE_SSH_EXECUTABLE=str(stub),ANSIBLE_NOCOLOR='1')
    result=subprocess.run([str(Path(sys.executable).parent/'ansible-playbook'),'-i',str(inv),'playbooks/infrastructure-deploy.yml'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode!=0 and not called.exists(),result.stdout+result.stderr
    assert 'SECRET_SENTINEL' not in result.stdout

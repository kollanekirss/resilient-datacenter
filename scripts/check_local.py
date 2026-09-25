#!/usr/bin/env python3
"""Run local checks and read-only Ansible task listing. Never deploy to real targets."""
from pathlib import Path
import os
import subprocess
import sys
from operation_environment import ansible_environment
ROOT=Path(__file__).resolve().parents[1]


def main():
    env=ansible_environment(ROOT)
    subprocess.run([sys.executable,'-m','pytest','tests','-q'],cwd=ROOT,env=env,check=True)
    ansible=Path(sys.executable).parent/'ansible-playbook'
    for playbook in sorted((ROOT/'playbooks').glob('*.yml')):
        if playbook.name == 'local-node.yml':
            inventory='localhost,'
        elif playbook.name.startswith('infrastructure-'):
            inventory='inventories/examples/infrastructure/hosts.yml'
        elif playbook.name.startswith('profile-'):
            inventory='inventories/examples/join/hosts.yml' if playbook.name in ('profile-join.yml','profile-enrollment.yml') else 'inventories/examples/independent/hosts.yml'
        else:
            inventory='inventories/example/hosts.yml'
        subprocess.run([str(ansible),'-i',inventory,str(playbook),'--syntax-check'],cwd=ROOT,env=env,check=True)
    cases=[('scripts/validate_inventory.py','inventories/example/hosts.yml'),('scripts/validate_profile.py','inventories/examples/independent/hosts.yml'),('scripts/validate_profile.py','inventories/examples/join/hosts.yml')]
    for script,inventory in cases:
        check=subprocess.run([sys.executable,script,inventory],cwd=ROOT,capture_output=True)
        if check.returncode!=1:
            raise RuntimeError('Documentation inventory must fail deployment validation: '+inventory)
    for kind,example in [('infrastructure','inventories/examples/infrastructure/hosts.yml'),('local-node','examples/local-node.yml')]:
        result=subprocess.run([sys.executable,'scripts/validate_setup.py',example,'--kind',kind],cwd=ROOT,capture_output=True)
        if result.returncode!=1: raise RuntimeError('Setup documentation input must fail validation')
    infrastructure=subprocess.run([str(ansible),'-i','tests/fixtures/setup/infrastructure.yml','playbooks/infrastructure-deploy.yml','--list-hosts','--list-tasks'],cwd=ROOT,env=env,capture_output=True,text=True,check=True)
    if 'client : ' in infrastructure.stdout or 'south-services' in infrastructure.stdout:
        raise RuntimeError('Infrastructure task listing must not manage a planned home node')
    print('Infrastructure-only task/host listing passed (no target connections).')
    for mode in ('independent','join'):
        result=subprocess.run([str(ansible),'-i',f'tests/fixtures/profiles/{mode}.yml',f'playbooks/profile-{mode}.yml','--list-hosts','--list-tasks'],cwd=ROOT,env=env,capture_output=True,text=True,check=True)
        if mode=='join' and ('controller : ' in result.stdout or 'relay : ' in result.stdout):
            raise RuntimeError('Join task list must not contain controller/relay installation')
        print(mode+' host/task listing passed (no target connections).')
    print('Offline checks passed. Dynamic test-group syntax warnings are expected: the pair is selected at runtime.')
    print('Live installation, Headscale runtime policy validation, connectivity and recovery remain NOT RUN.')

if __name__=='__main__': main()

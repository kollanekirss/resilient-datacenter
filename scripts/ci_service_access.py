"""Validate generated grants against the actual disposable Headscale controller."""
import json
import os
from pathlib import Path
import subprocess
from profile_config import load_profile
from service_access import change
from setup_contracts import normalize_infrastructure


def exercise():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Policy acceptance requires a disposable GitHub-hosted controller')
    root=Path(__file__).resolve().parents[1]
    inventory=load_profile(str(root/'tests/fixtures/setup/infrastructure.yml'))
    inventory['all']['vars']['enrollment_nodes'].append({'name':'ci-user','node_tag':'tag:ci-user'})
    inventory=change(inventory,'ci-user','south-services','https')
    inventory=change(inventory,'south-services','ci-user','backup')
    command=['/usr/bin/headscale','--config','/etc/headscale/config.yaml']
    subprocess.run(command+['users','create','lab-admin'],check=True,capture_output=True,timeout=30)
    candidate=Path('/root/rdc-ci-policy.json')
    candidate.write_text(json.dumps(normalize_infrastructure(inventory)['policy']));candidate.chmod(0o600)
    subprocess.run(command+['policy','check','--file',str(candidate)],check=True,capture_output=True,timeout=30)
    print('Actual Headscale parser accepts generated HTTPS and backup access grants. VPN packet enforcement remains a separate network acceptance test.',flush=True)

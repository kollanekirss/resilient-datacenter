"""Complete, guarded offsite operations over a private reviewed snapshot."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from profile_config import load_profile
from setup_contracts import validate_infrastructure
from operation_environment import ansible_environment
from operation_results import ActionResult, Exit, OperationError, result_for_state

ROOT=Path(__file__).resolve().parents[1]


def run_infrastructure(action: str, inventory_path: Path, *, ask_become_pass=False,
                       runner=subprocess.run, confirm_fn=input) -> ActionResult:
    if action not in ('check','apply') or (action=='check' and ask_become_pass):
        raise OperationError('operation.invalid',Exit.INVALID)
    try:
        data=load_profile(str(inventory_path))
        if validate_infrastructure(data,check_files=True):
            raise OperationError('manifest.invalid',Exit.INVALID)
    except (OSError,ValueError):
        raise OperationError('manifest.invalid',Exit.INVALID) from None
    print('Remote infrastructure: controller and relay only. Planned local nodes are not SSH targets.')
    for role,group in data['all']['children'].items():
        for name,host in group['hosts'].items():
            print(f"  {role}: {name} ({host['ansible_host']})")
    try:
        if action=='apply' and confirm_fn('Apply these remote infrastructure changes? Type yes: ').strip().lower()!='yes':
            return result_for_state('cancelled')
        with tempfile.TemporaryDirectory(prefix='rdc-infrastructure-') as folder:
            snapshot=Path(folder)/'inventory.json'
            snapshot.write_text(json.dumps(data)); snapshot.chmod(0o600)
            playbook='infrastructure-preflight.yml' if action=='check' else 'infrastructure-deploy.yml'
            command=[str(Path(sys.executable).parent/'ansible-playbook'),'-i',str(snapshot),str(ROOT/'playbooks'/playbook)]
            if ask_become_pass: command.append('--ask-become-pass')
            kwargs={'cwd':ROOT,'env':ansible_environment(ROOT),'check':True}
            if action=='check': kwargs['stdin']=subprocess.DEVNULL
            runner(command,**kwargs)
        return result_for_state('checks-passed' if action=='check' else 'installed')
    except (KeyboardInterrupt,EOFError):
        return result_for_state('cancelled')
    except (OSError,subprocess.SubprocessError):
        raise OperationError('operation.failed',Exit.FAILED) from None

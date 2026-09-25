#!/usr/bin/env python3
"""Explicit local-node check/apply/enroll/status; no remote-target installation."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from profile_config import load_profile
from setup_contracts import validate_local_manifest
from local_checks import check_local, inspect_local_checks
from operation_environment import ansible_environment
from operation_results import ActionResult, Exit, OperationError, result_for_state, blocking_checks

ROOT=Path(__file__).resolve().parents[1]


def install_command(manifest_path: Path, *, as_root: bool):
    command=[str(Path(sys.executable).parent/'ansible-playbook'),'-i','localhost,',str(ROOT/'playbooks/local-node.yml'),'--extra-vars',json.dumps({'local_manifest_path':str(manifest_path.absolute()),'local_apply_requested':True})]
    if not as_root: command.append('--ask-become-pass')
    return command


def apply_manifest(manifest, path, *, runner=subprocess.run, checker=check_local, confirm_fn=input):
    if validate_local_manifest(manifest): raise ValueError('Invalid manifest; installation refused')
    errors=checker(manifest)
    if errors: raise ValueError('; '.join(errors))
    print('Install the networking client on THIS machine: '+socket.gethostname()+'. Controller: '+manifest['headscale_hostname']+'. No applications or backups will be installed.')
    if confirm_fn('Apply these local changes? Type yes: ').strip().lower()!='yes': return {'status':'cancelled'}
    # Apply a private snapshot of the reviewed data, never an arbitrary inventory.
    with tempfile.TemporaryDirectory(prefix='sc-local-') as folder:
        snapshot=Path(folder)/'manifest.json'; snapshot.write_text(json.dumps(manifest)); snapshot.chmod(0o600)
        env=ansible_environment(ROOT)
        runner(install_command(snapshot,as_root=os.geteuid()==0),cwd=ROOT,env=env,check=True)
    return {'status':'installed','enrollment':'not-verified'}


def execute_local(action: str, manifest_path: Path) -> ActionResult:
    if action not in ('check','apply','enroll','status'):
        raise OperationError('operation.invalid',Exit.INVALID)
    try:
        manifest=load_profile(str(manifest_path))
    except (OSError,ValueError):
        raise OperationError('manifest.invalid',Exit.INVALID) from None
    if validate_local_manifest(manifest):
        raise OperationError('manifest.invalid',Exit.INVALID)
    checks=inspect_local_checks(manifest,require_owned=action in ('enroll','status'),check_tls=action!='status')
    if blocking_checks(checks):
        return ActionResult('blocked',Exit.BLOCKED,tuple(checks))
    try:
        if action=='apply': result=apply_manifest(manifest,manifest_path)
        elif action=='check': result={'status':'checks-passed','clock_sync':'not-verified'}
        else:
            from local_enrollment import NativeRuntime, enrollment_action
            result=enrollment_action(manifest,NativeRuntime(allow_sudo=action=='enroll'),start_requested=action=='enroll')
        return result_for_state(result['status'],details=result)
    except (ValueError,TypeError,AttributeError,KeyError):
        raise OperationError('client.state_mismatch',Exit.BLOCKED) from None
    except (OSError,subprocess.SubprocessError):
        raise OperationError('operation.failed',Exit.FAILED) from None
    except (KeyboardInterrupt,EOFError):
        return result_for_state('cancelled')


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('action',choices=['check','apply','enroll','status']); p.add_argument('manifest',type=Path); a=p.parse_args()
    try:
        manifest=load_profile(str(a.manifest))
        errors=validate_local_manifest(manifest)
        if errors: raise ValueError('; '.join(errors))
        if a.action=='apply': result=apply_manifest(manifest,a.manifest)
        else:
            errors=check_local(manifest,require_owned=a.action in ('enroll','status'),check_tls=a.action!='status')
            if errors: raise ValueError('; '.join(errors))
            if a.action=='check': result={'status':'checks-passed','machine':socket.gethostname(),'clock_sync':'not-verified'}
            else:
                from local_enrollment import NativeRuntime, enrollment_action
                result=enrollment_action(manifest,NativeRuntime(),start_requested=a.action=='enroll')
        print(json.dumps({**result,'generated_at_utc':datetime.now(timezone.utc).isoformat()},indent=2))
        return 0 if result['status'] not in ('cancelled','client_not_running') else 1
    except ValueError as error:
        print('ERROR: '+str(error)); return 1
    except (OSError,subprocess.SubprocessError):
        print('ERROR: Local operation failed. Inspect prerequisites/service state; no reset was attempted.'); return 1
    except (KeyboardInterrupt,EOFError):
        print('Cancelled. Persistent node state was preserved.'); return 1
if __name__=='__main__': raise SystemExit(main())

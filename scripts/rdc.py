#!/usr/bin/env python3
"""Guided networking operations. Preparation, installation and enrollment are separate."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
# The launcher uses isolated Python; only the reviewed project supplies local modules.
sys.path.insert(0,str(ROOT/'scripts'))
try:
    from operation_results import Exit, OperationError, ActionResult, message, result_for_state, blocking_checks
    from setup_wizard import run_wizard
    from setup_contracts import validate_local_manifest
    from profile_config import load_profile
    from local_node import execute_local
    from infrastructure_operations import run_infrastructure
    from doctor import diagnose
    from source_identity import source_identity
    from release_download import fetch as fetch_release
    from support_report import make_report, write_report
except ImportError:
    print('Project dependencies are missing. From the project directory run:\n'
          '.venv/bin/python -m pip install -r requirements.txt',file=sys.stderr)
    raise SystemExit(3)


class Parser(argparse.ArgumentParser):
    def __init__(self,*args,**kwargs):
        kwargs['allow_abbrev']=False
        super().__init__(*args,**kwargs)

    def error(self,message):
        raise OperationError('operation.invalid',Exit.INVALID)


def parser():
    result=Parser(prog='rdc',description=__doc__)
    commands=result.add_subparsers(dest='command',required=True)
    setup=commands.add_parser('setup',help='Prepare private configuration; changes no servers')
    setup.add_argument('--resume',type=Path)
    setup.add_argument('--output-dir',type=Path,default=ROOT/'inventories/lab/setup')
    infrastructure=commands.add_parser('infrastructure',help='Check or deploy the remote controller and relay')
    infra_actions=infrastructure.add_subparsers(dest='action',required=True)
    for action in ('check','apply'):
        command=infra_actions.add_parser(action)
        command.add_argument('inventory',type=Path)
        if action=='apply': command.add_argument('--ask-become-pass',action='store_true')
    node=commands.add_parser('node',help='Operate on THIS Ubuntu computer only')
    node_actions=node.add_subparsers(dest='action',required=True)
    for action in ('check','apply','enroll','status'):
        node_actions.add_parser(action).add_argument('manifest',type=Path)
    doctor=commands.add_parser('doctor',help='Read-only local and controller diagnostics; no sudo prompts')
    doctor.add_argument('manifest',type=Path)
    doctor.add_argument('--report',type=Path)
    backup=commands.add_parser('backup',help='Encrypted backups and isolated restore staging on the managed Ubuntu server')
    backup_commands=backup.add_subparsers(dest='action',required=True)
    backup_commands.add_parser('setup',help='Prepare a backup connection profile without changing servers').add_argument('--output-file',type=Path,required=True)
    configure=backup_commands.add_parser('configure',help='Create local backup credentials or import saved recovery access')
    configure.add_argument('profile',type=Path)
    configure.add_argument('--recovery-password-file',type=Path)
    configure.add_argument('--recovery-ssh-key-file',type=Path)
    for action in ('initialize','run','status','restore-recover','include-services'): backup_commands.add_parser(action)
    backup_commands.add_parser('restore-stage',help='Decrypt a specific snapshot into private staging; never promote').add_argument('snapshot')
    for action in ('restore-plan','restore-apply'):
        backup_commands.add_parser(action,help='Review or explicitly promote an already staged snapshot').add_argument('snapshot')
    schedule=backup_commands.add_parser('schedule',help='Opt-in consistent backups with brief service pauses')
    scheduled=schedule.add_subparsers(dest='schedule_action',required=True)
    scheduled.add_parser('enable').add_argument('--frequency',choices=('hourly','daily'),required=True)
    for action in ('disable','status'): scheduled.add_parser(action)
    target=backup_commands.add_parser('target',help='Prepare dedicated SFTP storage over the private overlay')
    targets=target.add_subparsers(dest='target_action',required=True)
    targets.add_parser('prepare').add_argument('manifest',type=Path)
    targets.add_parser('authorize').add_argument('public_key',type=Path)
    services=commands.add_parser('services',help='Prepare and operate the experimental local Matrix package')
    service_commands=services.add_subparsers(dest='action',required=True)
    service_commands.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    for action in ('check','apply'): service_commands.add_parser(action).add_argument('profile',type=Path)
    service_commands.add_parser('status')
    service_commands.add_parser('account').add_argument('--admin',action='store_true')
    release=commands.add_parser('release',help='Download and verify an experimental release; never install')
    fetch=release.add_subparsers(dest='action',required=True).add_parser('fetch')
    fetch.add_argument('version')
    fetch.add_argument('--commit',required=True)
    fetch.add_argument('--output-dir',type=Path,required=True)
    commands.add_parser('version',help='Show source identity and pinned component versions')
    return result


def menu():
    print('Networking pilot — choose an action:\n'
          '  1 Prepare configuration (no server changes)\n'
          '  2 Check remote controller/relay\n'
          '  3 Apply remote controller/relay\n'
          '  4 Check this local node\n'
          '  5 Install this local node\n'
          '  6 Enroll this local node\n'
          '  7 Show this local node status\n'
          '  8 Diagnose this node/controller\n'
          '  9 Show project version\n'
          '  0 Quit')
    choice=input('Choice: ').strip()
    if choice=='0': return None
    if choice=='1': return ['setup']
    if choice=='9': return ['version']
    commands={'2':['infrastructure','check'],'3':['infrastructure','apply'],
              '4':['node','check'],'5':['node','apply'],'6':['node','enroll'],
              '7':['node','status'],'8':['doctor']}
    if choice not in commands: raise OperationError('operation.invalid',Exit.INVALID)
    command=commands[choice]+[input('Absolute configuration file path: ').strip()]
    if choice=='3' and input('Request a remote sudo password interactively? Type yes if needed: ').strip().lower()=='yes':
        command.append('--ask-become-pass')
    return command


def show_checks(checks):
    for item in checks:
        print(f'{item.outcome.upper()}: {message(item)}')
        if item.outcome in ('fail','unknown'):
            print('  Next: '+item.next_step.replace('-',' '))


def doctor_exit(checks):
    if any(c.code=='manifest.invalid' for c in checks): return Exit.INVALID
    if any(c.code.startswith('probe.') for c in checks): return Exit.FAILED
    if any(c.code.startswith(('dns.','tcp.','tls.')) and c.outcome=='fail' for c in checks): return Exit.FAILED
    if blocking_checks(checks): return Exit.BLOCKED
    if any(c.code=='client.awaiting_enrollment' for c in checks): return Exit.PENDING
    return Exit.SUCCESS


def service_action(args):
    from service_operations import action
    return action(args)


def backup_action(args):
    from backup_operations import action
    return action(args)


def dispatch(args) -> ActionResult:
    if args.command=='setup':
        state=run_wizard(args.output_dir,resume=args.resume,input_fn=input)
        return result_for_state(state)
    if args.command=='services':
        try: outcome=service_action(args)
        except ValueError as error:
            print('Application action blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        return result_for_state({'prepared':'prepared','cancelled':'cancelled'}.get(outcome.get('state'),'checks-passed'))
    if args.command=='backup':
        try: outcome=backup_action(args)
        except ValueError as error:
            print('Backup action blocked: '+str(error))
            return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        return result_for_state({'no-backup':'blocked','backup-unreachable':'blocked','backup-overdue':'blocked','application-backup-missing':'blocked','cancelled':'cancelled','prepared':'prepared'}.get(outcome.get('state'),'checks-passed'))
    if args.command=='release':
        try: fetch_release(args.version,args.commit,args.output_dir)
        except ValueError as error:
            print('Release blocked: '+str(error))
            return result_for_state('blocked')
        print('Release verified. No servers were changed and no downloaded program was executed.')
        return result_for_state('checks-passed')
    if args.command=='version':
        print(json.dumps(source_identity(ROOT),indent=2))
        return result_for_state('checks-passed')
    if args.command=='infrastructure':
        return run_infrastructure(args.action,args.inventory,ask_become_pass=getattr(args,'ask_become_pass',False))
    if args.command=='node':
        print('Scope: THIS computer. Local installation supports Ubuntu 24.04 amd64 with systemd.')
        return execute_local(args.action,args.manifest)
    if args.command=='doctor':
        try: manifest=load_profile(str(args.manifest))
        except (OSError,ValueError): raise OperationError('manifest.invalid',Exit.INVALID) from None
        if validate_local_manifest(manifest): raise OperationError('manifest.invalid',Exit.INVALID)
        checks=diagnose(manifest)
        show_checks(checks)
        print('Local time (clock synchronization not independently verified): '+datetime.now(timezone.utc).isoformat())
        print('Diagnostics do not establish deployment readiness, NAT traversal or service resilience.')
        if args.report:
            report=make_report(checks,source_identity(ROOT),
                               {'system':platform.system(),'architecture':platform.machine()},
                               generated_at=datetime.now(timezone.utc).isoformat())
            try: write_report(args.report,report)
            except (OSError,ValueError): raise OperationError('report.failed',Exit.FAILED) from None
            print('Private support report written. Review it before sharing.')
        code=doctor_exit(checks)
        state={Exit.SUCCESS:'checks-passed',Exit.BLOCKED:'blocked',Exit.PENDING:'awaiting_enrollment'}.get(code,'failed')
        return ActionResult(state,code)
    raise OperationError('operation.invalid',Exit.INVALID)


def main(argv=None) -> int:
    try:
        command=parser()
        argv=list(sys.argv[1:] if argv is None else argv)
        if not argv:
            if not sys.stdin.isatty():
                command.print_help(); return int(Exit.SUCCESS)
            argv=menu()
            if argv is None: return int(Exit.PENDING)
        args=command.parse_args(argv)
        result=dispatch(args)
        show_checks(result.checks)
        text={
            'prepared':'Configuration prepared. No servers were changed.',
            'draft':'Draft saved. Remaining prerequisites must be completed before deployment.',
            'checks-passed':'Requested checks completed.',
            'installed':'Installation completed. Enrollment, applications and recovery are not verified.',
            'enrolled':'Network node enrolled in the intended network.',
            'awaiting_enrollment':'Awaiting enrollment or administrator approval. No completed enrollment is claimed.',
            'client_not_running':'Client is unavailable. Inspect it through local administration.',
            'blocked':'Blocked by a prerequisite or unverified state; review the checks above.',
            'cancelled':'Cancelled. Persistent node identity was preserved.',
            'failed':'Operation failed; review the checks above.',
        }
        print(text[result.state])
        return int(result.exit_code)
    except OperationError as error:
        print('ERROR: '+message(error.code))
        return int(error.exit_code)
    except (KeyboardInterrupt,EOFError):
        print('Cancelled. No identity reset was attempted.'); return int(Exit.PENDING)
    except (OSError,ValueError,subprocess.SubprocessError):
        print('ERROR: '+message('operation.failed')); return int(Exit.FAILED)


if __name__=='__main__': raise SystemExit(main())

#!/usr/bin/env python3
"""Guided self-hosted services. Preparation, installation and verified recovery are separate."""
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
    portable=commands.add_parser('portable',help='Preview/check a portable site or explicitly allocate stopped VM shells')
    portable.add_argument('portable_action',choices=('preview','check','allocate-shells','media-fetch','media-upload','upload-abandon','guest-attach','guest-start','guest-finish','guest-boot','guest-status','guest-confirm-login'))
    portable.add_argument('plan',type=Path)
    portable.add_argument('--json',action='store_true')
    portable.add_argument('--token-file',type=Path)
    portable.add_argument('--ca-file',type=Path)
    portable.add_argument('--media-dir',type=Path)
    portable.add_argument('--state-dir',type=Path)
    portable.add_argument('--kind',choices=('ubuntu','opnsense'))
    portable.add_argument('--iso-storage',default='local')
    portable.add_argument('--role',choices=('edge','dns','nginx','chat','files','partner'))
    portable.add_argument('--operator')
    commands.add_parser('status',help='Read separate local operational evidence').add_argument('--json',action='store_true')
    upgrade=commands.add_parser('upgrade',help='Check, apply or recover a reviewed local application upgrade')
    upgrade.add_argument('upgrade_action',choices=('check','apply','recover'))
    start=commands.add_parser('start',help='Plan personal, institutional or regional services; changes no servers')
    start.add_argument('--platform',choices=('ubuntu','proxmox'),default='ubuntu')
    start.add_argument('--resume',type=Path)
    start.add_argument('--output-dir',type=Path,default=ROOT/'inventories/lab/journey')
    commands.add_parser('guide',help='Open checked tasks for a saved product journey').add_argument('journey',type=Path)
    setup=commands.add_parser('setup',help='Prepare private configuration; changes no servers')
    setup.add_argument('--resume',type=Path)
    setup.add_argument('--output-dir',type=Path,default=ROOT/'inventories/lab/setup')
    infrastructure=commands.add_parser('infrastructure',help='Check or deploy the remote controller and relay')
    infra_actions=infrastructure.add_subparsers(dest='action',required=True)
    for action in ('check','apply'):
        command=infra_actions.add_parser(action)
        command.add_argument('inventory',type=Path)
        if action=='apply': command.add_argument('--ask-become-pass',action='store_true')
    access=commands.add_parser('access',help='Prepare explicit application access without editing network policy by hand')
    accesses=access.add_subparsers(dest='access_action',required=True)
    for mode in ('setup','prepare'):
        command=accesses.add_parser(mode);command.add_argument('inventory',type=Path);command.add_argument('--output-file',type=Path,required=True)
        if mode=='prepare':
            command.add_argument('--source',required=True);command.add_argument('--destination',required=True)
            command.add_argument('--service',choices=('https','backup'),required=True);command.add_argument('--remove',action='store_true')
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
    bootstrap=backup_commands.add_parser('bootstrap-stage',help='Prepare original VPN identity from a full application snapshot on a fresh replacement')
    bootstrap.add_argument('snapshot');bootstrap.add_argument('--package',choices=('matrix','nextcloud','gateway'),required=True)
    for action in ('bootstrap-plan','bootstrap-apply'):backup_commands.add_parser(action).add_argument('snapshot')
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
    files=commands.add_parser('files',help='Prepare and operate the experimental Nextcloud package')
    file_actions=files.add_subparsers(dest='action',required=True)
    file_actions.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    for action in ('check','apply'):file_actions.add_parser(action).add_argument('profile',type=Path)
    for action in ('status','account'):file_actions.add_parser(action)
    file_regional=file_actions.add_parser('regional',help='Experimental attachment to a reviewed dedicated file gateway')
    file_regional_actions=file_regional.add_subparsers(dest='regional_service_action',required=True)
    file_regional_actions.add_parser('attach').add_argument('document',type=Path)
    for action in ('status','disable'):file_regional_actions.add_parser(action)
    file_certificate=file_actions.add_parser('certificate')
    file_certificate.add_argument('--certificate',type=Path,required=True);file_certificate.add_argument('--private-key',type=Path,required=True)
    file_issuer=file_actions.add_parser('issuer',help='Optional DNS-based file-service certificate lifecycle')
    file_issuers=file_issuer.add_subparsers(dest='issuer_action',required=True)
    file_issuer.set_defaults(certificate_package='nextcloud')
    file_issuers.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    file_issue=file_issuers.add_parser('issue');file_issue.add_argument('profile',type=Path);file_issue.add_argument('--token-file',type=Path)
    for action in ('enable','status'):file_issuers.add_parser(action)
    gateway=commands.add_parser('gateway',help='Experimental dedicated regional transport for approved chat and file services')
    gateway_actions=gateway.add_subparsers(dest='gateway_action',required=True)
    gateway_recovery=gateway_actions.add_parser('recovery',help='Recover private certificate issuer material without enabling partner access')
    gateway_recovery_actions=gateway_recovery.add_subparsers(dest='gateway_recovery_action',required=True)
    gateway_recovery_export=gateway_recovery_actions.add_parser('export-token')
    gateway_recovery_export.add_argument('--output-file',type=Path,required=True)
    gateway_issuer=gateway_actions.add_parser('issuer',help='Fixed DNS certificate issuance and renewal for the pinned gateway')
    gateway_issuer.set_defaults(certificate_package='gateway')
    gateway_issuers=gateway_issuer.add_subparsers(dest='issuer_action',required=True)
    gateway_issuer_setup=gateway_issuers.add_parser('setup')
    gateway_issuer_setup.add_argument('--identity',type=Path,required=True);gateway_issuer_setup.add_argument('--output-file',type=Path,required=True)
    gateway_issuer_issue=gateway_issuers.add_parser('issue');gateway_issuer_issue.add_argument('profile',type=Path);gateway_issuer_issue.add_argument('--token-file',type=Path)
    for action in ('enable','status'):gateway_issuers.add_parser(action)
    gateway_tls=gateway_actions.add_parser('certificate',help='Verify or replace this gateway certificate')
    gateway_tls_actions=gateway_tls.add_subparsers(dest='certificate_action',required=True)
    gateway_tls_actions.add_parser('status')
    gateway_tls_replace=gateway_tls_actions.add_parser('replace')
    gateway_tls_replace.add_argument('--certificate',type=Path,required=True)
    gateway_tls_replace.add_argument('--private-key',type=Path,required=True)
    guided_gateway=gateway_actions.add_parser('setup');guided_gateway.add_argument('--identity',type=Path,required=True);guided_gateway.add_argument('--output-file',type=Path,required=True)
    for mode in ('check','apply'):gateway_actions.add_parser(mode).add_argument('profile',type=Path)
    for mode in ('status','resume'):gateway_actions.add_parser(mode)
    gateway_actions.add_parser('policy').add_argument('--agreement',type=Path,action='append',default=[])
    gateway_actions.add_parser('revoke').add_argument('agreement_id')
    gateway_link=gateway_actions.add_parser('service-link')
    gateway_link.add_argument('--output-file',type=Path,required=True)
    gateway_link.add_argument('--package',choices=('matrix','nextcloud'),default='matrix')
    regional=commands.add_parser('regional',help='Prepare independent institutional approvals; transport remains separate')
    regional_actions=regional.add_subparsers(dest='regional_action',required=True)
    regional_actions.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    regional_actions.add_parser('inspect').add_argument('document',type=Path)
    for action in ('init','export-identity','approve','offer','accept','import-agreement','export-agreement','revoke','status'):
        operation=regional_actions.add_parser(action)
        operation.add_argument('--workspace',type=Path,required=True)
        if action=='init':operation.add_argument('profile',type=Path)
        if action in ('approve','accept','import-agreement'):operation.add_argument('document',type=Path)
        if action in ('export-identity','offer','accept','export-agreement'):operation.add_argument('--output-file',type=Path,required=True)
        if action in ('revoke','export-agreement'):operation.add_argument('agreement_id')
        if action=='offer':
            operation.add_argument('--peer-fingerprint',required=True)
            operation.add_argument('--services',nargs='+',choices=('matrix','nextcloud'),required=True)
            operation.add_argument('--days',type=int,default=30)
    services=commands.add_parser('services',help='Prepare and operate the experimental local Matrix package')
    service_commands=services.add_subparsers(dest='action',required=True)
    service_commands.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    for action in ('check','apply'): service_commands.add_parser(action).add_argument('profile',type=Path)
    service_commands.add_parser('status')
    regional_service=service_commands.add_parser('regional',help='Review and attach a dedicated Matrix partner gateway')
    regional_service_actions=regional_service.add_subparsers(dest='regional_service_action',required=True)
    regional_service_actions.add_parser('attach').add_argument('document',type=Path)
    for mode in ('status','disable'):regional_service_actions.add_parser(mode)
    service_commands.add_parser('account').add_argument('--admin',action='store_true')
    certificate=service_commands.add_parser('certificate',help='Validate and activate replacement TLS for both service names')
    certificate.add_argument('--certificate',type=Path,required=True)
    certificate.add_argument('--private-key',type=Path,required=True)
    issuer=service_commands.add_parser('issuer',help='Optional DNS-based service certificates without public inbound HTTP')
    issuers=issuer.add_subparsers(dest='issuer_action',required=True)
    issuers.add_parser('setup').add_argument('--output-file',type=Path,required=True)
    issue=issuers.add_parser('issue');issue.add_argument('profile',type=Path);issue.add_argument('--token-file',type=Path)
    for action in ('enable','status'):issuers.add_parser(action)
    release=commands.add_parser('release',help='Download and verify an experimental release; never install')
    fetch=release.add_subparsers(dest='action',required=True).add_parser('fetch')
    fetch.add_argument('version')
    fetch.add_argument('--commit',required=True)
    fetch.add_argument('--output-dir',type=Path,required=True)
    commands.add_parser('version',help='Show source identity and pinned component versions')
    return result


def menu():
    print('Self-hosted services — choose an action. New here? Start with 10.\n'
          '  1 Prepare configuration (no server changes)\n'
          '  2 Check remote controller/relay\n'
          '  3 Apply remote controller/relay\n'
          '  4 Check this local node\n'
          '  5 Install this local node\n'
          '  6 Enroll this local node\n'
          '  7 Show this local node status\n'
          '  8 Diagnose this node/controller\n'
          '  9 Show project version\n'
          ' 10 Plan personal, institutional or regional services\n'
          ' 11 Continue a saved service journey\n'
          ' 12 Show separate local operational evidence\n'
          '  0 Quit')
    choice=input('Choice: ').strip()
    if choice=='0': return None
    if choice=='1': return ['setup']
    if choice=='9': return ['version']
    if choice=='12':return ['status']
    if choice=='10':return ['start']
    if choice=='11':return ['guide',input('Absolute saved journey.json path: ').strip()]
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
    if args.command=='portable':
        from portable_operations import action
        from portable_plan import render
        try:outcome=action(args)
        except ValueError as error:
            print('Portable operation needs attention: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2) if args.json or args.portable_action!='preview' else render(outcome))
        return result_for_state('checks-passed')
    if args.command=='upgrade':
        from upgrade_runtime import action
        try:outcome=action(args,input_fn=input)
        except ValueError as error:
            print('Upgrade needs attention: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        state='cancelled' if outcome['state']=='cancelled' else ('blocked' if outcome['state']=='upgrade-pending' else 'checks-passed')
        return result_for_state(state)
    if args.command=='status':
        from product_status import collect,render,needs_attention
        evidence=collect()
        print(json.dumps(evidence,indent=2) if args.json else render(evidence))
        return result_for_state('blocked' if needs_attention(evidence) else 'checks-passed')
    if args.command=='start':
        if getattr(args,'platform','ubuntu')=='proxmox':
            from portable_wizard import wizard
            if args.resume and args.resume.name!='site.json':raise ValueError('Resume using the saved portable site.json file.')
            folder=args.resume.parent if args.resume else args.output_dir
            if not args.resume and folder==ROOT/'inventories/lab/journey':folder=ROOT/'inventories/lab/portable'
            outcome=wizard(folder)
            print(json.dumps(outcome,indent=2))
            return result_for_state('cancelled' if outcome['state']=='cancelled' else 'checks-passed')
        from product_journey import wizard
        outcome=wizard(args.output_dir,resume=args.resume,input_fn=input)
        print(json.dumps(outcome,indent=2));return result_for_state(outcome['state'])
    if args.command=='guide':
        from product_guide import choose
        argv=choose(args.journey,input_fn=input)
        return dispatch(parser().parse_args(argv)) if argv is not None else result_for_state('cancelled')
    if args.command=='access':
        from service_access import action
        try:outcome=action(args)
        except ValueError as error:
            print('Access preparation blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2));return result_for_state(outcome['state'])
    if args.command=='setup':
        state=run_wizard(args.output_dir,resume=args.resume,input_fn=input)
        return result_for_state(state)
    if args.command=='gateway':
        from gateway_operations import action
        try:outcome=action(args)
        except ValueError as error:
            print('Gateway action blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        if outcome.get('state') in ('gateway-change-pending','gateway-enforcement-unverified','gateway-recovery-review-required') or outcome.get('network_identity_verified') is False or outcome.get('proxy_running') is False:return result_for_state('blocked')
        return result_for_state({'prepared':'prepared','cancelled':'cancelled'}.get(outcome.get('state'),'checks-passed'))
    if args.command=='regional':
        from regional_operations import action
        try:outcome=action(args)
        except ValueError as error:
            print('Regional approval blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        return result_for_state({'prepared':'prepared','cancelled':'cancelled'}.get(outcome.get('state'),'checks-passed'))
    if args.command=='files':
        from nextcloud_operations import action
        try:outcome=action(args)
        except ValueError as error:
            print('File-service action blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        if any(outcome.get(key)=='configuration-changed' for key in ('federation','public_links')):return result_for_state('blocked')
        if outcome.get('expires_within_14_days') or outcome.get('serving_verified') is False or outcome.get('state') in ('issuance-failed','renewal-failed'):return result_for_state('blocked')
        return result_for_state({'prepared':'prepared','cancelled':'cancelled'}.get(outcome.get('state'),'checks-passed'))
    if args.command=='services':
        try: outcome=service_action(args)
        except ValueError as error:
            print('Application action blocked: '+str(error));return result_for_state('blocked')
        print(json.dumps(outcome,indent=2))
        if outcome.get('expires_within_14_days') or outcome.get('serving_verified') is False or outcome.get('state') in ('issuance-failed','renewal-failed'):
            return result_for_state('blocked')
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
        if args.command in ('status','portable') and args.json:return int(result.exit_code)
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

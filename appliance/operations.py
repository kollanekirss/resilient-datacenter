"""CLI integration. Public inspection is separate from privileged operations."""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import platform
import tempfile
import time

from .contracts import ApplianceError, fields, identity, load_json, require
from .plan import validate_site
from .runner import Runner
from . import state

PRIVATE = Path('/var/lib/rdc-appliance/private')


def add_commands(commands, default_release):
    from .role_operations import add_commands as add_roles
    add_roles(commands)
    commands.add_parser('menu', help='Open the local operations menu')
    for name in ('diagnose', 'resume', 'start-local', 'start-roles', 'host-policy', 'rollback', 'first-boot'):
        commands.add_parser(name)
    attach = commands.add_parser('attachment', help='Show public virtual-network attachment metadata')
    attach.add_argument('plan', type=Path); attach.add_argument('--release', type=Path, default=default_release)
    image = commands.add_parser('iso', help='Assemble an unqualified development USB image on Linux')
    sub = image.add_subparsers(dest='action', required=True)
    build = sub.add_parser('build'); build.add_argument('--bundle', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--qualification-build', action='store_true')
    build.add_argument('--release', type=Path, default=default_release)
    network = commands.add_parser('network'); sub = network.add_subparsers(dest='action', required=True)
    render = sub.add_parser('render'); render.add_argument('plan', type=Path)
    render.add_argument('--ports', type=Path, required=True); render.add_argument('--output', type=Path, required=True)
    render.add_argument('--release', type=Path, default=default_release)
    sub.add_parser('apply')
    confirm = sub.add_parser('confirm'); confirm.add_argument('transaction_id')
    sub.add_parser('recover')
    router = commands.add_parser('router'); sub = router.add_subparsers(dest='action', required=True)
    render = sub.add_parser('render'); render.add_argument('plan', type=Path)
    render.add_argument('--credentials', type=Path, required=True); render.add_argument('--output', type=Path, required=True)
    render.add_argument('--release', type=Path, default=default_release)
    bootstrap = sub.add_parser('bootstrap-files', help='Prepare private console-transfer files for the router')
    bootstrap.add_argument('plan', type=Path); bootstrap.add_argument('--credentials', type=Path, required=True)
    bootstrap.add_argument('--output', type=Path, required=True); bootstrap.add_argument('--release', type=Path, default=default_release)
    for action in ('allocate', 'install', 'disk-boot', 'verify', 'enable-wan', 'reconcile'):
        sub.add_parser(action)
    sub.add_parser('reconcile-policy', help='Inspect and acknowledge an already completed router policy change')
    link = sub.add_parser('reconcile-link', help='Inspect and acknowledge an already completed link change')
    link.add_argument('zone', choices=('management','wan','infrastructure','workload','relay'))
    sub.add_parser('enable-management', help='Confirm checks through the disconnected VM console')
    policy = sub.add_parser('policy'); policy.add_argument('stage', choices=('bootstrap', 'transit'))
    probe = commands.add_parser('probe', help='Prepare the neutral workload test guest')
    sub = probe.add_subparsers(dest='action', required=True)
    seed = sub.add_parser('seed'); seed.add_argument('plan', type=Path)
    seed.add_argument('--credentials', type=Path, required=True); seed.add_argument('--output', type=Path, required=True)
    seed.add_argument('--release', type=Path, default=default_release)
    prepare = sub.add_parser('prepare'); prepare.add_argument('--seed', type=Path, required=True)
    for action in ('start','reconcile','attach-workload'): sub.add_parser(action)
    export = commands.add_parser('export'); sub = export.add_subparsers(dest='action', required=True)
    create = sub.add_parser('create'); create.add_argument('--output', type=Path, required=True)
    create.add_argument('--password-file', type=Path, required=True)
    inspect = sub.add_parser('inspect'); inspect.add_argument('source', type=Path)
    inspect.add_argument('--output', type=Path, required=True); inspect.add_argument('--password-file', type=Path, required=True)
    inspect.add_argument('--restic-binary', type=Path, default=PRIVATE.parent / 'media/restic')
    inspect.add_argument('--release', type=Path, default=default_release)
    repair = commands.add_parser('repair'); sub = repair.add_subparsers(dest='action', required=True)
    sub.add_parser('inspect'); sub.add_parser('local-management')
    restore = sub.add_parser('restore-management'); restore.add_argument('--opened-export', type=Path, required=True)
    restore.add_argument('--target-id', required=True)
    clone = sub.add_parser('router-clone', help='Import and check an isolated router copy, then leave it stopped')
    clone.add_argument('--opened-export', type=Path, required=True)
    clone.add_argument('--vmid', dest='clone_vmid', type=int, required=True)
    clone.add_argument('--work', type=Path, required=True, help='Private workspace for the recovery image and evidence')
    reconcile = sub.add_parser('reconcile-router', help='Inspect an interrupted isolated router recovery without replaying it')
    reconcile.add_argument('--vmid', dest='clone_vmid', type=int, required=True)


def _installed():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'installed-host-required')
    require(os.geteuid() == 0, 'root-required')
    staged = state.read(PRIVATE / 'staged.json')
    require(staged.get('complete') is True, 'staging-incomplete')
    plan = state.read(PRIVATE / 'site.json')
    release = load_json(PRIVATE.parent / 'release.lock.json')
    validate_site(plan, release)
    require(staged.get('target') == plan['target'], 'installed-host-identity')
    return plan, release, staged


def _new_file(path, raw):
    path = Path(path).absolute()
    require(path.resolve() == path and not path.exists() and path.parent.is_dir(), 'output-exists-or-unsafe')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def installed_status(plan, staged, runner, *, private=PRIVATE):
    """Fresh read-only observations with no private runtime dictionaries exposed."""
    from .host_network import audit_host, collect_host
    from .router import collect_router, router_ready, _upstream
    capabilities = {name:{'state':'unknown', 'next_action':'Run the corresponding live probe.'}
                    for name in ('management','router','upstream','dns','time','https','isolation')}
    try:
        problems = audit_host(plan, collect_host(plan, Path('/'), runner))
        capabilities['management'] = {'state':'blocked' if problems else 'configured',
            'problems':problems, 'packet_tests':'not-performed'}
    except ApplianceError as error:
        capabilities['management'] = {'state':'blocked','code':error.code}
    try:
        fresh = collect_router(plan, runner)
        ready = router_ready(plan, fresh)
        capabilities['router'] = {'state':ready['state'],'packet_tests':'not-performed'}
        if ready['checks_passed']:
            try:
                _upstream(plan, fresh)
                capabilities['upstream'] = {'state':'configured','packet_tests':'not-performed'}
            except ApplianceError as error:
                capabilities['upstream'] = {'state':'blocked','code':error.code}
    except ApplianceError as error:
        capabilities['router'] = {'state':'blocked','code':error.code}
    from .role_operations import role_status
    capabilities.update(role_status(plan, staged, runner, private))
    report = {'schema':1,'state':'inspected','site_id':plan['site_id'], 'build_id':staged['build_id'],
              'plan_id':identity(plan),'management_ip':plan['networks']['management']['host_ip'],
              'capabilities':capabilities,'qualification':'not-run', 'mutations':False}
    pending = Path(private) / 'network/pending.json'
    if pending.exists():
        record = state.read(pending)
        if record.get('phase') == 'pending': report['pending_network_transaction'] = record['transaction_id']
    return report


def status_if_installed():
    if platform.system() != 'Linux' or os.geteuid() != 0 or not (PRIVATE / 'staged.json').is_file():
        return None
    plan, _, staged = _installed()
    return installed_status(plan, staged, Runner())


def install_live(args):
    from .installer.live import install_site
    require(platform.system() == 'Linux' and os.geteuid() == 0, 'live-installer-required')
    password_hash = getpass.getpass('Unique root password hash (not recorded on the USB): ')
    return install_site(load_json(args.plan), args.bundle, args.confirmation, Runner(),
                        password_hash=password_hash, consent_boot_id=args.boot_id)


def execute_operation(args):
    if args.command == 'menu':
        return menu(), 0
    if args.command == 'attachment':
        from .checks import attachment
        return attachment(validate_site(load_json(args.plan), load_json(args.release))), 0
    if args.command == 'iso':
        from .installer.iso import build_iso
        output = build_iso(load_json(args.release), args.bundle, args.output, runner=Runner(),
                           qualification_build=args.qualification_build)
        return {'schema': 1, 'state': 'assembled', 'path': str(output), 'qualification': 'not-run'}, 0
    if args.command == 'network' and args.action == 'render':
        from .host_network import render_host
        plan = validate_site(load_json(args.plan), load_json(args.release))
        rendered = render_host(plan, load_json(args.ports))
        destination = args.output.absolute()
        require(destination.resolve() == destination and not destination.exists(), 'output-exists-or-unsafe')
        destination.mkdir(mode=0o700)
        from .files import atomic_write
        for path, raw in rendered.items(): atomic_write(destination, path, raw)
        return {'state': 'rendered', 'files': sorted(rendered), 'applied': False}, 0
    if args.command == 'router' and args.action in ('render', 'bootstrap-files'):
        from .router_config import render_router
        plan = validate_site(load_json(args.plan), load_json(args.release))
        credentials = state.read(args.credentials)
        if args.action == 'bootstrap-files':
            from .router import bootstrap_files
            files = bootstrap_files(plan, credentials)
            destination = args.output.absolute()
            require(destination.resolve() == destination and not destination.exists(), 'output-exists-or-unsafe')
            destination.mkdir(mode=0o700)
            for name, raw in files.items(): _new_file(destination / name, raw)
        else:
            _new_file(args.output, render_router(plan, credentials))
        return {'state': 'rendered', 'configuration': str(args.output), 'applied': False}, 0
    if args.command == 'probe' and args.action == 'seed':
        from .probe import build_seed
        plan = validate_site(load_json(args.plan), load_json(args.release))
        credentials = state.read(args.credentials)
        fields(credentials, {'password_hash'}, {'ssh_public_key'})
        receipt = build_seed(plan, args.output, Runner(), **credentials)
        return {'state':'prepared','seed':str(args.output),'qualification':receipt['qualification']}, 0
    runner = Runner(max_output_bytes=16 * 1024 * 1024)
    if args.command == 'export' and args.action == 'inspect':
        from .export import inspect_export
        return inspect_export(args.source, args.password_file, args.output, runner,
                              binary=args.restic_binary, release=load_json(args.release)), 0
    if args.command == 'first-boot':
        require(platform.system() == 'Linux' and os.geteuid() == 0, 'installed-host-required')
        from .installer.first_boot import first_boot
        first_boot(Path('/'), runner)
        return {'state': 'configured', 'scope': 'early-management'}, 0
    if args.command == 'repair' and args.action in ('inspect', 'restore-management'):
        from .repair import discover_target, repair_host
        target = discover_target(runner)
        if args.action == 'inspect': return target, 0
        require(args.target_id == target['target']['by_id'], 'repair-not-confirmed')
        target['confirmed'] = True
        return repair_host(target, args.opened_export, runner), 0
    plan, release, staged = _installed()
    if args.command == 'roles':
        from .role_operations import execute
        result = execute(args, plan, release, staged, runner, PRIVATE)
        return result, 2 if result.get('state') in ('blocked', 'unknown') else 0
    now = int(time.monotonic())
    if args.command in ('diagnose', 'resume'):
        return installed_status(plan, staged, runner), 0
    if args.command in ('start-local', 'start-roles'):
        from .startup import start_local, start_roles
        records = (start_local if args.command == 'start-local' else start_roles)(plan, runner)
        return {'state': 'configured', 'capabilities': records}, 0
    if args.command == 'host-policy':
        from .rollback import post_pve
        post_pve(Path('/'), runner)
        return {'state': 'configured', 'scope': 'host-policy'}, 0
    if args.command == 'rollback':
        from .rollback import recover_pending
        recover_pending(Path('/'), runner, now=now)
        return {'state': 'inspected', 'scope': 'pending-network-transaction'}, 0
    if args.command == 'network':
        from .rollback import apply_host, confirm_management, recover_pending
        if args.action == 'apply':
            tx = apply_host(plan, Path('/'), runner, now=now)
            return {'state': 'pending', 'transaction_id': tx,
                    'confirmation_challenge': state.read(PRIVATE / 'network/pending.json')['challenge'],
                    'next_action': 'Keep this challenge private. Confirm from a fresh management SSH session within 120 seconds.'}, 0
        if args.action == 'confirm':
            challenge = getpass.getpass('Management confirmation challenge: ')
            confirm_management(args.transaction_id, challenge, root=Path('/'), runner=runner, now=now)
            return {'state': 'confirmed'}, 0
        recover_pending(Path('/'), runner, now=now)
        return {'state': 'inspected'}, 0
    if args.command == 'router':
        return _router(args, plan, release, runner), 0
    if args.command == 'probe':
        from . import probe
        if args.action == 'prepare':
            observed = probe.prepare_probe(plan, release, PRIVATE.parent / 'media/probe-image', args.seed, runner, PRIVATE)
        elif args.action == 'start': observed = probe.start_probe(plan, runner, PRIVATE)
        elif args.action == 'reconcile': observed = probe.reconcile_probe(plan, runner, PRIVATE)
        else:
            prompts = {'cloud_init_done':'The probe console confirms cloud-init completed successfully',
                       'workload_mac_address':'The sole interface has the planned workload MAC and IPv4 address',
                       'ipv6_disabled':'IPv6 is disabled and no IPv6 addresses are present',
                       'no_optional_roles':'No connector, controller or relay role is installed',
                       'unique_login':'The unique probe console login works'}
            print('Inspect the disconnected probe through its Proxmox console before confirming.')
            checks = {key:input(prompts[key]+' [yes/no]: ').strip().lower()=='yes' for key in probe.CONSOLE_CHECKS}
            expected = 'CONNECT PROBE '+str(plan['vms']['probe']['vmid'])
            require(input('Type '+expected+': ')==expected, 'probe-console-confirmation')
            attestation = probe.attest_console(plan, checks, runner, PRIVATE)
            observed = probe.attach_workload(plan, runner, PRIVATE, attestation=attestation)
        return {'state':'configured','vmid':plan['vms']['probe']['vmid'],
                'running':observed.get('running') is True,'packet_tests':'not-performed'}, 0
    if args.command == 'export':
        from .export import collect_base, collect_roles, seal, inspect_export
        binary = PRIVATE.parent / 'media/restic'
        if args.action == 'inspect':
            return inspect_export(args.source, args.password_file, args.output, runner, binary=binary, release=release), 0
        from .router import export_router
        with tempfile.TemporaryDirectory(prefix='export-router-', dir=PRIVATE) as temporary:
            xml = Path(temporary) / 'router.xml'
            _new_file(xml, export_router(plan, runner))
            files = collect_base(plan, PRIVATE, xml)
            files.update(collect_roles(plan, runner, Path(temporary) / 'roles', private=PRIVATE))
            return seal(files, args.output, args.password_file, runner, binary=binary, release=release), 0
    if args.command == 'repair':
        if args.action in ('router-clone', 'reconcile-router'):
            from .router_recovery import restore_router_isolated, reconcile_router_recovery
            if args.action == 'reconcile-router':
                result = reconcile_router_recovery(args.clone_vmid, runner, PRIVATE)
            else:
                result = restore_router_isolated(plan, args.opened_export, args.clone_vmid, runner, PRIVATE,
                    dvd=PRIVATE.parent / 'media/opnsense-dvd', work=args.work, release=release,
                    build=load_json(PRIVATE.parent / 'build.json'))
            return result, 0 if result.get('state') in ('verified', 'configured', 'inspected') else 2
        from .rollback import restore_known_good
        restore_known_good(Path('/'), runner, now=now)
        return {'state': 'configured', 'scope': 'local-management-recovery'}, 0
    raise ApplianceError('unsupported-command')


def _router(args, plan, release, runner):
    from . import proxmox, router
    spec = proxmox.vm_spec(plan, 'router')
    if args.action == 'allocate':
        observed = proxmox.ensure_vm(spec, runner, PRIVATE)
    elif args.action == 'reconcile':
        observed = proxmox.reconcile_vm(spec['vmid'], runner, PRIVATE)
    elif args.action == 'reconcile-policy':
        return router.reconcile_router_policy(plan, runner, PRIVATE)
    elif args.action == 'reconcile-link':
        return router.reconcile_router_link(plan, args.zone, runner, PRIVATE)
    elif args.action == 'install':
        # The immutable ISO is copied into PVE's ordinary local ISO storage.
        from .installer.media import _copy_verified
        from .media import verify_file
        item = next(i for i in release['components'] if i['id'] == 'opnsense-dvd')
        source = PRIVATE.parent / 'media/opnsense-dvd'
        destination = Path('/var/lib/vz/template/iso') / ('rdc-' + item['expanded']['sha256'] + '.iso')
        verify_file(source, item['expanded'])
        require(destination.parent.is_dir() and destination.parent.resolve() == destination.parent, 'router-iso-storage')
        if not destination.exists(): _copy_verified(source, destination, item['expanded'])
        verify_file(destination, item['expanded'])
        proxmox.ensure_vm(spec, runner, PRIVATE)
        proxmox.attach_installer(spec, 'local:iso/' + destination.name, runner, PRIVATE)
        observed = proxmox.start_installer(spec['vmid'], runner, PRIVATE)
    elif args.action == 'disk-boot':
        observed = proxmox.disk_boot(spec['vmid'], runner, PRIVATE)
    elif args.action == 'enable-management':
        checks = {}
        prompts = {
            'installed_disk': 'The router is running its installed internal disk with the DVD detached',
            'mac_mapping': 'Each guest interface matches the recorded MAC and network role',
            'management_dhcp_off': 'DHCP serving is disabled on management and WAN',
            'management_ra_off': 'Router advertisements are disabled on management and WAN',
            'ipv6_off': 'IPv6 is disabled for this profile',
            'unique_credentials': 'Unique local passwords and management keys are installed',
            'management_only_admin': 'Administration listens only on the management address',
            'restricted_helper': 'The documented restricted management helper is installed',
            'host_key_compared': 'The SSH host key was compared through the console and pinned locally',
        }
        print('Inspect each item in the disconnected Proxmox VM console. This is an operator attestation, not an automated guest test.')
        for key, prompt in prompts.items(): checks[key] = input(prompt + ' [yes/no]: ').strip().lower() == 'yes'
        confirmation = input('Type CONNECT MANAGEMENT ' + str(spec['vmid']) + ': ')
        attestation = router.attest_console(plan, checks, confirmation, runner)
        router.enable_router_management(plan, attestation, runner, PRIVATE)
        return {'state': 'configured', 'next_action': 'Verify through the pinned management channel.'}
    elif args.action == 'policy':
        return router.apply_router_policy(plan, args.stage, runner, PRIVATE)
    else:
        runtime = router.collect_router(plan, runner)
        if args.action == 'enable-wan':
            router.enable_wan(plan, runtime, runner, PRIVATE)
            return {'state': 'configured', 'next_action': 'Verify upstream overlap, DNS, time and controlled routing.'}
        return router.router_ready(plan, runtime)
    return {'state': 'configured', 'vmid': spec['vmid'], 'running': observed.get('running') is True,
            'installed_guest_verified': False}


def menu():
    from .cli import main
    choices = {'1': ['status'], '2': ['diagnose'], '3': ['router', 'install'],
               '4': ['router', 'verify'], '5': ['router', 'enable-wan'], '6': ['repair', 'local-management']}
    while True:
        print('\nTwo-port appliance\n1 Status\n2 Check local setup\n3 Start disconnected router installation\n'
              '4 Check router\n5 Enable upstream after checks\n6 Restore local management\nq Exit')
        try: selected = input('Choose an action: ').strip().lower()
        except EOFError: selected = 'q'
        if selected == 'q': return {'state': 'exited'}
        if selected in choices: main(choices[selected])
        else: print('Choose one of the listed actions.')

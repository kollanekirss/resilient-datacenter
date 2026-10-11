"""Actual process interruption at durable production operation boundaries.

The worker forks *before* invoking production code. At the chosen boundary the
child fsyncs a small observation and exits without stack unwinding, so finally
blocks cannot accidentally turn a simulated exception into successful cleanup.
These entry points are for the DMI-bound disposable lab guest only.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time

from . import state
from .contracts import ApplianceError, identity, require

STAGES = ('install-staging', 'network-before-reload', 'network-after-reload',
          'vm-create-response', 'vm-start-response', 'router-policy-response',
          'router-link-response', 'repair-files')


class BoundaryRunner:
    def __init__(self, runner, stage, cut):
        self.runner, self.stage, self.cut = runner, stage, cut
    def __getattr__(self, key): return getattr(self.runner, key)
    def run(self, argv, **kwargs):
        match = False
        if self.stage.startswith('network-'):
            match = argv == ['/usr/sbin/ifreload', '-a']
        elif self.stage in ('vm-create-response', 'vm-start-response'):
            match = argv[:2] == ['/usr/sbin/qm', 'create' if self.stage == 'vm-create-response' else 'start']
        elif self.stage == 'router-link-response':
            match = argv[:2] == ['/usr/sbin/qm', 'set'] and any(key.startswith('--net') for key in argv[3:])
        elif self.stage == 'router-policy-response' and argv[0] == '/usr/bin/ssh':
            try: match = json.loads(kwargs.get('stdin', b'{}')).get('action') == 'apply-policy'
            except (ValueError, TypeError): pass
        if match and self.stage == 'network-before-reload': self.cut(self.stage, 0)
        result = self.runner.run(argv, **kwargs)
        if match: self.cut(self.stage, 1)
        return result


def run_interrupted(directory, stage, operation, *, timeout_s=7200):
    """Run a bounded child; tests can exercise this using only temporary files."""
    require(stage in STAGES and threading.active_count() == 1, 'lab-fault-stage')
    require(type(timeout_s) is int and 1 <= timeout_s <= 7200, 'lab-fault-timeout')
    directory = Path(directory)
    with state._directory_fd(directory.parent): pass
    require(not directory.exists(), 'lab-fault-already-observed')
    directory.mkdir(mode=0o700)
    record = {'schema': 1, 'stage': stage, 'operation_id': identity({'stage': stage, 'nonce': os.urandom(32).hex()}),
              'mutation_counts': {stage: 0}, 'boundary': None, 'child_exit': None}
    state.write(directory / 'result.json', record)
    pid = os.fork()
    if pid == 0:
        os.setsid()
        def cut(boundary, count):
            record.update(boundary=boundary, mutation_counts={stage: count})
            state.write(directory / 'result.json', record)
            os._exit(86)
        try:
            operation(cut)
            record['error'] = 'lab-fault-boundary-not-reached'
        except BaseException as error:
            record['error'] = error.code if isinstance(error, ApplianceError) else 'lab-fault-operation-failed'
        state.write(directory / 'result.json', record)
        os._exit(87)
    deadline = time.monotonic() + timeout_s
    status = None
    try:
        while True:
            done, observed = os.waitpid(pid, os.WNOHANG)
            if done: status = observed; break
            require(time.monotonic() < deadline, 'lab-fault-timeout')
            time.sleep(.02)
    finally:
        if status is None:
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            os.waitpid(pid, 0)
    record = state.read(directory / 'result.json')
    record['child_exit'] = os.waitstatus_to_exitcode(status)
    state.write(directory / 'result.json', record)
    require(record['child_exit'] == 86 and record['boundary'] == stage,
            record.get('error', 'lab-fault-child-failed'))
    return record


def _guard():
    from .lab_guest import verify_guest
    require(os.geteuid() == 0 and os.uname().sysname == 'Linux', 'lab-disposable-guest-required')
    verify_guest(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower())


def _directory(private, stage):
    if stage in ('install-staging', 'repair-files'): return Path('/run/rdc-acceptance/faults') / stage
    return Path(private).parent / 'lab/faults' / stage


class ResumeRunner:
    """Observe prohibited replay attempts, including a failed second command."""
    def __init__(self, runner, receipt): self.runner, self.receipt = runner, receipt
    def __getattr__(self, key): return getattr(self.runner, key)
    def run(self, argv, **kwargs):
        mutating = (argv[:2] in (['/usr/sbin/qm', 'create'], ['/usr/sbin/qm', 'start'], ['/usr/sbin/qm', 'set'])
                    or argv == ['/usr/bin/systemctl', 'restart', 'rdc-network-rollback.timer'])
        if argv[0] == '/usr/bin/ssh':
            try: mutating = json.loads(kwargs.get('stdin', b'{}')).get('action') == 'apply-policy'
            except (ValueError, TypeError): pass
        if mutating:
            record = state.read(self.receipt)
            counts = record['mutation_counts']
            counts['resume_mutations'] = counts.get('resume_mutations', 0) + 1
            state.write(self.receipt, record)
        return self.runner.run(argv, **kwargs)


def _auxiliary(plan, stage):
    from .proxmox import vm_spec
    altered = copy.deepcopy(plan)
    vm = altered['vms']['router']; vm['vmid'] += 20000 if stage == 'vm-create-response' else 20001
    vm['name'] = 'rdc-interrupt-' + str(vm['vmid'])
    require(vm['vmid'] not in {item['vmid'] for item in plan['vms'].values()}, 'lab-fault-vmid')
    return vm_spec(altered, 'router')


def interrupt_operation(plan, release, private, stage, runner):
    _guard(); require(stage in STAGES, 'lab-fault-stage')
    private = Path(private); directory = _directory(private, stage)
    with state._directory_fd(directory.parent, create=True): pass
    def operation(cut):
        from . import rollback, proxmox, router
        wrapped = BoundaryRunner(runner, stage, cut)
        if stage == 'install-staging':
            from . import lab_guest
            from .installer.adapters import pve
            original_write = pve.write
            def publish(path, value):
                if Path(path).name == 'staged.json' and value.get('complete') is True:
                    cut(stage, 0)
                return original_write(path, value)
            pve.write = publish
            lab_guest.Runner = lambda **kwargs: wrapped
            result = lab_guest.install({})
            require(result.get('returncode') == 0, result.get('code', 'lab-fault-install'))
        elif stage.startswith('network-'):
            rollback.apply_host(plan, Path('/'), wrapped, now=int(time.monotonic()))
        elif stage.startswith('vm-'):
            spec = _auxiliary(plan, stage)
            if stage == 'vm-create-response': proxmox.ensure_vm(spec, wrapped, private)
            else:
                from .media import verify_file
                from .installer.media import _copy_verified
                item = next(record for record in release['components'] if record['id'] == 'opnsense-dvd')['expanded']
                source = private.parent / 'media/opnsense-dvd'
                destination = Path('/var/lib/vz/template/iso') / ('rdc-fault-' + item['sha256'] + '.iso')
                verify_file(source, item)
                if not destination.exists(): _copy_verified(source, destination, item)
                verify_file(destination, item)
                proxmox.ensure_vm(spec, runner, private)
                proxmox.attach_installer(spec, 'local:iso/' + destination.name, runner, private)
                proxmox.start_installer(spec['vmid'], wrapped, private)
        elif stage == 'router-policy-response':
            router.apply_router_policy(plan, 'bootstrap', wrapped, private)
        elif stage == 'router-link-response':
            # Use the same private, journalled product link operation to
            # withdraw WAN. Enabling links still requires the normal gates.
            router._link(plan, 'wan', False, wrapped, private, {'reason': 'disposable-interruption-withdrawal'})
        elif stage == 'repair-files':
            from . import files
            from .repair import discover_target, repair_host
            require(not (private / 'staged.json').exists(), 'lab-usb-repair-required')
            runner.run(['/usr/sbin/vgchange', '-ay', 'pve'])
            Path('/target').mkdir(exist_ok=True)
            runner.run(['/usr/bin/mount', '-t', 'ext4', '/dev/pve/root', '/target'])
            opened = Path('/target/var/lib/rdc-appliance/lab/opened')
            target = discover_target(runner); target['confirmed'] = True
            original = files.atomic_write
            def publish(root, path, raw, **kwargs):
                result = original(root, path, raw, **kwargs)
                if Path(root) == Path('/target') and path == '/etc/network/interfaces': cut(stage, 1)
                return result
            files.atomic_write = publish
            repair_host(target, opened, wrapped)
    return run_interrupted(directory, stage, operation)


def observe_operation(plan, private, stage, runner):
    """Read the interrupted product journal plus current resource observations."""
    _guard(); require(stage in STAGES, 'lab-fault-stage')
    private = Path(private)
    fault = state.read(_directory(private, stage) / 'result.json')
    require(fault['boundary'] == stage and fault['child_exit'] == 86, 'lab-fault-unobserved')
    if stage == 'install-staging':
        journal = state.read(Path('/run/rdc-appliance/install-started.json'))
        resources = {'journal': journal, 'staged_marker': Path('/target/var/lib/rdc-appliance/private/staged.json').exists()}
        phase = 'pending' if journal.get('phase') == 'pending' and not resources['staged_marker'] else 'unexpected'
    elif stage == 'repair-files':
        from .repair import _observe_target
        from .files import read_optional
        root = Path('/target')
        journal = state.read(root / 'var/lib/rdc-appliance/private/network/pending.json')
        resources = {'journal': journal, 'target': _observe_target(root, runner),
                     'files': {name: hashlib.sha256(read_optional(root, name) or b'').hexdigest()
                               for name in journal['desired']}}
        phase = 'recovered' if journal.get('phase') == 'rolled-back' else journal.get('phase')
    elif stage.startswith('network-'):
        journal = state.read(private / 'network/pending.json')
        from .host_network import collect_host
        resources = {'journal': journal, 'host': collect_host(plan, Path('/'), runner)}
        phase = 'recovered' if journal.get('phase') == 'rolled-back' else journal.get('phase')
    elif stage.startswith('vm-'):
        from . import proxmox
        vmid = _auxiliary(plan, stage)['vmid']
        journal = state.read(private / 'vms' / (str(vmid) + '.json'))
        resources = {'journal': journal, 'vm': proxmox.observe_vm(vmid, runner)}
        phase = 'pending' if journal.get('pending') else 'complete'
    else:
        from . import router, proxmox
        journal = state.read(private / 'router' / ('policy.json' if stage == 'router-policy-response' else 'wan-link.json'))
        resources = {'journal': journal, 'vm': proxmox.observe_vm(plan['vms']['router']['vmid'], runner),
                     'router': router.collect_router(plan, runner)}
        phase = journal.get('status')
    operation_id = identity({'fault': fault['operation_id'], 'transaction': journal.get('transaction_id')})
    return {'operation_id': operation_id, 'mutation_counts': fault['mutation_counts'],
            'phase': phase, 'observed_resource_sha256': identity(resources), 'child_exit': fault['child_exit'],
            'boundary': stage}


def resume_operation(plan, private, stage, runner):
    _guard(); require(stage in STAGES, 'lab-fault-stage')
    private = Path(private)
    before = observe_operation(plan, private, stage, runner)
    runner = ResumeRunner(runner, _directory(private, stage) / 'result.json')
    if stage.startswith('vm-'):
        from .proxmox import reconcile_vm
        reconcile_vm(_auxiliary(plan, stage)['vmid'], runner, private)
        outcome = 'reconciled'
    elif stage == 'router-policy-response':
        from .router import reconcile_router_policy
        reconcile_router_policy(plan, runner, private); outcome = 'reconciled'
    elif stage == 'router-link-response':
        from .router import reconcile_router_link
        reconcile_router_link(plan, 'wan', runner, private); outcome = 'reconciled'
    elif stage.startswith('network-'):
        from .rollback import recover_pending
        record = state.read(private / 'network/pending.json')
        require(record['deadline'] - time.monotonic() <= 125, 'lab-rollback-deadline')
        while time.monotonic() < record['deadline']: time.sleep(.5)
        recover_pending(Path('/'), runner, now=int(time.monotonic())); outcome = 'recovered'
    else:
        # An incomplete installer must never restart; mounted-root repair's
        # boot journal is retained for the documented recovery boot. Inspecting
        # either is the product's explicit response to uncertain local work.
        outcome = 'inspection-required'
    after = observe_operation(plan, private, stage, runner)
    require(before['operation_id'] == after['operation_id'] and before['mutation_counts'] == after['mutation_counts'],
            'lab-interruption-replayed')
    return {'state': outcome, 'next_action': 'Inspect the retained operation; do not repeat installation or resource allocation.',
            'observation': after}

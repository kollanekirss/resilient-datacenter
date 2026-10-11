"""Full acceptance orchestration around freshly isolated namespace workers.

Only newly created private children and regular image copies are writable.
Real execution and a fixture boundary are never interchangeable evidence.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat

from .contracts import ApplianceError, _unique, canonical, identity, load_json, require
from .files import atomic_write, _parent
from .lab import IMAGE_ROLES, SUITES, collect_platform
from .lab_runner import (inspect_execution, _open_regular, _read_pin, _hash_fd,
                         source_identity, _input_digests)


def _nested_available():
    for path in ('/sys/module/kvm_intel/parameters/nested', '/sys/module/kvm_amd/parameters/nested'):
        try:
            if Path(path).read_text().strip().lower() in ('1', 'y'): return True
        except OSError: pass
    return False


def inspect_full_execution(config, platform_record):
    reasons = inspect_execution(config, platform_record)
    profile = config.get('acceptance') if type(config) is dict else None
    if type(profile) is not dict or set(profile) != {'enabled', 'case_timeout_seconds', 'tools'}:
        return list(dict.fromkeys(reasons + ['acceptance-profile-required']))
    if profile.get('enabled') is not True: reasons.append('acceptance-not-authorized')
    timeout = profile.get('case_timeout_seconds')
    if type(timeout) is not int or not 30 <= timeout <= 7200: reasons.append('acceptance-timeout')
    tools = profile.get('tools')
    if type(tools) is not dict or set(tools) != {'openssl', 'ssh', 'ssh-keygen'}:
        reasons.append('acceptance-tools-required')
    else:
        for name, pin in tools.items():
            try:
                require(type(pin) is dict and set(pin) == {'path', 'sha256'}, 'acceptance-tool-pin')
                fd = _open_regular(pin['path'], trusted=True, maximum=256 * 1024 * 1024)
                try:
                    require(os.access(pin['path'], os.X_OK) and _hash_fd(fd) == pin['sha256'], 'acceptance-tool-pin')
                finally: os.close(fd)
            except (OSError, ValueError, KeyError, TypeError): reasons.append('acceptance-tool-invalid:' + name)
    nested = platform_record.get('nested_kvm') if 'nested_kvm' in platform_record else _nested_available()
    if nested is not True: reasons.append('nested-kvm-unavailable')
    try:
        from .plan import validate_site, validate_release
        work = Path(config['workspace'])
        plan = _read_pin(config['plan'], work, json_value=True)
        release = validate_release(load_json(Path(__file__).parent / 'releases/v1.lock.json'), production=True)
        validate_site(plan, release)
        require(plan['upstream']['mode'] == 'dhcp' and len(plan['upstream']['cidrs']) == 1, 'acceptance-dhcp-profile')
        require(not any(role['selected'] for role in plan['roles'].values()), 'acceptance-base-roles-only')
        build = _read_pin(config['build_receipt'], work, json_value=True)
        require(build['release_identity'] == identity(release), 'acceptance-release-mismatch')
    except (OSError, ValueError, TypeError, KeyError) as error:
        reasons.append(error.code if isinstance(error, ApplianceError) else 'acceptance-plan-invalid')
    return list(dict.fromkeys(reasons))


def _case(case, config):
    from .acceptance import required_assertions
    return {'schema': 1, 'case_id': case, 'capability': case, 'build_id': config.get('build_id'),
            'spec_id': config.get('spec_id'), 'state': 'unknown', 'status': 'NOT RUN',
            'assertions': [{'name': name, 'passed': False} for name in required_assertions(case)],
            'evidence': [], 'reasons': ['execution-prerequisites'], 'qualification': 'NOT RUN'}


def _write_report(run, report):
    from .acceptance_report import human_report
    atomic_write(run, '/result.json', canonical(report), mode=0o600)
    atomic_write(run, '/report.txt', human_report(report).encode(), mode=0o600)


def execute_full_lab(config, suite, *, config_sha256, _platform=None, _worker_factory=None,
                     _legacy_process_factory=None):
    from .acceptance import run_case
    from .acceptance_report import case_problems
    require(suite in SUITES, 'lab-suite-invalid')
    platform = collect_platform() if _platform is None else _platform
    synthetic = any(value is not None for value in (_platform, _worker_factory, _legacy_process_factory))
    report = {'schema': 1, 'suite': suite, 'scope': 'disposable-base-acceptance', 'status': 'NOT RUN',
              'qualification': 'NOT RUN', 'checked_at': datetime.now(timezone.utc).isoformat(),
              'platform': platform, 'identities': {'build_id': config.get('build_id'),
              'spec_id': config.get('spec_id'), 'lab_config_sha256': config_sha256},
              'cases': [_case(case, config) for case in SUITES[suite]], 'reasons': []}
    report['reasons'] = inspect_full_execution(config, platform)
    if not isinstance(config_sha256, str) or len(config_sha256) != 64 or any(c not in '0123456789abcdef' for c in config_sha256):
        report['reasons'].append('lab-config-identity-invalid')
    if report['reasons']: return report
    if _worker_factory is None:
        from .lab_driver import NamespaceWorker
        factory = NamespaceWorker
    else: factory = _worker_factory
    work = Path(config['workspace']); run = None
    with ExitStack() as cleanup:
        try:
            inputs = {}
            for role in IMAGE_ROLES:
                fd = _open_regular(config['images'][role]['path']); cleanup.callback(os.close, fd)
                require(_hash_fd(fd) == config['images'][role]['sha256'], 'lab-input-sha256-mismatch')
                inputs[role] = fd
            qemu = _open_regular(platform['qemu_path'], trusted=True, maximum=256 * 1024 * 1024)
            cleanup.callback(os.close, qemu)
            require(_hash_fd(qemu) == config['qemu_sha256'], 'qemu-sha256-mismatch')
            with _parent(Path('/'), str(work / '.rdc-appliance-lab.json')) as (parent, name):
                lock = os.dup(parent); cleanup.callback(os.close, lock)
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise ApplianceError('lab-workspace-busy') from None
                info = os.fstat(parent)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'workspace-private-required')
                marker_fd = _open_regular(work / name, maximum=4096)
                try: marker = json.loads(os.read(marker_fd, 4097), object_pairs_hook=_unique)
                finally: os.close(marker_fd)
                require(marker == {'schema': 1, 'owner_id': config['owner_id']}, 'workspace-owner-mismatch')
                child = 'acceptance-' + secrets.token_hex(16)
                os.mkdir(child, 0o700, dir_fd=parent); os.fsync(parent)
            run = work / child; report['evidence_directory'] = str(run)
            plan = _read_pin(config['plan'], work, json_value=True)
            context = {'plan': plan, 'plan_id': identity(plan), 'build_id': config['build_id'],
                       'spec_id': config['spec_id'], 'source_id': source_identity(),
                       'run_id': identity({'nonce': secrets.token_hex(32), 'build': config['build_id']})}
            report['identities'].update({key: value for key, value in context.items() if key != 'plan'})
            fixed_config = {**config, '_qemu_path': platform['qemu_path']}
            for index, case in enumerate(SUITES[suite]):
                if case == 'physical-operator':
                    report['cases'][index] = run_case(case, None, context)
                    continue
                # Each case gets a new worker, namespace and private disk set.
                space = sum(os.fstat(inputs[role]).st_size for role in ('target', 'canary', 'uefi_vars'))
                require(shutil.disk_usage(work).free >= space + 1024**3, 'lab-workspace-space')
                case_dir = run / case; case_dir.mkdir(mode=0o700)
                worker = None
                try:
                    worker = factory(fixed_config, {**context, 'case_id': case}, case_dir, {**inputs, 'qemu': qemu})
                    result = run_case(case, worker, context)
                    report['cases'][index] = result
                except (OSError, ValueError, TypeError, KeyError) as error:
                    result = report['cases'][index]
                    result['reasons'] = [error.code if isinstance(error, ApplianceError) else 'lab-worker-unavailable']
                    if worker is not None and getattr(worker, 'launched', False) and not synthetic:
                        result.update(state='failed', status='FAIL')
                except KeyboardInterrupt:
                    report['cases'][index].update(state='failed' if not synthetic else 'unknown',
                                                  status='FAIL' if not synthetic else 'NOT RUN', reasons=['operator-interrupted'])
                    report['reasons'].append('operator-interrupted')
                finally:
                    result = report['cases'][index]
                    if worker is not None:
                        try:
                            result['cleanup'] = worker.close()
                        except (OSError, ValueError, TimeoutError):
                            result.update(state='failed', status='FAIL')
                            result['reasons'].append('lab-worker-cleanup-failed')
                    if synthetic:
                        result.update(state='unknown', status='NOT RUN', test_only=True, method='unit-fixture')
                        result['reasons'].append('synthetic-driver-boundary')
                    elif result['state'] == 'verified':
                        problems = case_problems(result, [item['name'] for item in _case(case, config)['assertions']])
                        if problems:
                            result.update(state='failed', status='FAIL')
                            result['reasons'].extend(problems)
                    _write_report(run, report)
                if 'operator-interrupted' in report['reasons']: break
            report['input_digests'] = _input_digests(config, inputs)
            unchanged = all(value['same_file'] and value['initial'] == value['final'] for value in report['input_digests'].values())
            if not unchanged: report['reasons'].append('lab-readonly-input-changed')
            if source_identity() != context['source_id']: report['reasons'].append('lab-source-changed')
            statuses = [item['status'] for item in report['cases']]
            if synthetic: report['status'] = 'NOT RUN'
            elif 'FAIL' in statuses or report['reasons']: report['status'] = 'FAIL'
            elif statuses and all(status == 'PASS' for status in statuses): report['status'] = 'PASS'
            elif 'PASS' in statuses: report['status'] = 'PARTIAL'
            _write_report(run, report)
        except (OSError, ValueError, TypeError, KeyError) as error:
            report['reasons'].append(error.code if isinstance(error, ApplianceError) else 'lab-run-unavailable')
            if any(item['status'] in ('PASS', 'FAIL') for item in report['cases']): report['status'] = 'FAIL'
            if run is not None:
                try: _write_report(run, report)
                except (OSError, ValueError): report['reasons'].append('lab-result-publication-failed')
    return report

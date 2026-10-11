"""Explicitly requested, disposable KVM console observations.

No host network backend, shared directory, block device, download, disk erasure,
or existing writable image is passed to QEMU. Injected process/platform seams are
always reported as synthetic. A case observation is never suite qualification.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import time
import threading

from .contracts import ApplianceError, _unique, canonical, identity, require
from .files import _parent, atomic_write
from .lab import IMAGE_ROLES, SUITES, collect_platform, inspect_lab

CASE = 'boot-menu-cancel'
MAX_IMAGE = 128 * 1024**3
MAX_METADATA = 1024 * 1024
MAX_LOG = 16 * 1024 * 1024
MENU = b'Select (no default): '
GRUB = b'Appliance local setup (serial console)'
CONSOLE = b'USB recovery (local root) # '
ANSI = re.compile(rb'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))')


def _open_regular(path, *, trusted=False, maximum=MAX_IMAGE):
    path = Path(path)
    with _parent(Path('/'),str(path)) as (parent,name):
        fd = os.open(name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid in ((0,os.getuid()) if trusted else (os.getuid(),))
                and not stat.S_IMODE(info.st_mode) & 0o6022,'lab-input-unsafe')
        require(0 < info.st_size <= maximum,'lab-input-size')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _hash_fd(fd):
    before = os.fstat(fd)
    os.lseek(fd,0,os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = before.st_size
    deadline = time.monotonic() + 600
    while remaining:
        require(time.monotonic() < deadline,'lab-input-read-timeout')
        chunk = os.read(fd,min(1024 * 1024,remaining))
        require(chunk,'lab-input-changed')
        digest.update(chunk); remaining -= len(chunk)
    after = os.fstat(fd)
    snapshot = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
    require(snapshot(before) == snapshot(after),'lab-input-changed')
    os.lseek(fd,0,os.SEEK_SET)
    return digest.hexdigest()


def _read_pin(pin, work, *, maximum=MAX_METADATA, json_value=False):
    require(type(pin) is dict and set(pin) == {'path','sha256'},'lab-pin-invalid')
    path = Path(pin['path'])
    require(path.is_absolute() and path.is_relative_to(work) and path != work,'lab-pin-outside-workspace')
    fd = _open_regular(path,maximum=maximum)
    try:
        require(_hash_fd(fd) == pin['sha256'],'lab-pin-sha256-mismatch')
        if json_value:
            raw = os.read(fd,maximum + 1)
            value = json.loads(raw,object_pairs_hook=_unique)
            require(type(value) is dict,'lab-metadata-invalid')
            canonical(value)  # Shared depth and JSON value bounds.
            return value
        return None
    finally:
        os.close(fd)


def source_identity():
    """Identity of the same closed appliance source manifest used by the ISO."""
    from .installer.payload import _allowed
    package = Path(__file__).parent
    records = []
    for path in sorted(package.rglob('*')):
        relative = path.relative_to(package)
        if any(p.startswith('.') or p == '__pycache__' for p in relative.parts):
            continue
        require(not path.is_symlink(),'lab-source-symlink')
        if not path.is_file() or not _allowed(relative.as_posix()):
            continue
        fd = _open_regular(path,trusted=True,maximum=2 * MAX_METADATA)
        try:
            size = os.fstat(fd).st_size
            records.append({'path':'appliance/'+relative.as_posix(),'sha256':_hash_fd(fd),
                            'size_bytes':size,'max_bytes':size})
        finally:
            os.close(fd)
    require(records,'lab-source-missing')
    return identity({'schema':1,'files':records})


def inspect_execution(config, platform_record):
    """Read-only gate for the additional opt-in execution contract."""
    reasons = inspect_lab(config,platform_record)
    if type(config) is not dict:
        return reasons
    if os.getuid() != os.geteuid():
        reasons.append('lab-setuid-execution-forbidden')
    try:
        work = Path(config['workspace'])
        if stat.S_IMODE(work.stat().st_mode) != 0o700:
            reasons.append('workspace-private-required')
        marker = work / '.rdc-appliance-lab.json'
        if stat.S_IMODE(marker.stat().st_mode) != 0o600:
            reasons.append('workspace-marker-private-required')
        # Also traverse ancestors through no-follow descriptors before mutation.
        fd = _open_regular(marker,maximum=4096); os.close(fd)
    except (OSError,ValueError,TypeError,KeyError):
        return list(dict.fromkeys(reasons + ['workspace-execution-unsafe']))
    execution = config.get('execution',{})
    if type(execution) is not dict or set(execution) != {'enabled','timeout_seconds','memory_mib','vcpus'}:
        reasons.append('execution-config-invalid')
    else:
        if execution['enabled'] is not True:
            reasons.append('execution-not-authorized')
        full = type(config.get('acceptance')) is dict and config['acceptance'].get('enabled') is True
        bounds = (('timeout_seconds',30,7200),('memory_mib',16384,65536),('vcpus',4,16)) if full else (
            ('timeout_seconds',30,900),('memory_mib',1024,8192),('vcpus',1,4))
        for key,low,high in bounds:
            if type(execution[key]) is not int or not low <= execution[key] <= high:
                reasons.append('execution-'+key.replace('_','-')+'-invalid')
    values = {}
    for name in ('build_receipt','plan','spec'):
        try:
            values[name] = _read_pin(config.get(name),work,json_value=name != 'spec')
        except (OSError,ValueError,TypeError,KeyError) as error:
            code = error.code if isinstance(error,ApplianceError) else 'invalid'
            reasons.append(name.replace('_','-')+'-'+code.removeprefix('lab-pin-'))
    if 'spec' in values and config.get('spec_id') != config['spec']['sha256']:
        reasons.append('spec-identity-mismatch')
    try:
        qemu = platform_record['qemu_path']
        fd = _open_regular(qemu,trusted=True,maximum=256 * MAX_METADATA)
        try:
            require(os.access(qemu,os.X_OK) and _hash_fd(fd) == config.get('qemu_sha256'),'qemu-sha256-mismatch')
        finally:
            os.close(fd)
    except (OSError,ValueError,TypeError,KeyError):
        reasons.append('qemu-pin-invalid')
    if 'build_receipt' in values:
        try:
            receipt = values['build_receipt']
            build = {k:v for k,v in receipt.items() if k not in ('image','build_id')}
            from .installer.adapters.pve import ADAPTER_ID, SOURCE_REVISION
            require(receipt['build_id'] == config['build_id'] == identity(build),'build-identity-mismatch')
            require(build['schema'] == 1 and build['qualification'] == 'not-run'
                    and build['adapter_id'] == ADAPTER_ID and build['source_revision'] == SOURCE_REVISION
                    and build['qualification_build'] is True and build['runtime_identity'] == source_identity(),
                    'build-source-mismatch')
            image = receipt['image']; installer = config['images']['installer']
            require(image['sha256'] == installer['sha256'] and image['size_bytes'] == image['max_bytes']
                    == Path(installer['path']).stat().st_size,'build-image-mismatch')
        except (OSError,ValueError,TypeError,KeyError) as error:
            reasons.append(error.code if isinstance(error,ApplianceError) else 'build-receipt-invalid')
    return list(dict.fromkeys(reasons))


class QemuConsole:
    """One process group, bounded pipe reads, deterministic teardown."""
    def __init__(self,argv,*,cwd,pass_fds,executable,timeout_seconds):
        # Run this dedicated Linux driver single-threaded. Resolve libc before
        # fork; the child hook only makes async-signal-safe kernel calls. QEMU
        # must die even if the harness is SIGKILLed before its finally block.
        require(threading.active_count() == 1,'lab-driver-must-be-single-threaded')
        try:
            prctl = ctypes.CDLL(None,use_errno=True).prctl
        except AttributeError:
            raise ApplianceError('lab-parent-death-signal-unavailable') from None
        prctl.argtypes = (ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong)
        prctl.restype = ctypes.c_int
        parent_pid = os.getpid()
        def child_setup():
            if prctl(1,signal.SIGKILL,0,0,0) != 0 or os.getppid() != parent_pid:
                os._exit(127)
        self.process = subprocess.Popen(argv,executable=executable,cwd=cwd,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            pass_fds=tuple(pass_fds),close_fds=True,start_new_session=True,shell=False,umask=0o077,
            preexec_fn=child_setup,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','HOME':str(cwd)})
        self.selector = selectors.DefaultSelector()
        for stream,channel in ((self.process.stdout,'serial'),(self.process.stderr,'qemu')):
            os.set_blocking(stream.fileno(),False)
            self.selector.register(stream,selectors.EVENT_READ,channel)
        self.closed = False

    def receive(self,timeout):
        result = []
        for key,_ in self.selector.select(timeout):
            raw = os.read(key.fd,65536)
            if raw:
                result.append((key.data,raw))
            else:
                self.selector.unregister(key.fileobj)
        if not result and self.process.poll() is not None and not self.selector.get_map():
            raise ApplianceError('qemu-exited-before-observation')
        return result

    def send(self,raw):
        require(type(raw) is bytes and len(raw) <= 16,'lab-console-input')
        try:
            self.process.stdin.write(raw); self.process.stdin.flush()
        except (OSError,ValueError):
            raise ApplianceError('lab-console-write-failed') from None

    def close(self):
        if self.closed:
            return {'returncode':self.process.returncode,'termination':'already-closed'}
        termination = 'exited'
        try:
            if self.process.poll() is None:
                termination = 'terminated'
                os.killpg(self.process.pid,signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    termination = 'killed'
                    os.killpg(self.process.pid,signal.SIGKILL)
                    self.process.wait(timeout=5)
            return {'returncode':self.process.returncode,'termination':termination}
        finally:
            self.closed = True
            self.selector.close()
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
                stream.close()


def _new_file(dfd,name):
    return os.open(name,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=dfd)


def _copy(source,destination):
    size = os.fstat(source).st_size
    os.lseek(source,0,os.SEEK_SET)
    remaining = size
    deadline = time.monotonic() + 600
    while remaining:
        require(time.monotonic() < deadline,'lab-copy-timeout')
        raw = os.read(source,min(remaining,1024 * 1024))
        require(raw,'lab-input-changed'); remaining -= len(raw)
        if not raw.strip(b'\0'):
            os.lseek(destination,len(raw),os.SEEK_CUR)
        else:
            view = memoryview(raw)
            while view:
                written = os.write(destination,view)
                require(written > 0,'lab-copy-failed'); view = view[written:]
    os.ftruncate(destination,size)
    os.fsync(destination)
    os.lseek(source,0,os.SEEK_SET); os.lseek(destination,0,os.SEEK_SET)


def qemu_arguments(qemu,handles,execution):
    """Closed argv: all storage is an already-open regular-file descriptor."""
    at = lambda name:'/proc/self/fd/' + str(handles[name])
    return [qemu,'-name','rdc-disposable-appliance-lab','-machine','q35,accel=kvm',
            '-cpu','host','-m',str(execution['memory_mib']),'-smp',str(execution['vcpus']),
            '-nodefaults','-no-user-config','-display','none','-monitor','none','-serial','stdio',
            '-no-reboot','-boot','order=d,menu=off,strict=on',
            '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+at('uefi_code'),
            '-drive','if=pflash,format=raw,unit=1,file='+at('uefi_vars_copy'),
            '-device','virtio-scsi-pci,id=scsi0',
            '-drive','if=none,id=installer,format=raw,media=cdrom,readonly=on,file='+at('installer'),
            '-device','scsi-cd,drive=installer,bootindex=1',
            '-drive','if=none,id=target,format=raw,file='+at('target_copy'),
            '-device','scsi-hd,drive=target,serial=RDC-LAB-TARGET',
            '-drive','if=none,id=canary,format=raw,file='+at('canary_copy'),
            '-device','scsi-hd,drive=canary,serial=RDC-LAB-CANARY',
            '-nic','none',
            '-device','virtio-net-pci,id=management,mac=52:54:00:77:00:01,romfile=',
            '-device','virtio-net-pci,id=wan,mac=52:54:00:77:00:02,romfile=',
            '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-rtc','base=utc']


def _observe(console,logs,assertions,timeout):
    deadline = time.monotonic() + timeout
    serial = bytearray()
    sizes = {'serial':0,'qemu':0}
    def wait(marker,start=0):
        while True:
            clean = ANSI.sub(b'',bytes(serial)).replace(b'\r\n',b'\n')
            index = clean.find(marker,start)
            if index >= 0:
                return index + len(marker)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ApplianceError('console-observation-timeout')
            try:
                chunks = console.receive(min(remaining,1))
            except TimeoutError:
                raise ApplianceError('console-observation-timeout') from None
            for channel,raw in chunks:
                require(channel in logs and type(raw) is bytes,'lab-console-output')
                sizes[channel] += len(raw)
                require(sizes[channel] <= MAX_LOG,'lab-output-limit')
                logs[channel].write(raw); logs[channel].flush()
                if channel == 'serial':
                    serial.extend(raw)
    end = wait(GRUB)
    assertions.append({'name':'closed-grub-menu-observed','passed':True})
    console.send(b'\x1b[B\r')
    end = wait(MENU,end)
    require('Two-port appliance installer — UNQUALIFIED CANDIDATE'.encode() in serial,'installer-menu-unproven')
    assertions.append({'name':'installer-menu-observed','passed':True})
    console.send(b'\r')
    end = wait(b'No action selected.',end)
    end = wait(MENU,end)
    assertions.append({'name':'blank-selection-keeps-menu','passed':True})
    console.send(b'3\r')
    end = wait(CONSOLE,end)
    assertions.append({'name':'explicit-recovery-console-observed','passed':True})
    console.send(b'exit\r')
    wait(MENU,end)
    assertions.append({'name':'console-exit-returns-menu','passed':True})


def _case(case,config):
    return {'case_id':case,'build_id':config.get('build_id'),'spec_id':config.get('spec_id'),
            'state':'unknown','status':'NOT RUN','reasons':['full-acceptance-profile-required'],
            'assertions':[],'evidence':[]}


def classify_outcome(*,synthetic,launched,observed,assertions,reasons):
    """Classify execution facts; this pure helper creates no evidence record."""
    if synthetic or not launched:
        return 'unknown','NOT RUN','NOT RUN'
    if reasons or not observed or any(item['passed'] is not True for item in assertions):
        return 'failed','FAIL','FAIL'
    return 'verified','OBSERVED','PARTIAL'


def _set_outcome(case,result,*,synthetic,launched,observed):
    state,status,overall = classify_outcome(synthetic=synthetic,launched=launched,
        observed=observed,assertions=case['assertions'],reasons=case['reasons'])
    case.update(state=state,status=status)
    result['status'] = overall


def _input_digests(config,inputs):
    result = {}
    for name,old_fd in inputs.items():
        result[name] = {'initial':config['images'][name]['sha256'],'final':None,'same_file':False}
        try:
            fd = _open_regular(config['images'][name]['path'])
            try:
                before,after = os.fstat(old_fd),os.fstat(fd)
                result[name]['same_file'] = (before.st_dev,before.st_ino) == (after.st_dev,after.st_ino)
                result[name]['final'] = _hash_fd(fd)
            finally:
                os.close(fd)
        except (OSError,ValueError):
            pass
    return result


def execute_lab(config,suite,*,config_sha256,_platform=None,_process_factory=None):
    """Run supported observations only; all current suites remain incomplete.

    Underscored injection points are unit-test seams and irrevocably mark the
    result synthetic. The CLI exposes neither seam nor arbitrary QEMU arguments.
    """
    require(suite in SUITES,'lab-suite-invalid')
    config = config if type(config) is dict else {}
    if 'acceptance' in config:
        from .lab_acceptance_runner import execute_full_lab
        return execute_full_lab(config, suite, config_sha256=config_sha256, _platform=_platform,
                                _legacy_process_factory=_process_factory)
    platform_record = collect_platform() if _platform is None else _platform
    synthetic = _platform is not None or _process_factory is not None
    factory = QemuConsole if _process_factory is None else _process_factory
    result = {'schema':1,'status':'NOT RUN','qualification':'NOT RUN','scope':'disposable-boot-observation',
              'suite':suite,'checked_at':datetime.now(timezone.utc).isoformat(),'platform':platform_record,
              'identities':{'build_id':config.get('build_id'),'spec_id':config.get('spec_id'),
                            'lab_config_sha256':config_sha256},
              'cases':[_case(case,config) for case in SUITES[suite]],'reasons':[]}
    result['reasons'] = inspect_execution(config,platform_record)
    if not isinstance(config_sha256,str) or not re.fullmatch('[0-9a-f]{64}',config_sha256):
        result['reasons'].append('lab-config-identity-invalid')
    if result['reasons']:
        return result
    case = next((case for case in result['cases'] if case['case_id'] == CASE),None)
    if case is None:
        result['reasons'] = ['full-acceptance-profile-required']
        return result
    case.update(reasons=[],method='unit-fixture' if synthetic else 'real-execution',environment='nested-kvm')
    work = Path(config['workspace'])
    run = None
    console = None
    observed = False
    with ExitStack() as cleanup:
        try:
            inputs = {}
            for name in IMAGE_ROLES:
                fd = _open_regular(config['images'][name]['path'])
                cleanup.callback(os.close,fd); inputs[name] = fd
                require(_hash_fd(fd) == config['images'][name]['sha256'],'lab-input-sha256-mismatch')
            qemu_fd = _open_regular(platform_record['qemu_path'],trusted=True,maximum=256 * MAX_METADATA)
            cleanup.callback(os.close,qemu_fd)
            require(_hash_fd(qemu_fd) == config['qemu_sha256'],'qemu-sha256-mismatch')
            space = sum(os.fstat(inputs[name]).st_size for name in ('target','canary','uefi_vars'))
            require(shutil.disk_usage(work).free >= space + 128 * MAX_METADATA,'lab-workspace-space')
            with _parent(Path('/'),str(work / '.rdc-appliance-lab.json')) as (work_fd,_):
                lock_fd = os.dup(work_fd); cleanup.callback(os.close,lock_fd)
                try:
                    fcntl.flock(lock_fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ApplianceError('lab-workspace-busy') from None
                info = os.fstat(work_fd)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,'workspace-private-required')
                marker_fd = _open_regular(work / '.rdc-appliance-lab.json',maximum=4096)
                try:
                    marker = json.loads(os.read(marker_fd,4097),object_pairs_hook=_unique)
                    require(marker == {'schema':1,'owner_id':config['owner_id']},'workspace-owner-mismatch')
                finally:
                    os.close(marker_fd)
                name = 'run-' + secrets.token_hex(16)
                os.mkdir(name,0o700,dir_fd=work_fd); os.fsync(work_fd)
                run_fd = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=work_fd)
            cleanup.callback(os.close,run_fd)
            run = work / name
            result['evidence_directory'] = str(run)
            plan = _read_pin(config['plan'],work,json_value=True)
            result['identities'].update(plan_id=identity(plan),plan_sha256=config['plan']['sha256'],
                                         source_id=source_identity(),build_receipt_sha256=config['build_receipt']['sha256'],
                                         qemu_sha256=config['qemu_sha256'])
            handles = dict(inputs)
            hashes = {}
            for role in ('target','canary','uefi_vars'):
                fd = _new_file(run_fd,role+'.raw'); cleanup.callback(os.close,fd)
                _copy(inputs[role],fd)
                digest = _hash_fd(fd)
                require(digest == config['images'][role]['sha256'],'lab-copy-sha256-mismatch')
                handles[role+'_copy'] = fd
                hashes[role] = {'initial':digest}
            os.fsync(run_fd)
            args = qemu_arguments(platform_record['qemu_path'],handles,config['execution'])
            atomic_write(run,'/launch.json',canonical({'schema':1,'identities':result['identities'],
                         'argv':args,'network':'none; disconnected virtual NICs','copies':hashes,
                         'inputs':config['images']}),mode=0o600)
            logs = {}
            for channel,filename in (('serial','serial.log'),('qemu','qemu.log')):
                fd = _new_file(run_fd,filename)
                stream = os.fdopen(fd,'wb'); cleanup.callback(stream.close); logs[channel] = stream
            try:
                pass_fds = [handles[name] for name in ('uefi_code','installer','uefi_vars_copy','target_copy','canary_copy')] + [qemu_fd]
                console = factory(args,cwd=run,pass_fds=pass_fds,executable='/proc/self/fd/'+str(qemu_fd),
                                  timeout_seconds=config['execution']['timeout_seconds'])
                _observe(console,logs,case['assertions'],config['execution']['timeout_seconds'])
                observed = True
            except KeyboardInterrupt:
                case['reasons'].append('operator-interrupted')
            except (ApplianceError,OSError,ValueError,TimeoutError) as error:
                case['reasons'].append(error.code if isinstance(error,ApplianceError) else 'lab-process-unavailable')
            finally:
                if console is not None:
                    try:
                        case['process'] = console.close()
                    except (OSError,subprocess.TimeoutExpired):
                        case['reasons'].append('lab-process-cleanup-failed')
                for stream in logs.values():
                    stream.flush(); os.fsync(stream.fileno())
            for role in ('target','canary','uefi_vars'):
                hashes[role]['final'] = _hash_fd(handles[role+'_copy'])
                if role != 'uefi_vars':
                    case['assertions'].append({'name':role+'-unchanged','passed':hashes[role]['initial'] == hashes[role]['final']})
            case['input_digests'] = _input_digests(config,inputs)
            originals = all(record['same_file'] and record['initial'] == record['final']
                            for record in case['input_digests'].values())
            case['assertions'].append({'name':'readonly-inputs-unchanged','passed':originals})
            case['assertions'].append({'name':'source-identity-unchanged',
                                       'passed':source_identity() == result['identities']['source_id']})
            case['image_digests'] = hashes
            for filename in ('launch.json','serial.log','qemu.log'):
                path = run / filename
                # Empty diagnostic streams are legitimate evidence, unlike input files.
                raw = path.read_bytes()
                case['evidence'].append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)})
            case['checked_at'] = datetime.now(timezone.utc).isoformat()
            if synthetic:
                case['reasons'].append('synthetic-process-boundary')
            _set_outcome(case,result,synthetic=synthetic,launched=console is not None,observed=observed)
            result['reasons'].append('suite-assertions-incomplete')
            atomic_write(run,'/result.json',canonical(result),mode=0o600)
        except (ApplianceError,OSError,ValueError,TypeError,KeyError) as error:
            code = error.code if isinstance(error,ApplianceError) else 'lab-run-unavailable'
            case['reasons'].append(code); result['reasons'].append(code)
            _set_outcome(case,result,synthetic=synthetic,launched=console is not None,observed=observed)
            if run is not None:
                try:
                    atomic_write(run,'/result.json',canonical(result),mode=0o600)
                except (ApplianceError,OSError):
                    result['reasons'].append('lab-result-publication-failed')
    return result

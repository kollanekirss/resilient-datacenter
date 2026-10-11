"""Disposable runner tests use fake process boundaries, never live KVM proof."""
import hashlib
import fcntl
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from appliance.contracts import canonical, identity
from appliance.installer.adapters.pve import ADAPTER_ID,SOURCE_REVISION

ROOT = Path(__file__).resolve().parents[2]


def api():
    return importlib.import_module('appliance.lab_runner')


def pin(path):
    return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.fixture
def execution(tmp_path):
    work = tmp_path / 'lab'
    work.mkdir(mode=0o700)
    marker = work / '.rdc-appliance-lab.json'
    marker.write_bytes(canonical({'schema':1,'owner_id':'unit-lab'})); marker.chmod(0o600)
    images = {}
    for name in ('installer','target','canary','uefi_code','uefi_vars'):
        path = work / (name + '.raw')
        path.write_bytes((name.encode()+b'\0') * 512)
        path.chmod(0o600)
        images[name] = pin(path)
    qemu = tmp_path / 'qemu-system-x86_64'
    qemu.write_bytes(b'fake executable boundary; never run\n'); qemu.chmod(0o700)
    plan = work / 'site.json'; plan.write_bytes(canonical({'schema':1,'site_id':'unit-lab'})); plan.chmod(0o600)
    spec = work / 'spec.md'; spec.write_bytes(b'Pinned unit-test specification\n'); spec.chmod(0o600)
    build = {'schema':1,'adapter_id':ADAPTER_ID,'source_revision':SOURCE_REVISION,
             'release_identity':'b'*64,'runtime_identity':api().source_identity(),
             'qualification':'not-run','qualification_build':True,
             'launcher':{'sha256':'c'*64,'size_bytes':1,'max_bytes':1},
             'init_script':{'sha256':'d'*64,'size_bytes':1,'max_bytes':1}}
    receipt = work / 'candidate.iso.json'
    receipt.write_bytes(canonical({**build,'build_id':identity(build),
        'image':{'sha256':images['installer']['sha256'],'size_bytes':Path(images['installer']['path']).stat().st_size,
                 'max_bytes':Path(images['installer']['path']).stat().st_size}})); receipt.chmod(0o600)
    config = {'schema':1,'workspace':str(work),'owner_id':'unit-lab','build_id':identity(build),
              'spec_id':pin(spec)['sha256'],'images':images,'plan':pin(plan),'spec':pin(spec),
              'build_receipt':pin(receipt),'qemu_sha256':pin(qemu)['sha256'],
              'execution':{'enabled':True,'timeout_seconds':60,'memory_mib':2048,'vcpus':2}}
    platform = {'system':'Linux','machine':'x86_64','kvm_available':True,'qemu_path':str(qemu)}
    return config,platform


class FakeConsole:
    def __init__(self,argv,*,cwd,pass_fds,executable,timeout_seconds):
        self.argv,self.cwd,self.fds = argv,Path(cwd),pass_fds
        self.sent = []
        self.closed = False
        self.events = [b'Appliance local setup (serial console)\n']

    def receive(self,timeout):
        if not self.events:
            raise TimeoutError('fixture console has no more bytes')
        return [('serial',self.events.pop(0))]

    def send(self,raw):
        self.sent.append(raw)
        if raw == b'\x1b[B\r':
            self.events.append('Two-port appliance installer — UNQUALIFIED CANDIDATE\n1 Install\nSelect (no default): '.encode())
        elif raw == b'\r':
            self.events.append(b'No action selected.\nSelect (no default): ')
        elif raw == b'3\r':
            self.events.append(b'Local USB recovery console. No disk was mounted or changed by opening it.\nUSB recovery (local root) # ')
        elif raw == b'exit\r':
            self.events.append(b'exit\nSelect (no default): ')
        else:
            raise AssertionError('Unexpected console action')

    def close(self):
        self.closed = True
        return {'returncode':-15,'termination':'terminated'}


class Factory:
    def __init__(self,cls=FakeConsole):
        self.cls = cls
        self.instances = []

    def __call__(self,*args,**kwargs):
        console = self.cls(*args,**kwargs)
        self.instances.append(console)
        return console


def execute(config,platform,factory):
    return api().execute_lab(config,'media-gate',config_sha256=hashlib.sha256(canonical(config)).hexdigest(),
                             _platform=platform,_process_factory=factory)


def test_execution_profile_requires_owned_private_workspace_and_pinned_receipt(execution):
    config,platform = execution
    assert api().inspect_execution(config,platform) == []
    Path(config['workspace']).chmod(0o777)
    assert 'workspace-private-required' in api().inspect_execution(config,platform)
    Path(config['workspace']).chmod(0o700)
    Path(config['build_receipt']['path']).write_bytes(b'{}')
    assert 'build-receipt-sha256-mismatch' in api().inspect_execution(config,platform)


def test_fake_process_never_becomes_live_evidence_and_only_copies_are_writable(execution):
    config,platform = execution
    initial = {name:pin(Path(item['path']))['sha256'] for name,item in config['images'].items()}
    factory = Factory()
    result = execute(config,platform,factory)
    assert result['qualification'] == 'NOT RUN' and result['status'] == 'NOT RUN'
    case = next(c for c in result['cases'] if c['case_id'] == 'boot-menu-cancel')
    assert case['method'] == 'unit-fixture' and case['state'] == 'unknown'
    assert 'synthetic-process-boundary' in case['reasons']
    assert all(a['passed'] for a in case['assertions'])
    process = factory.instances[0]
    assert process.closed and process.sent == [b'\x1b[B\r',b'\r',b'3\r',b'exit\r']
    assert process.cwd.parent == Path(config['workspace'])
    for name,item in config['images'].items():
        assert pin(Path(item['path']))['sha256'] == initial[name]
    assert (process.cwd / 'target.raw').read_bytes() == Path(config['images']['target']['path']).read_bytes()
    assert (process.cwd / 'canary.raw').read_bytes() == Path(config['images']['canary']['path']).read_bytes()
    argv = process.argv
    assert '-nic' in argv and argv[argv.index('-nic')+1] == 'none'
    assert not any(value.startswith(('tap,','user,','bridge,','socket,','vhost-user,')) or 'hostfwd' in value for value in argv)
    assert 'q35,accel=kvm' in argv and '-snapshot' not in argv
    assert any('if=pflash' in value and 'readonly=on' in value for value in argv)
    assert any('media=cdrom' in value and 'readonly=on' in value for value in argv)
    for fd in process.fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert Path(result['evidence_directory'],'serial.log').is_file()
    assert result['identities']['plan_id'] == identity({'schema':1,'site_id':'unit-lab'})
    assert all(c['status'] == 'NOT RUN' for c in result['cases'])


def test_timeout_cleans_process_and_leaves_unobserved_cases_not_run(execution):
    class Silent(FakeConsole):
        def receive(self,timeout):
            raise TimeoutError('no guest output')
    config,platform = execution
    factory = Factory(Silent)
    result = execute(config,platform,factory)
    assert factory.instances[0].closed
    case = next(c for c in result['cases'] if c['case_id'] == 'boot-menu-cancel')
    assert case['state'] == 'unknown' and 'console-observation-timeout' in case['reasons']
    assert result['qualification'] == 'NOT RUN'


def test_canary_change_is_detected_without_modifying_seed(execution):
    class Changing(FakeConsole):
        def close(self):
            (self.cwd / 'canary.raw').write_bytes(b'changed disposable copy')
            return super().close()
    config,platform = execution
    before = Path(config['images']['canary']['path']).read_bytes()
    result = execute(config,platform,Factory(Changing))
    case = next(c for c in result['cases'] if c['case_id'] == 'boot-menu-cancel')
    assert any(a['name'] == 'canary-unchanged' and not a['passed'] for a in case['assertions'])
    assert Path(config['images']['canary']['path']).read_bytes() == before
    assert case['state'] != 'verified'


def test_failed_prerequisites_never_create_run_directory_or_spawn(execution):
    config,platform = execution
    platform['system'] = 'Darwin'
    factory = Factory()
    before = set(Path(config['workspace']).iterdir())
    result = execute(config,platform,factory)
    assert 'linux-required' in result['reasons'] and result['status'] == 'NOT RUN'
    assert factory.instances == [] and set(Path(config['workspace']).iterdir()) == before


def test_readonly_input_symlink_or_seed_hardlink_never_launches(execution):
    config,platform = execution
    installer = Path(config['images']['installer']['path'])
    saved = installer.with_suffix('.original'); installer.rename(saved); installer.symlink_to(saved)
    factory = Factory()
    result = execute(config,platform,factory)
    assert not factory.instances and any('symlink' in r for r in result['reasons'])


def test_unknown_suite_cases_never_launch_or_claim_pass(execution):
    config,platform = execution
    factory = Factory()
    result = api().execute_lab(config,'router-policy',config_sha256='a'*64,_platform=platform,_process_factory=factory)
    assert factory.instances == []
    assert result['status'] == 'NOT RUN' and all(c['status'] == 'NOT RUN' for c in result['cases'])


def test_execute_cli_without_linux_lab_is_structured_nonzero(tmp_path):
    result = subprocess.run([sys.executable,str(ROOT / 'scripts/ci_appliance_base.py'),
                             '--execute','--suite','media-gate','--lab-config',str(tmp_path / 'missing.json')],
                            capture_output=True,text=True)
    assert result.returncode == 2
    report = json.loads(result.stdout)
    assert report['status'] == 'NOT RUN' and report['qualification'] == 'NOT RUN'


def test_busy_workspace_refuses_second_process_without_creating_a_child(execution):
    config,platform = execution
    work = Path(config['workspace'])
    fd = os.open(work,os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        factory = Factory()
        before = set(work.iterdir())
        result = execute(config,platform,factory)
        assert 'lab-workspace-busy' in result['reasons']
        assert not factory.instances and set(work.iterdir()) == before
    finally:
        os.close(fd)


def test_operator_interrupt_closes_child_and_records_final_digests(execution):
    class Interrupted(FakeConsole):
        def receive(self,timeout):
            raise KeyboardInterrupt()
    config,platform = execution
    factory = Factory(Interrupted)
    result = execute(config,platform,factory)
    assert factory.instances[0].closed
    case = next(c for c in result['cases'] if c['case_id'] == 'boot-menu-cancel')
    assert 'operator-interrupted' in case['reasons']
    assert case['image_digests']['canary']['initial'] == case['image_digests']['canary']['final']


def test_replacing_an_input_path_during_guest_run_is_not_verified(execution):
    config,platform = execution
    class Replacing(FakeConsole):
        def close(self):
            seed = Path(config['images']['target']['path'])
            replacement = seed.with_suffix('.replacement')
            replacement.write_bytes(b'replaced by another host process')
            os.replace(replacement,seed)
            return super().close()
    result = execute(config,platform,Factory(Replacing))
    case = next(c for c in result['cases'] if c['case_id'] == 'boot-menu-cancel')
    assert any(a['name'] == 'readonly-inputs-unchanged' and not a['passed'] for a in case['assertions'])


@pytest.mark.parametrize('reason',[
    'console-observation-timeout','qemu-exited-before-observation',
    'lab-process-cleanup-failed','lab-run-unavailable',
])
def test_classification_marks_post_launch_errors_failed_without_creating_live_evidence(reason):
    # Pure classification only: no fake report is promoted to real execution.
    assert api().classify_outcome(synthetic=False,launched=True,observed=False,
                                 assertions=[],reasons=[reason]) == ('failed','FAIL','FAIL')


def test_classification_distinguishes_prelaunch_synthetic_and_completed_observation():
    classify = api().classify_outcome
    assert classify(synthetic=False,launched=False,observed=False,assertions=[],
                    reasons=['lab-process-unavailable']) == ('unknown','NOT RUN','NOT RUN')
    assert classify(synthetic=True,launched=True,observed=False,assertions=[],
                    reasons=['console-observation-timeout']) == ('unknown','NOT RUN','NOT RUN')
    assert classify(synthetic=False,launched=True,observed=True,
                    assertions=[{'passed':True}],reasons=[]) == ('verified','OBSERVED','PARTIAL')
    assert classify(synthetic=False,launched=True,observed=True,
                    assertions=[{'passed':False}],reasons=[]) == ('failed','FAIL','FAIL')
    assert classify(synthetic=False,launched=True,observed=True,
                    assertions=[{'passed':True}],reasons=['lab-process-cleanup-failed']) == ('failed','FAIL','FAIL')

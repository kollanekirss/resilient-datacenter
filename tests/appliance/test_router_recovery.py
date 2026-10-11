"""Recovery mutates only a newly allocated, isolated clone.

PVE/FreeBSD execution is an explicit external boundary. The controller,
validation, journals, locks, protocol and private artifacts run here for real.
"""
import base64
import copy
import fcntl
import hashlib
import importlib
import json
from pathlib import Path
import subprocess

import pytest

from appliance import proxmox, state
from appliance.contracts import ApplianceError, canonical, identity
from appliance.router_config import render_router


def recovery():
    try:
        module = importlib.import_module('appliance.router_recovery')
    except ModuleNotFoundError:
        pytest.fail('isolated router recovery is not implemented')
    return module


class RecoveryPve:
    """Emulates qm storage/config outcomes, not recovery policy decisions."""
    def __init__(self, site, private):
        spec = proxmox.vm_spec(site, 'router')
        cfg = proxmox._base(spec)
        cfg['scsi0'] = 'local-lvm:vm-101-disk-0,size=16G'
        self.configs = {101: cfg}; self.running = set(); self.mutations = []
        self.fail = None; self.foreign_disk = False; self.lock_dir = None
        self.pending = False
        self.bridges = {}
        state.write(private / 'vms/101.json', {'schema':1,'spec':spec,'phase':'disk-ready',
            'links':{},'sequence':1,'disk_volume':'local-lvm:vm-101-disk-0'})
    def run(self, argv, *, stdin=b'', timeout_s=30):
        value = ''
        if argv[0] == '/usr/sbin/ip':
            if argv[1:5] == ['-json','-details','link','show']: value=json.dumps(list(self.bridges.values()))
            elif argv[1:4] == ['-json','address','show']:
                value=json.dumps([dict(row,addr_info=[]) for row in self.bridges.values()])
            elif argv[1:3] == ['link','add']:
                name=argv[4]; assert name not in self.bridges
                self.bridges[name]={'ifname':name,'ifalias':argv[6],'flags':['BROADCAST','MULTICAST'],
                    'linkinfo':{'info_kind':'bridge'}}
            elif argv[1:3] == ['link','delete']: del self.bridges[argv[4]]
            else: raise AssertionError(argv)
        elif argv[0] == '/usr/bin/hostname': value = 'pve\n'
        elif argv[0] == '/usr/bin/cat':
            value = 'host-boot\n' if argv[1].endswith('boot_id') else '123 (qemu) S ' + '0 '*18 + '456 0\n'
        elif argv[0] == proxmox.PVESH:
            if argv[2] == '/cluster/resources':
                value = json.dumps([{'vmid':v,'node':'pve','type':'qemu'} for v in self.configs])
            elif argv[2].endswith('/status'):
                value = json.dumps({'active':1,'enabled':1,'type':'lvmthin','content':'images','avail':100*1024**3})
            else: value = json.dumps([{'volid':'local-lvm:vm-901-disk-0'}] if self.foreign_disk else [])
        elif argv[:2] == [proxmox.QM,'config']:
            cfg = dict(self.configs[int(argv[2])])
            if self.pending and int(argv[2])==901 and len(argv)==3: cfg['onboot']='1'
            value = '\n'.join(k+': '+v for k,v in cfg.items())+'\n'
        elif argv[:2] == [proxmox.QM,'status']:
            value = 'status: '+('running' if int(argv[2]) in self.running else 'stopped')+'\npid: 123\n'
        elif argv[0] == proxmox.QM:
            vmid = int(argv[2]); self.mutations.append(argv)
            assert vmid == 901, 'the original router must never be mutated'
            if argv[1]=='create':
                # Real PVE start/update requires this same exclusive flock.
                if self.lock_dir:
                    with open(self.lock_dir/'lock-101.conf','a') as lock:
                        with pytest.raises(BlockingIOError): fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        # PVE import-from takes a shared source lock while
                        # copying a stopped volume. It must not deadlock.
                        fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
                assert vmid not in self.configs
                cfg=dict(zip((p[2:] for p in argv[3::2]),argv[4::2]))
                assert 'import-from=local-lvm:vm-101-disk-0' in cfg['scsi0']
                cfg['scsi0']='local-lvm:vm-901-disk-0,size=16G,serial='+cfg['scsi0'].split('serial=')[1]
                self.configs[vmid]=cfg
            elif argv[1]=='set':
                for key,value in zip(argv[3::2],argv[4::2]):
                    if key=='--delete':
                        for name in value.split(','): self.configs[vmid].pop(name,None)
                    else: self.configs[vmid][key[2:]]=value
            elif argv[1]=='start':
                # The controller's contract must hold before either boot.
                assert 'rdcr901' in self.bridges
                assert all('bridge=rdcr901' in v and 'link_down=1' in v
                    for k,v in self.configs[vmid].items() if k.startswith('net'))
                self.running.add(vmid)
            elif argv[1] in ('stop','shutdown'): self.running.discard(vmid)
            else: raise AssertionError(argv)
            if self.fail==argv[1]: raise ApplianceError('command-timeout')
        else: raise AssertionError(argv)
        return subprocess.CompletedProcess(argv,0,value.encode(),b'')


@pytest.fixture
def prepared(site, release, tmp_path, monkeypatch):
    module = recovery()
    release = copy.deepcopy(release); release.pop('test_only')
    dvd=tmp_path/'dvd.iso'; dvd.write_bytes(b'pinned DVD')
    release['components']=[dict(id=name,version='26.7' if name=='opnsense-dvd' else '1',
        url='https://example.org/'+name,sha256=hashlib.sha256(dvd.read_bytes()).hexdigest(),
        size_bytes=10,max_bytes=10,provenance={'kind':'official-checksum','url':'https://example.org/sums'})
        for name in ('proxmox-iso','opnsense-dvd','probe-image','restic')]
    private=tmp_path/'private'; runner=RecoveryPve(site,private)
    lockdir=tmp_path/'locks'; lockdir.mkdir(mode=0o700); runner.lock_dir=lockdir
    export=tmp_path/'opened'; build={'schema':1,'build_id':'b'*64}
    for name,record in {'site.json':site,'release.lock.json':release,'build.json':build,
        'vms.json':{'101':state.read(private/'vms/101.json')},'host.json':{}}.items(): state.write(export/name,record)
    key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'x'*32).decode()
    xml=render_router(site,{'root_password_hash':'$2y$12$'+'a'*53,'management_public_key':key,
        'interface_map':{n['mac']:'vtnet'+str(n['index']) for n in proxmox.vm_spec(site,'router')['nics']}})
    with state._directory_fd(export) as fd: state._write_at(fd,'router.xml',xml)
    def builder(plan, xml, nonce, dvd, output, runner, release):
        output.write_bytes(b'private recovery DVD'); output.chmod(0o600)
        return {'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'size_bytes':20}
    monkeypatch.setattr(module,'build_recovery_iso',builder)
    class Console:
        def __init__(self,vmid): self.vmid=vmid
        def exchange(self,nonce,stage,*,timeout_s=300):
            return {'schema':1,'nonce':nonce,'stage':stage,'config_sha256':hashlib.sha256(xml).hexdigest(),
                    'version':'26.7','root_kind':'installed-disk' if stage=='verify' else 'recovery-media',
                    'root_device':'/dev/da0p3','hook_removed':stage=='verify'}
        def close(self): pass
    arguments=dict(dvd=dvd,work=tmp_path/'work',release=release,build=build,
                   console_factory=Console,lock_directory=lockdir)
    return module,runner,private,export,arguments


def test_restores_only_bridge_free_clone_and_stops_it(site,prepared):
    module,runner,private,export,arguments=prepared
    original=copy.deepcopy(runner.configs[101])
    result=module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert result['state']=='verified' and result['clone_stopped'] is True
    assert result['activation']=='forbidden' and not runner.running
    assert runner.configs[101]==original
    assert runner.configs[901]['boot']=='order=scsi0' and 'ide2' not in runner.configs[901]
    assert all('bridge=rdcr901' in v and 'link_down=1' in v for k,v in runner.configs[901].items() if k.startswith('net'))
    assert runner.bridges=={} and result['bridge_removed'] is True
    assert len([a for a in runner.mutations if a[1]=='start'])==2
    assert 'password' not in json.dumps(result) and 'xml' not in json.dumps(result)
    assert not (arguments['work']/'recovery.iso').exists()


@pytest.mark.parametrize('fault',['running-source','foreign-clone','foreign-disk','export-plan','export-build','export-vm','xml-plan'])
def test_refuses_unbound_source_export_or_target_before_mutation(site,prepared,fault):
    module,runner,private,export,arguments=prepared
    if fault=='running-source': runner.running.add(101)
    if fault=='foreign-clone': runner.configs[901]={'name':'other'}
    if fault=='foreign-disk': runner.foreign_disk=True
    if fault=='export-plan': state.write(export/'site.json',dict(site,revision=2))
    if fault=='export-build': state.write(export/'build.json',{'build_id':'c'*64})
    if fault=='export-vm': state.write(export/'vms.json',{})
    if fault=='xml-plan':
        path=export/'router.xml'; path.write_bytes(path.read_bytes().replace(identity(site).encode(),b'f'*64))
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert runner.mutations==[]


@pytest.mark.parametrize('failure',['create','start','set'])
def test_uncertain_mutation_is_stopped_and_never_replayed(site,prepared,failure):
    module,runner,private,export,arguments=prepared; runner.fail=failure
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert not runner.running
    attempts=len(runner.mutations); runner.fail=None
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert len(runner.mutations)==attempts
    result=module.reconcile_router_recovery(901,runner,private)
    assert result['state']=='incomplete' and result['clone_stopped'] is True
    assert len(runner.mutations)==attempts


@pytest.mark.parametrize('fault',['nonce','version','config_sha256','root_kind','hook_removed','interrupt'])
def test_failed_or_interrupted_disk_proof_always_stops_clone(site,prepared,fault):
    module,runner,private,export,arguments=prepared
    normal=arguments['console_factory']
    class Console(normal):
        def exchange(self,nonce,stage,**kwargs):
            result=super().exchange(nonce,stage,**kwargs)
            if stage=='verify':
                if fault=='interrupt': raise KeyboardInterrupt()
                result[fault]='wrong'
            return result
    arguments['console_factory']=Console
    with pytest.raises((ApplianceError,KeyboardInterrupt)):
        module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert not runner.running
    receipt=state.read(private/'router-recovery/901.json')
    assert receipt['phase']=='failed' and receipt['cleanup']=='stopped'


def test_source_lock_is_exclusive_and_released_after_exception(tmp_path):
    module=recovery(); tmp_path.chmod(0o700)
    with pytest.raises(RuntimeError):
        with module.source_lock(101,tmp_path):
            with open(tmp_path/'lock-101.conf','a') as other:
                with pytest.raises(BlockingIOError): fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            raise RuntimeError('stop')
    with open(tmp_path/'lock-101.conf','a') as other: fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)


def test_serial_handles_split_frames_and_waits_for_nonce_bound_ready(tmp_path):
    import socket
    import threading
    import tempfile
    short=tempfile.TemporaryDirectory(prefix='rdc-',dir='/tmp')
    module=recovery(); tmp_path=Path(short.name); path=tmp_path/'901.serial0'; nonce='a'*64
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); listener.bind(str(path)); listener.listen(1)
    errors=[]
    def guest():
        try:
            conn,_=listener.accept()
            with conn:
                conn.settimeout(0.03)
                with pytest.raises(socket.timeout): conn.recv(200)
                conn.settimeout(2)
                conn.sendall(b'boot progress\nRDC-READY import '+nonce.encode()+b'\n')
                assert conn.recv(200)==('RDC1 '+nonce+' import\n').encode()
                payload=module.PREFIX+b'{"nonce":"'+nonce.encode()+b'"}\n'
                for fragment in (payload[:10],payload[10:25],payload[25:]):
                    conn.sendall(fragment)
                    __import__('time').sleep(0.01)
        except BaseException as e: errors.append(e)
    worker=threading.Thread(target=guest); worker.start()
    console=module.SerialConsole(901,socket_directory=tmp_path)
    try: assert console.exchange(nonce,'import',timeout_s=2)=={'nonce':nonce}
    finally: console.close(); worker.join(timeout=3); listener.close(); short.cleanup()
    assert not errors and not worker.is_alive()


def test_reconciliation_never_accepts_foreign_media(site,prepared):
    module,runner,private,export,arguments=prepared; runner.fail='start'
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    runner.configs[901]['ide2']='/foreign/recovery.iso,media=cdrom'
    with pytest.raises(ApplianceError,match='recovery-clone-media'):
        module.reconcile_router_recovery(901,runner,private)


def test_clone_cleanup_stops_owned_running_vm_despite_pending_config_drift(site,prepared):
    module,runner,private,export,arguments=prepared
    normal=arguments['console_factory']
    class Console(normal):
        def exchange(self,*args,**kwargs):
            runner.pending=True
            raise ApplianceError('recovery-pending-drift')
    arguments['console_factory']=Console
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert not runner.running


def test_payload_is_valid_shell_and_does_not_require_guest_agent(site,tmp_path):
    module=recovery()
    # Its boot script must parse on /bin/sh; actual FreeBSD commands require lab.
    xml=('<opnsense><rdcappliance><plan_id>'+identity(site)+'</plan_id></rdcappliance></opnsense>').encode()
    payload=module.recovery_payload(site,xml,'a'*64)
    for name in ('/etc/rc','/rdc-recovery/verify'):
        script=tmp_path/Path(name).name; script.write_bytes(payload[name])
        completed=subprocess.run(['/bin/sh','-n',str(script)],capture_output=True)
        assert completed.returncode==0,completed.stderr.decode()


@pytest.mark.parametrize('fault',['foreign-port','address','up','owner'])
def test_bridge_drift_aborts_proof_and_stops_clone(site,prepared,fault):
    module,runner,private,export,arguments=prepared
    normal=arguments['console_factory']
    class Console(normal):
        def exchange(self,*args,**kwargs):
            bridge=runner.bridges['rdcr901']
            if fault=='foreign-port': runner.bridges['eth9']={'ifname':'eth9','master':'rdcr901'}
            if fault=='up': bridge['flags'].append('UP')
            if fault=='owner': bridge['ifalias']='foreign'
            if fault=='address':
                old=runner.run
                def run(argv,**kw):
                    answer=old(argv,**kw)
                    if argv[:4]==['/usr/sbin/ip','-json','address','show']:
                        answer.stdout=json.dumps([{'ifname':'rdcr901','addr_info':[{'local':'fe80::1'}]}]).encode()
                    return answer
                runner.run=run
            return super().exchange(*args,**kwargs)
    arguments['console_factory']=Console
    with pytest.raises(ApplianceError): module.restore_router_isolated(site,export,901,runner,private,**arguments)
    assert not runner.running
    assert state.read(private/'router-recovery/901.json')['phase']=='failed'


def test_remaster_uses_bundled_genisoimage_and_unmounts_on_readback_failure(site,prepared,monkeypatch,tmp_path):
    module,_,_,export,arguments=prepared
    # Remove only the fixture's external-media stub to exercise actual builder.
    monkeypatch.undo()
    class MediaRunner:
        def __init__(self): self.mounted=set(); self.generated=None
        def run(self,argv,**kwargs):
            if argv[0]=='/usr/bin/mount':
                mount=Path(argv[-1]); self.mounted.add(mount)
                if argv[-2]==str(arguments['dvd']):
                    (mount/'boot').mkdir(); (mount/'boot/cdboot').write_bytes(b'boot')
                    (mount/'etc').mkdir(); (mount/'etc/rc').write_bytes(b'original')
                else:
                    for target in ('etc/rc','rdc-recovery/config.xml','rdc-recovery/verify'):
                        p=mount/target; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b'corrupt')
            elif argv[0]=='/usr/bin/umount': self.mounted.remove(Path(argv[-1]))
            elif argv[0]=='/usr/bin/genisoimage':
                self.generated=Path(argv[-1]); Path(argv[argv.index('-o')+1]).write_bytes(b'output')
            else: raise AssertionError(argv)
            return subprocess.CompletedProcess(argv,0,b'',b'')
    runner=MediaRunner(); out=tmp_path/'recovery.iso'
    with pytest.raises(ApplianceError,match='recovery-media-readback'):
        module.build_recovery_iso(site,(export/'router.xml').read_bytes(),'a'*64,
            arguments['dvd'],out,runner,arguments['release'])
    assert runner.mounted==set() and runner.generated is not None and not out.exists()

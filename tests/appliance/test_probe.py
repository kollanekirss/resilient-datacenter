import base64
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from appliance.contracts import ApplianceError, identity
from appliance import probe

PASSWORD='$6$uniquesalt$'+'a'*86


def test_seed_is_deterministic_private_site_only_and_offline(site):
    files=probe.seed_files(site,password_hash=PASSWORD)
    assert files==probe.seed_files(site,password_hash=PASSWORD)
    assert set(files)=={'user-data','meta-data','network-config'}
    user=json.loads(files['user-data'].split(b'\n',1)[1])
    network=json.loads(files['network-config'])['ethernets']['probe0']
    assert user['users'][0]['hashed_passwd']==PASSWORD
    assert user['package_update'] is False and user['package_upgrade'] is False
    assert user['ssh_pwauth'] is False and user['disable_root'] is True
    assert network['match']['macaddress']==site['vms']['probe']['nics'][0]['mac']
    assert network['addresses']==['10.77.2.10/24']
    assert network['dhcp4'] is False and network['dhcp6'] is False
    assert network['accept-ra'] is False and network['link-local']==[]
    assert b'tailscale' not in b''.join(files.values())
    assert b'curl' not in b''.join(files.values())
    assert all('://' not in value.decode() for value in files.values())
    different=probe.seed_files(site,password_hash='$6$anothersalt$'+'b'*86)
    assert files['meta-data']!=different['meta-data']


@pytest.mark.parametrize('password',['','plain text','$6$short$bad',PASSWORD+'\ncommand'])
def test_seed_refuses_non_hash_console_credentials(site,password):
    with pytest.raises(ApplianceError,match='probe-password-hash'):
        probe.seed_files(site,password_hash=password)


def test_seed_refuses_forbidden_attachment_and_invalid_key(site):
    with pytest.raises(ApplianceError,match='probe-public-key'):
        probe.seed_files(site,password_hash=PASSWORD,ssh_public_key='ssh-ed25519 malicious\ncommand')
    site['vms']['probe']['nics'][0]['zone']='management'
    with pytest.raises(ApplianceError): probe.seed_files(site,password_hash=PASSWORD)


class SeedTools:
    def __init__(self): self.files={}; self.calls=[]; self.bad=False
    def run(self,argv,**kwargs):
        self.calls.append(argv)
        if argv[0] == '/usr/bin/genisoimage':
            for item in argv[argv.index('-graft-points')+1:]:
                name,path=item.split('=',1); self.files['/'+name]=Path(path).read_bytes()
            Path(argv[argv.index('-o')+1]).write_bytes(b'fixture-only-seed-iso')
        elif argv[0] == '/usr/bin/isoinfo':
            return CompletedProcess(argv,0,b'bad' if self.bad else self.files[argv[-1]],b'')
        else: pytest.fail(str(argv))
        return CompletedProcess(argv,0,b'',b'')


def test_seed_builder_reads_back_private_iso_before_publication(site,tmp_path):
    tmp_path.chmod(0o700); runner=SeedTools();output=tmp_path/'seed.iso'
    receipt=probe.build_seed(site,output,runner,password_hash=PASSWORD)
    assert receipt['image']['sha256']==hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.stat().st_mode&0o777==0o600
    assert output.with_suffix('.iso.json').stat().st_mode&0o777==0o600
    assert receipt['qualification']=='not-run'
    assert all(PASSWORD not in ' '.join(command) for command in runner.calls)
    with pytest.raises(ApplianceError):probe.build_seed(site,output,runner,password_hash=PASSWORD)


def test_bad_seed_readback_is_not_published(site,tmp_path):
    tmp_path.chmod(0o700);runner=SeedTools();runner.bad=True
    with pytest.raises(ApplianceError,match='probe-seed-readback'):
        probe.build_seed(site,tmp_path/'seed.iso',runner,password_hash=PASSWORD)
    assert not (tmp_path/'seed.iso').exists()


class Pve:
    def __init__(self,seed_target,state_dir):
        self.config=None;self.running=False;self.calls=[];self.mutations=[]
        self.lose=False;self.foreign=False;self.backing=False;self.seed_target=seed_target;self.state_dir=state_dir
        self.ticks='456'
    def run(self,argv,**kwargs):
        self.calls.append(argv)
        def result(data): return CompletedProcess(argv,0,(data if isinstance(data,str) else json.dumps(data)).encode(),b'')
        name=Path(argv[0]).name
        if name=='qemu-img':return result({'format':'qcow2','virtual-size':3*1024**3,**({'backing-filename':'/private/key'} if self.backing else {})})
        if name=='hostname':return result('pve\n')
        if name=='pvesm':return result(str(self.seed_target))
        if name=='pvesh':
            route=argv[2]
            if route=='/cluster/resources':return result([{'vmid':102}] if self.foreign or self.config else [])
            if route=='/storage/local':return result({'type':'dir','path':'/var/lib/vz','content':'iso'})
            if route.endswith('/status'):return result({'active':1,'enabled':1,'type':'lvmthin','content':'images','avail':100*1024**3})
            if route.endswith('/content'):return result([])
        if name=='cat':return result('host-boot\n' if argv[1].endswith('boot_id') else '123 (qemu) S '+'0 '*18+self.ticks+' 0\n')
        if name=='qm' and argv[1]=='config':
            assert self.config is not None
            return result('\n'.join(k+': '+str(v) for k,v in self.config.items())+'\n')
        if name=='qm' and argv[1]=='status':return result('status: '+('running' if self.running else 'stopped')+'\npid: 123\n')
        assert name=='qm',argv
        # Every external mutation must already have its durable intent.
        from appliance.state import read
        receipt=read(self.state_dir/'probe/102.json')
        assert receipt.get('pending')
        assert read(self.state_dir/'operations'/(receipt['pending']+'.json'))['phase']=='pending'
        self.mutations.append(argv)
        if argv[1]=='create':
            self.config=dict(zip([k[2:] for k in argv[3::2]],argv[4::2]))
            assert self.config['scsi0'].startswith('local-lvm:0,import-from=')
            self.config['scsi0']='local-lvm:vm-102-disk-0,size=3G'
        elif argv[1]=='resize':self.config['scsi0']='local-lvm:vm-102-disk-0,size='+argv[-1]
        elif argv[1]=='start':self.running=True
        elif argv[1]=='set':self.config[argv[3][2:]]=argv[4]
        else:pytest.fail(argv)
        if self.lose:raise ApplianceError('command-timeout')
        return result('')


@pytest.fixture
def prepared_inputs(site,tmp_path):
    tmp_path.chmod(0o700)
    release=json.loads((Path(__file__).parents[2]/'appliance/releases/v1.lock.json').read_text())
    site['release_id']=release['release_id']
    image=tmp_path/'probe-image';image.write_bytes(b'fixture-only-qcow2')
    component=next(c for c in release['components'] if c['id']=='probe-image')
    component.update(sha256=hashlib.sha256(image.read_bytes()).hexdigest(),size_bytes=image.stat().st_size,max_bytes=image.stat().st_size)
    seed=tmp_path/'seed.iso';probe.build_seed(site,seed,SeedTools(),password_hash=PASSWORD)
    media=tmp_path/'iso-storage';media.mkdir(mode=0o700)
    state_dir=tmp_path/'state';runner=Pve(media/'owned-seed.iso',state_dir)
    return site,release,image,seed,runner,state_dir


def test_prepare_imports_verified_image_grows_owned_disk_and_never_starts(prepared_inputs):
    plan,release,image,seed,runner,state=prepared_inputs
    original=image.read_bytes()
    observed=probe.prepare_probe(plan,release,image,seed,runner,state)
    assert not observed['running'] and observed['nics']['net0']=={
        'mac':plan['vms']['probe']['nics'][0]['mac'],'bridge':'vmbr3','connected':False}
    assert runner.config['boot']=='order=scsi0' and runner.config['onboot']=='0'
    assert runner.config['ide2'].startswith('local:iso/rdc-probe-')
    assert [a[1] for a in runner.mutations]==['create','resize']
    probe.prepare_probe(plan,release,image,seed,runner,state)
    assert len(runner.mutations)==2 and image.read_bytes()==original


@pytest.mark.parametrize('fault',['foreign','backing','image-bytes','seed-bytes'])
def test_unsafe_probe_inputs_never_mutate_vm(prepared_inputs,fault):
    plan,release,image,seed,runner,state=prepared_inputs
    if fault=='foreign':runner.foreign=True
    if fault=='backing':runner.backing=True
    if fault=='image-bytes':image.write_bytes(b'bad')
    if fault=='seed-bytes':seed.write_bytes(b'bad')
    with pytest.raises(ApplianceError):probe.prepare_probe(plan,release,image,seed,runner,state)
    assert not runner.mutations


def test_unknown_import_is_not_retried_and_exact_outcome_can_be_reconciled(prepared_inputs):
    plan,release,image,seed,runner,state=prepared_inputs
    runner.lose=True
    with pytest.raises(ApplianceError):probe.prepare_probe(plan,release,image,seed,runner,state)
    runner.lose=False
    with pytest.raises(ApplianceError,match='probe-operation-needs-inspection'):
        probe.prepare_probe(plan,release,image,seed,runner,state)
    assert len(runner.mutations)==1
    probe.reconcile_probe(plan,runner,state)
    probe.prepare_probe(plan,release,image,seed,runner,state)
    assert [a[1] for a in runner.mutations]==['create','resize']


@pytest.mark.parametrize('fault',['network','disk','extra-device','boot','owner'])
def test_uncertain_import_drift_is_never_adopted(prepared_inputs,fault):
    plan,release,image,seed,runner,state=prepared_inputs;runner.lose=True
    with pytest.raises(ApplianceError):probe.prepare_probe(plan,release,image,seed,runner,state)
    runner.lose=False
    if fault=='network':runner.config['net0']=runner.config['net0'].replace('vmbr3','vmbr0')
    if fault=='disk':runner.config['scsi0']='foreign:vm-102-disk-0,size=3G'
    if fault=='extra-device':runner.config['hostpci0']='0000:01:00.0'
    if fault=='boot':runner.config['boot']='order=ide2;scsi0'
    if fault=='owner':runner.config['description']='foreign'
    with pytest.raises(ApplianceError):probe.reconcile_probe(plan,runner,state)
    assert len(runner.mutations)==1


def ready_probe(prepared_inputs):
    plan,release,image,seed,runner,state=prepared_inputs
    probe.prepare_probe(plan,release,image,seed,runner,state)
    probe.start_probe(plan,runner,state)
    return probe.attest_console(plan,{key:True for key in probe.CONSOLE_CHECKS},runner,state)


def router_checks(monkeypatch,plan):
    from appliance import router,proxmox
    calls=[]
    def fresh(*args):
        calls.append('fresh')
        return {'stage':'transit','guard_blocking':False,'vm_boot_id':'router-boot'}
    monkeypatch.setattr(router,'collect_router',fresh)
    monkeypatch.setattr(router,'router_ready',lambda *args:{'checks_passed':True})
    spec=proxmox.vm_spec(plan,'router');nic=next(n for n in spec['nics'] if n['zone']=='workload')
    observed={'boot_id':'router-boot','nics':{'net'+str(nic['index']):{'connected':True}}}
    monkeypatch.setattr(router,'_vm',lambda *args:(spec,observed))
    return calls,observed


def test_workload_attach_requires_live_console_and_fresh_router(prepared_inputs,monkeypatch):
    plan,_,_,_,runner,state=prepared_inputs; attestation=ready_probe(prepared_inputs)
    calls,_=router_checks(monkeypatch,plan)
    before=len(runner.mutations)
    with pytest.raises(ApplianceError,match='probe-console-attestation-required'):
        probe.attach_workload(plan,runner,state,attestation={'checks':True})
    assert len(runner.mutations)==before
    result=probe.attach_workload(plan,runner,state,attestation=attestation)
    assert calls==['fresh'] and result['nics']['net0']['connected']
    assert runner.mutations[-1][3:] == ['--net0','virtio='+plan['vms']['probe']['nics'][0]['mac']+',bridge=vmbr3,firewall=1,link_down=0']


def test_stale_guest_boot_or_router_policy_blocks_attach(prepared_inputs,monkeypatch):
    from appliance import router
    plan,_,_,_,runner,state=prepared_inputs;attestation=ready_probe(prepared_inputs)
    router_checks(monkeypatch,plan);before=len(runner.mutations)
    runner.ticks='999'
    with pytest.raises(ApplianceError,match='probe-console-attestation-stale'):
        probe.attach_workload(plan,runner,state,attestation=attestation)
    runner.ticks='456'
    monkeypatch.setattr(router,'collect_router',lambda *args:{'stage':'bootstrap','guard_blocking':True})
    with pytest.raises(ApplianceError,match='probe-router-not-ready'):
        probe.attach_workload(plan,runner,state,attestation=attestation)
    assert len(runner.mutations)==before


def test_cold_restart_with_old_link_disconnects_before_start(prepared_inputs,monkeypatch):
    plan,_,_,_,runner,state=prepared_inputs;attestation=ready_probe(prepared_inputs)
    router_checks(monkeypatch,plan);probe.attach_workload(plan,runner,state,attestation=attestation)
    runner.running=False;before=len(runner.mutations)
    probe.start_probe(plan,runner,state)
    assert [a[1] for a in runner.mutations[before:]]==['set','start']
    assert runner.running and 'link_down=1' in runner.config['net0']

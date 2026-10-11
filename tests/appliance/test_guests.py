import copy
import json
from subprocess import CompletedProcess
import pytest
from appliance import guests, proxmox, state as records
from appliance.contracts import ApplianceError, identity


def role_site(site):
    site=copy.deepcopy(site);site['roles']['connector']={'selected':True}
    site['vms']['connector']={'role':'connector','vmid':103,'name':'pilot-connector','memory_mib':1024,'vcpus':1,'disk_gib':8,'storage':'local-lvm','nics':[{'zone':'infrastructure','mac':'02:bb:00:00:00:06','address':'10.77.1.10','connected':False}]}
    return site


def req():return {'schema':1,'operation_id':'operation-1','plan_id':'a'*64,'role':'connector','action':'enroll','parameters':{'authorization':'synthetic-private-key'}}


class GuestTools:
    def __init__(self):self.calls=[];self.inputs=[];self.pending=False;self.lose=False;self.large=False;self.bad=False
    def run(self,argv,*,stdin=b'',**kw):
        self.calls.append(argv);self.inputs.append(stdin)
        if argv[1:3]==['guest','exec']:
            if self.lose:raise ApplianceError('command-timeout')
            data={'pid':1234}
        else:
            data={'exited':0} if self.pending else {'exited':1,'exitcode':0,'out-data':json.dumps({'operation_id':'wrong' if self.bad else 'operation-1','phase':'complete','code':'ok','observations':{'machine_id':'1'*32,'configured':True,'padding':'a'*(600000 if self.large else 0)}})}
        return CompletedProcess(argv,0,json.dumps(data).encode(),b'')


def owned(tmp_path,site,monkeypatch):
    site=role_site(site);spec=proxmox.vm_spec(site,'connector');spec['plan_id']='a'*64
    record={'schema':1,'spec':spec,'phase':'prepared','connected':False,'sequence':1,'disk_bytes':8*1024**3,'disk_volume':'local-lvm:vm-103-disk-0','seed_path':'/private/seed.iso','seed_image':{'sha256':'c'*64,'size_bytes':1,'max_bytes':1},'seed_volume':'local:iso/seed.iso','source_image':'d'*64}
    records.write(tmp_path/'role-vms/103.json',record)
    observation={'running':True,'config':dict(proxmox._base(spec),agent='enabled=1,freeze-fs=0',scsi0='local-lvm:vm-103-disk-0,size=8G',ide2='local:iso/seed.iso,media=cdrom',serial0='socket',vga='serial0'),'boot_id':'e'*64}
    monkeypatch.setattr(guests,'_observe',lambda record,runner:observation)
    return observation


def test_private_guest_transport_has_fixed_argv_and_stdin(tmp_path,site,monkeypatch):
    owned(tmp_path,site,monkeypatch);runner=GuestTools()
    reply=guests.guest_call(103,req(),runner,state=tmp_path)
    assert reply['phase']=='complete'
    assert 'synthetic-private-key' not in json.dumps(runner.calls)
    assert json.loads(runner.inputs[0])==req()
    assert runner.calls[0]==['/usr/sbin/qm','guest','exec','103','--pass-stdin','1','--synchronous','0','--','/usr/lib/rdc-guest/helper']


def test_foreign_vm_or_missing_agent_cannot_receive_secrets(tmp_path,site,monkeypatch):
    observation=owned(tmp_path,site,monkeypatch);runner=GuestTools()
    for key,value in [('description','foreign'),('agent','0')]:
        original=observation['config'][key];observation['config'][key]=value
        with pytest.raises(ApplianceError):guests.guest_call(103,req(),runner,state=tmp_path)
        observation['config'][key]=original
    assert runner.calls==[]


def test_timeout_records_unknown_outcome_without_resubmission(tmp_path,site,monkeypatch):
    owned(tmp_path,site,monkeypatch);runner=GuestTools();runner.lose=True
    assert guests.guest_call(103,req(),runner,state=tmp_path)['phase']=='pending'
    runner.lose=False
    assert guests.guest_call(103,req(),runner,state=tmp_path)['phase']=='pending'
    assert len(runner.calls)==1
    assert 'synthetic-private-key' not in ''.join(p.read_text() for p in tmp_path.rglob('*.json'))


def test_guest_transport_rejects_oversized_request_and_reply(tmp_path,site,monkeypatch):
    with pytest.raises(ApplianceError,match='guest-request-too-large'):guests.encode_request(dict(req(),parameters={'large':'a'*600000}))
    owned(tmp_path,site,monkeypatch);runner=GuestTools();runner.large=True
    with pytest.raises(ApplianceError,match='guest-response-too-large'):guests.guest_call(103,req(),runner,state=tmp_path)


def test_reply_binding_is_required(tmp_path,site,monkeypatch):
    owned(tmp_path,site,monkeypatch);runner=GuestTools();runner.bad=True
    with pytest.raises(ApplianceError,match='guest-reply-binding'):guests.guest_call(103,req(),runner,state=tmp_path)


def test_role_seed_has_one_static_nic_no_credentials_and_no_ssh(site):
    site=role_site(site);files=guests.seed_files(site,'connector');raw=b''.join(files.values())
    user=json.loads(files['user-data'].split(b'\n',1)[1]);net=json.loads(files['network-config'])
    assert user['users']==[] and user['disable_root'] and not user['ssh_pwauth']
    assert len(net['ethernets'])==1 and net['ethernets']['role0']['dhcp4'] is False
    assert b'authorization' not in raw and b'auth-key' not in raw
    assert 'ssh.service' in json.dumps(user)
    assert net['ethernets']['role0']['addresses']==['10.77.1.10/24']


def test_unbuilt_image_cannot_provision(site,tmp_path,release):
    site=role_site(site);runner=GuestTools()
    with pytest.raises(ApplianceError,match='role-image-not-built'):
        guests.provision_linux(site,'connector',runner,tmp_path,release=release,inputs=tmp_path)
    assert runner.calls==[]


def test_duplicate_machine_identity_is_rejected_before_use(tmp_path):
    reply={'observations':{'machine_id':'1'*32}}
    guests._remember_machine(103,reply,tmp_path)
    with pytest.raises(ApplianceError,match='guest-machine-identity-duplicate'):
        guests._remember_machine(104,reply,tmp_path)
    with pytest.raises(ApplianceError,match='guest-machine-identity-changed'):
        guests._remember_machine(103,{'observations':{'machine_id':'2'*32}},tmp_path)


def test_runtime_binding_requires_exact_network_and_image(site,tmp_path,monkeypatch):
    site=role_site(site);spec=proxmox.vm_spec(site,'connector')
    monkeypatch.setattr(guests,'receipt',lambda *a,**k:{'spec':spec,'image_recipe_id':'b'*64})
    monkeypatch.setattr(guests,'_observe',lambda *a,**k:{'boot_id':'c'*64})
    runtime={'image':{'schema':1,'recipe_id':'b'*64,'versions':{'tailscale':'1.104.1'}},'forwarding':False,'ipv6_disabled':True,'ssh_masked':True,
      'addresses':[{'ifname':'lo','address':'00:00:00:00:00:00','addr_info':[]},{'ifname':'role0','address':'02:bb:00:00:00:06','addr_info':[{'family':'inet','local':'10.77.1.10','prefixlen':24}]}],
      'routes':[{'dst':'default','gateway':'10.77.1.1','dev':'role0'}]}
    reply={'operation_id':'x','phase':'complete','code':'ok','observations':{'machine_id':'1'*32,'boot_id':'11111111-1111-1111-1111-111111111111','plan_id':identity(site),'role':'connector','runtime':runtime}}
    monkeypatch.setattr(guests,'guest_call',lambda *a,**k:reply)
    assert guests.inspect_runtime(site,'connector',None,tmp_path)['phase']=='complete'
    runtime['addresses'].append({'ifname':'rogue0','address':'02:00:00:00:00:01','addr_info':[]})
    with pytest.raises(ApplianceError,match='guest-runtime-network'):guests.inspect_runtime(site,'connector',None,tmp_path)
    runtime['addresses'].pop();runtime['image']['recipe_id']='c'*64
    with pytest.raises(ApplianceError,match='guest-runtime-image'):guests.inspect_runtime(site,'connector',None,tmp_path)


def test_role_static_network_configures_before_host_attaches_carrier(site):
    network=json.loads(guests.seed_files(role_site(site),'connector')['network-config'])
    nic=network['ethernets']['role0']
    assert nic['ignore-carrier'] is True
    assert nic['dhcp4'] is False and nic['routes']==[{'to':'0.0.0.0/0','via':'10.77.1.1'}]

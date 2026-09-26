import copy
import importlib
import json
from pathlib import Path
import sys
import pytest
from test_connectivity import answers

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))


def setup():
    p=importlib.import_module('connectivity_plan').record(answers())
    m=importlib.import_module('connectivity_provision')
    return m,p,m.settings(p,300,'192.168.50.2')


class API:
    def __init__(self):
        self.calls=[];self.configs={};self.version='9.2.20';self.space=10**12
        self.bridges=[{'iface':f'vmbr{i}','type':'bridge','active':1} for i in range(4)]
        self.bridges[1]['address']='192.168.50.2'
        self.running=False;self.memory=64*1024**3;self.fail=None
    def request(self,method,path,data=None):
        self.calls.append((method,path,copy.deepcopy(data)))
        if path=='/version':return {'version':self.version}
        if path.endswith('/network'):return self.bridges
        if path=='/cluster/resources?type=vm':return [{'vmid':i,'node':'pve','type':'qemu'} for i in self.configs]
        if '/tasks/' in path:return {'status':'stopped','exitstatus':'OK'}
        if path=='/nodes/pve/storage/local-lvm/status':return {'active':1,'enabled':1,'avail':self.space,'content':'images','type':'lvmthin'}
        if path=='/nodes/pve/status':return {'memory':{'free':self.memory}}
        if path.endswith('/config'):return self.configs[int(path.split('/')[-2])]
        if path.endswith('/status/current'):return {'status':'running' if self.running else 'stopped'}
        if method=='POST':
            assert path=='/nodes/pve/qemu'
            if self.fail=='before':raise ValueError('Uncertain request')
            cfg=dict(data);vmid=cfg.pop('vmid')
            cfg['scsi0']=f"local-lvm:vm-{vmid}-disk-0,size={cfg['scsi0'].split(':')[1]}G"
            self.configs[vmid]=cfg
            if self.fail=='after':raise ValueError('Uncertain response')
            return 'UPID:pve:example'
        raise AssertionError((method,path))


def test_role_selection_creates_only_local_connectivity_shells():
    m,p,c=setup();payloads=m.payloads(p,c)
    assert len(payloads)==5
    assert [x['vmid'] for x in payloads]==[300,301,302,303,304]
    assert all(x['start']==0 and x['onboot']==0 for x in payloads)
    assert all('link_down=1' in value for x in payloads for key,value in x.items() if key.startswith('net'))
    assert len([k for k in payloads[0] if k.startswith('net')])==4
    assert payloads[2]['net0']=='virtio,bridge=vmbr3,link_down=1'
    assert 'institution-controller' in payloads[-1]['name']
    assert not any(term in x['name'] for x in payloads for term in ('matrix','nextcloud','backup'))
    a=answers()
    for role in ('institution_controller','institution_relay','partner_controller','partner_relay'):a[role+'_placement']='local'
    all_local=importlib.import_module('connectivity_plan').record(a)
    assert len(m.payloads(all_local,m.settings(all_local,300,'192.168.50.2')))==8


@pytest.mark.parametrize('first,address',[(True,'192.168.50.2'),(99,'192.168.50.2'),(999999998,'192.168.50.2'),(300,'bad'),(300,'127.0.0.1')])
def test_invalid_provisioning_settings_rejected(first,address):
    m,p,c=setup()
    with pytest.raises(ValueError):m.settings(p,first,address)


def test_check_is_read_only_and_reports_observed_limits():
    m,p,c=setup();api=API();r=m.check(p,c,api)
    assert r['state']=='ready-for-shell-allocation'
    assert r['missing_vm_ids']==[300,301,302,303,304]
    assert r['management_address_observed'] is True
    assert r['independent_console_verified'] is False
    assert all(call[0]=='GET' for call in api.calls)


@pytest.mark.parametrize('fault',['bridge-hidden','bridge-inactive','wan-address','management-address','space','memory','infinite-space','foreign-vm','version','malformed'])
def test_preflight_blocks_all_mutations(fault):
    m,p,c=setup();api=API()
    if fault=='bridge-hidden':api.bridges.pop()
    if fault=='bridge-inactive':api.bridges[2]['active']=0
    if fault=='wan-address':api.bridges[0]['address']='192.0.2.1'
    if fault=='management-address':api.bridges[1]['address']='192.168.50.3'
    if fault=='space':api.space=0
    if fault=='memory':api.memory=0
    if fault=='infinite-space':api.space=float('inf')
    if fault=='foreign-vm':api.configs[300]={'description':'foreign'}
    if fault=='version':api.version='8.4'
    if fault=='malformed':api.bridges={}
    journal=m.journal(p,c)
    with pytest.raises(ValueError) as error:m.allocate(p,c,api,journal,lambda _:None)
    if fault=='bridge-hidden':assert 'SDN.Use' in str(error.value)
    assert not any(call[0]=='POST' for call in api.calls)


def test_allocate_reconciles_owned_stopped_shells_without_recreating():
    m,p,c=setup();api=API();j=m.journal(p,c);saved=[]
    r=m.allocate(p,c,api,j,lambda value:saved.append(copy.deepcopy(value)))
    assert r['state']=='shells-allocated' and r['guest_installation']=='not-performed'
    assert saved[0]['vms']['300']['state']=='intent'
    assert saved[1]['vms']['300']['state']=='task'
    assert all(entry['state']=='verified' for entry in j['vms'].values())
    assert len([call for call in api.calls if call[0]=='POST'])==5
    m.allocate(p,c,api,j,lambda _:None)
    assert len([call for call in api.calls if call[0]=='POST'])==5


def test_lost_response_is_reconciled_only_when_shell_is_observed():
    m,p,c=setup();api=API();api.fail='after';j=m.journal(p,c)
    with pytest.raises(ValueError):m.allocate(p,c,api,j,lambda _:None)
    assert j['vms']['300']['state']=='intent'
    api.fail=None
    m.allocate(p,c,api,j,lambda _:None)
    assert len([call for call in api.calls if call[0]=='POST'])==5


def test_unobserved_uncertain_request_is_never_replayed():
    m,p,c=setup();api=API();api.fail='before';j=m.journal(p,c)
    with pytest.raises(ValueError):m.allocate(p,c,api,j,lambda _:None)
    api.fail=None
    with pytest.raises(ValueError,match='unresolved'):m.allocate(p,c,api,j,lambda _:None)
    assert len([call for call in api.calls if call[0]=='POST'])==1


def test_changed_plan_or_running_shell_cannot_be_adopted():
    m,p,c=setup();api=API();j=m.journal(p,c)
    m.allocate(p,c,api,j,lambda _:None);before=len(api.calls);api.running=True
    with pytest.raises(ValueError):m.allocate(p,c,api,j,lambda _:None)
    assert not any(call[0]=='POST' for call in api.calls[before:])
    a=answers();a['site']='tartu';other=importlib.import_module('connectivity_plan').record(a)
    with pytest.raises(ValueError):m.payloads(other,c)


def test_intent_write_failure_prevents_remote_creation():
    m,p,c=setup();api=API();j=m.journal(p,c)
    def failed(_):raise OSError('disk full')
    with pytest.raises(OSError):m.allocate(p,c,api,j,failed)
    assert not any(call[0]=='POST' for call in api.calls)


def test_operation_menu_exit_and_rejected_confirmation_make_no_api_calls(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');state.save(tmp_path/'site',p)
    menu=importlib.import_module('connectivity_operations').menu
    def forbidden(*args):raise AssertionError('must not connect')
    output=[];replies=iter(['allocate','300','192.168.50.2','NO','exit'])
    result=menu(tmp_path/'site',p,input_fn=lambda _:next(replies),output_fn=output.append,api_factory=forbidden)
    assert result['state']=='prepared'
    assert not (tmp_path/'site/provisioning').exists()
    assert any('disconnected' in line for line in output)


def test_menu_explicit_allocation_records_checkpoint_without_tokens(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');state.save(tmp_path/'site',p)
    auth=tmp_path/'auth.json';auth.write_text(json.dumps({'token_id':'user@pve!rdc','token_secret':'SECRET'}));auth.chmod(0o600)
    api=API();out=[]
    replies=iter(['allocate','300','192.168.50.2','ALLOCATE',str(auth),'','exit'])
    result=importlib.import_module('connectivity_operations').menu(tmp_path/'site',p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=lambda *args:api)
    assert result['state']=='prepared'
    j=json.loads((tmp_path/'site/provisioning/journal.json').read_text())
    assert j['last']['outcome']=='shells-allocated'
    assert 'SECRET' not in json.dumps(j)+'\n'.join(out)
    assert any('Choose opnsense' in line for line in out)
    assert state.load(tmp_path/'site/connectivity.json')==p


def test_settings_can_change_after_check_but_not_after_creation(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p);api=API()
    ops.run(folder,p,c,'check',api)
    changed=m.settings(p,400,'192.168.50.2')
    assert ops.run(folder,p,changed,'check',api)['missing_vm_ids']==[400,401,402,403,404]
    ops.run(folder,p,changed,'allocate',api)
    before=len(api.calls)
    with pytest.raises(ValueError):ops.run(folder,p,c,'allocate',api)
    assert len(api.calls)==before


def test_very_large_capacity_response_is_rejected_cleanly():
    m,p,c=setup();api=API();api.space=10**400
    with pytest.raises(ValueError):m.check(p,c,api)


def test_known_task_is_polled_before_locked_shell_inspection():
    m,p,c=setup();api=API();j=m.journal(p,c)
    j['vms']['300']={'state':'task','upid':'UPID:pve:pending'}
    original=api.request
    def pending(method,path,data=None):
        if '/tasks/' in path and not api.configs:
            original('POST','/nodes/pve/qemu',m.payloads(p,c)[0])
        return original(method,path,data)
    api.request=pending
    m.allocate(p,c,api,j,lambda _:None)
    assert len([call for call in api.calls if call[0]=='POST'])==5


def test_menu_can_preview_new_settings_without_contacting_host(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p);ops.run(folder,p,c,'check',API())
    before=(folder/'provisioning/settings.json').read_bytes();out=[]
    replies=iter(['settings','400','192.168.50.2','exit'])
    ops.menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=lambda *args:pytest.fail('no network'))
    assert any('400 opnsense' in line for line in out)
    assert (folder/'provisioning/settings.json').read_bytes()==before


def test_any_unresolved_record_blocks_new_allocations_before_first_post():
    m,p,c=setup();api=API();j=m.journal(p,c)
    j['vms']['304']={'state':'intent','upid':None}
    with pytest.raises(ValueError,match='unresolved'):m.allocate(p,c,api,j,lambda _:None)
    assert not any(call[0]=='POST' for call in api.calls)


def test_read_only_check_does_not_forget_a_failed_creation_task(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p);api=API()
    ops.run(folder,p,c,'check',api)
    api.request('POST','/nodes/pve/qemu',m.payloads(p,c)[0])
    journal_path=folder/'provisioning/journal.json';data=json.loads(journal_path.read_text())
    data['vms']['300']={'state':'task','upid':'UPID:pve:failed'}
    importlib.import_module('portable_state').write(journal_path,data)
    original=api.request
    def failed(method,path,payload=None):
        if '/tasks/' in path:return {'status':'stopped','exitstatus':'ERROR'}
        return original(method,path,payload)
    api.request=failed
    with pytest.raises(ValueError):ops.run(folder,p,c,'check',api)
    assert json.loads(journal_path.read_text())['vms']['300']['state']=='task'


def test_runtime_refuses_changed_plan_before_contacting_api(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p)
    a=answers();a['site']='tartu';new=importlib.import_module('connectivity_plan').record(a)
    state.save(folder,new,expected=p);api=API()
    with pytest.raises(ValueError):ops.run(folder,p,c,'allocate',api)
    assert api.calls==[]


def test_invalid_vm_id_input_is_not_echoed(tmp_path):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p);out=[];replies=iter(['preview','SECRET','exit'])
    ops.menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=lambda *args:pytest.fail('no connection'))
    assert 'SECRET' not in '\n'.join(out)


@pytest.mark.parametrize('fault',['missing','dangling-symlink'])
def test_missing_or_symlinked_journal_cannot_reset_allocation_history(tmp_path,fault):
    m,p,c=setup();state=importlib.import_module('connectivity_state');ops=importlib.import_module('connectivity_operations')
    folder=tmp_path/'site';state.save(folder,p);api=API()
    ops.run(folder,p,c,'allocate',api)
    path=folder/'provisioning/journal.json';path.unlink()
    if fault=='dangling-symlink':path.symlink_to(folder/'does-not-exist')
    api.configs={};api.calls=[]
    with pytest.raises(ValueError):ops.run(folder,p,c,'allocate',api)
    assert api.calls==[]


def test_allocation_cannot_succeed_when_final_inspection_loses_a_shell():
    m,p,c=setup();api=API();request=api.request;reads=0
    def disappearing(method,path,data=None):
        nonlocal reads
        if path=='/cluster/resources?type=vm':
            reads+=1
            if reads==2:api.configs.pop(300)
        return request(method,path,data)
    api.request=disappearing
    with pytest.raises(ValueError,match='missing'):
        m.allocate(p,c,api,m.journal(p,c),lambda _:None)


def test_completed_task_ids_survive_allocate_resume_and_read_only_check(tmp_path):
    m,p,c=setup();api=API();state=importlib.import_module('connectivity_state')
    ops=importlib.import_module('connectivity_operations');folder=tmp_path/'site';state.save(folder,p)
    for verb in ('allocate','allocate','check'):
        ops.run(folder,p,c,verb,api)
        data=json.loads((folder/'provisioning/journal.json').read_text())
        assert all(entry=={'state':'verified','upid':'UPID:pve:example'} for entry in data['vms'].values())

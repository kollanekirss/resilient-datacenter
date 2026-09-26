"""Connectivity guest lifecycle: isolated edge, durable requests, honest evidence."""
import copy
import importlib
import json
from pathlib import Path
import pytest
from test_connectivity_provision import API, setup


class EdgeAPI(API):
    def __init__(self):
        super().__init__();self.power='stopped';self.media=[];self.mutations=[];self.fault=None;self.task_ok=True
    def request(self,method,path,data=None):
        if method=='POST' and (path.endswith('/config') or path.endswith('/status/start')):
            self.mutations.append((path,copy.deepcopy(data)))
            if self.fault=='before':raise ValueError('Uncertain outcome')
            if path.endswith('/config'):
                assert data['digest']=='a'*40
                cfg=self.configs[300]
                for k,v in data.items():
                    if k=='delete':cfg.pop(v,None)
                    elif k!='digest':cfg[k]=v
            else:self.power='running'
            if self.fault=='after':raise ValueError('Uncertain outcome')
            return 'UPID:pve:guest-task'
        if '/tasks/' in path:return {'status':'stopped','exitstatus':'OK' if self.task_ok else 'ERROR'}
        if path.endswith('/qemu/300/pending'):return [{'key':key,'value':value} for key,value in self.configs[300].items()]
        if path.endswith('/qemu/300/config') or path.endswith('/qemu/300/config?current=1'):
            return dict(self.configs[300],digest='a'*40)
        if path.endswith('/qemu/300/status/current'):return {'status':self.power}
        if path.endswith('/storage/local/status'):return {'active':1,'enabled':1,'content':'iso','avail':10**10}
        if path.endswith('/storage/local/content'):return self.media
        return super().request(method,path,data)
    def upload(self,node,storage,filename,stream,size,sha256):
        self.mutations.append(('upload',filename));assert stream.read()==b'iso'
        if self.fault=='before':raise ValueError('Uncertain upload')
        self.media.append({'volid':storage+':iso/'+filename,'size':size})
        if self.fault=='after':raise ValueError('Uncertain upload')
        return 'UPID:pve:upload-task'


@pytest.fixture
def edge(tmp_path,monkeypatch):
    m,p,c=setup();api=EdgeAPI();folder=tmp_path/'site'
    importlib.import_module('connectivity_state').save(folder,p)
    importlib.import_module('connectivity_operations').run(folder,p,c,'allocate',api)
    media=importlib.import_module('guest_media')
    item=media.catalogue()['opnsense']
    record={'kind':'opnsense','version':item['version'],'source_sha256':item['sha256'],
            'sha256':'b'*64,'size':3,'filename':'opnsense.iso'}
    def prepare(kind,cache):
        cache.mkdir(mode=0o700,exist_ok=True)
        target=cache/'opnsense.iso';target.write_bytes(b'iso');target.chmod(0o600)
        return dict(record)
    monkeypatch.setattr(media,'prepare',prepare)
    monkeypatch.setattr(media,'verify',lambda cache,kind:dict(record))
    e=importlib.import_module('connectivity_edge')
    return e,folder,p,c,api


def act(edge,action,**kwargs):
    e,folder,p,c,api=edge
    return e.run(folder,p,action,api=api,**kwargs)


def through(edge,last):
    for action in ('prepare','upload','attach','start'):
        act(edge,action,**({'storage':'local'} if action=='upload' else {}))
        if action==last:return


def test_full_guided_installation_keeps_network_disconnected_and_evidence_honest(edge):
    e,folder,p,c,api=edge
    through(edge,'start');api.power='stopped'
    act(edge,'finish',operator='Lab operator')
    act(edge,'boot')
    result=act(edge,'confirm',operator='Lab operator',version='26.7')
    assert result['phase']=='installed-attested'
    assert result['os_verification']=='operator-attested'
    assert result['observed']['boot']=='disk-only'
    assert result['network_links']=='disconnected'
    assert api.configs[300]['boot']=='order=scsi0' and 'ide2' not in api.configs[300]
    assert all('link_down=1' in value for key,value in api.configs[300].items() if key.startswith('net'))
    state=json.loads((folder/'provisioning/edge.json').read_text())
    assert set(state['tasks'])=={'upload','attach','start','finish','boot'}
    assert all(value.startswith('UPID:') for value in state['tasks'].values())
    assert state['attestation']['version']=='26.7'
    before=len(api.mutations);act(edge,'status');act(edge,'confirm',operator='Lab operator',version='26.7')
    assert len(api.mutations)==before


@pytest.mark.parametrize('action',['attach','start','finish','boot','confirm'])
def test_steps_cannot_be_skipped(edge,action):
    with pytest.raises(ValueError):act(edge,action,operator='Operator',version='26.7')
    assert not edge[-1].mutations


@pytest.mark.parametrize('action,previous',[('attach','upload'),('start','attach')])
@pytest.mark.parametrize('fault',['before','after'])
def test_unknown_guest_requests_reconcile_observed_result_only(edge,action,previous,fault):
    through(edge,previous);api=edge[-1];api.fault=fault
    with pytest.raises(ValueError):act(edge,action)
    count=len(api.mutations);api.fault=None
    if fault=='after':act(edge,action)
    else:
        with pytest.raises(ValueError,match='uncertain|unresolved'):act(edge,action)
    assert len(api.mutations)==count


def test_unknown_upload_is_never_replayed_even_when_name_and_size_match(edge):
    act(edge,'prepare');api=edge[-1];api.fault='after'
    with pytest.raises(ValueError):act(edge,'upload',storage='local')
    api.fault=None;count=len(api.mutations)
    with pytest.raises(ValueError,match='uncertain|unresolved'):act(edge,'upload',storage='local')
    assert len(api.mutations)==count


def test_failed_task_cannot_be_hidden_by_matching_configuration(edge):
    through(edge,'upload');api=edge[-1];api.task_ok=False
    with pytest.raises(ValueError):act(edge,'attach')
    count=len(api.mutations)
    with pytest.raises(ValueError):act(edge,'attach')
    assert len(api.mutations)==count


@pytest.mark.parametrize('change',['link','disk','owner'])
def test_unexpected_guest_changes_block_mutation(edge,change):
    through(edge,'upload');api=edge[-1]
    if change=='link':api.configs[300]['net0']=api.configs[300]['net0'].replace('link_down=1','link_down=0')
    if change=='disk':api.configs[300]['scsi1']='local-lvm:vm-300-disk-1,size=20G'
    if change=='owner':api.configs[300]['description']='foreign'
    count=len(api.mutations)
    with pytest.raises(ValueError):act(edge,'attach')
    assert len(api.mutations)==count


def test_running_installer_cannot_be_finished_or_attested(edge):
    through(edge,'start')
    with pytest.raises(ValueError,match='shut down|stopped'):act(edge,'finish',operator='Operator')
    with pytest.raises(ValueError):act(edge,'confirm',operator='Operator',version='26.7')


def test_missing_guest_journal_does_not_reset_history(edge):
    through(edge,'upload');e,folder,p,c,api=edge
    (folder/'provisioning/edge.json').unlink();count=len(api.mutations)
    with pytest.raises(ValueError,match='missing'):act(edge,'prepare')
    assert len(api.mutations)==count


def test_allocator_directs_to_guest_checkpoint_after_guest_stage_begins(edge):
    act(edge,'prepare');e,folder,p,c,api=edge
    with pytest.raises(ValueError,match='OPNsense|guest'):
        importlib.import_module('connectivity_operations').run(folder,p,c,'allocate',api)


def test_stale_plan_and_incomplete_allocation_block_media_preparation(edge,monkeypatch):
    e,folder,p,c,api=edge;bad=copy.deepcopy(p);bad['revision']='f'*64
    with pytest.raises(ValueError):e.run(folder,bad,'prepare')
    path=folder/'provisioning/journal.json';data=json.loads(path.read_text());data['vms']['300']['state']='intent';data['vms']['300']['upid']=None
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):act(edge,'prepare')


def test_intent_write_failure_prevents_remote_mutation(edge,monkeypatch):
    through(edge,'upload');e,folder,p,c,api=edge;count=len(api.mutations)
    def failed(*args):raise OSError('disk full')
    monkeypatch.setattr(e,'write',failed)
    with pytest.raises(ValueError):act(edge,'attach')
    assert len(api.mutations)==count


def test_confirm_requires_observed_version_from_pinned_release(edge):
    through(edge,'start');edge[-1].power='stopped';act(edge,'finish',operator='Operator');act(edge,'boot')
    with pytest.raises(ValueError):act(edge,'confirm',operator='Operator',version='25.7')


def test_opnsense_menu_exits_without_credentials_or_downloads(edge,monkeypatch):
    e,folder,p,c,api=edge;ui=importlib.import_module('connectivity_edge_ui');out=[]
    def forbidden(*args,**kwargs):raise AssertionError('no external action authorized')
    monkeypatch.setattr(e.guest_media,'prepare',forbidden)
    replies=iter(['prepare','NO','exit'])
    ui.menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=forbidden)
    assert not (folder/'provisioning/edge.json').exists()
    assert any('disconnected' in line for line in out)


def test_main_menu_exposes_opnsense_without_changing_allocation_settings(edge,monkeypatch):
    e,folder,p,c,api=edge;ui=importlib.import_module('connectivity_edge_ui');calls=[]
    monkeypatch.setattr(ui,'menu',lambda *args,**kwargs:calls.append(args))
    replies=iter(['opnsense','exit'])
    importlib.import_module('connectivity_operations').menu(folder,p,input_fn=lambda _:next(replies),output_fn=lambda _:None)
    assert len(calls)==1 and calls[0][:2]==(folder,p)


def test_menu_prints_installer_instructions_and_truthful_checkpoint(edge):
    e,folder,p,c,api=edge;through(edge,'attach');ui=importlib.import_module('connectivity_edge_ui')
    auth=folder/'token.json';auth.write_text(json.dumps({'token_id':'test@pve!rdc','token_secret':'SECRET'}));auth.chmod(0o600)
    replies=iter(['start','START',str(auth),'','exit']);out=[]
    ui.menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=lambda *args:api)
    assert any('installer' in line and 'opnsense' in line for line in out)
    assert any('operator' in line.lower() and 'console' in line.lower() for line in out)
    assert any('not verified' in line.lower() for line in out)
    assert not any('SECRET' in line for line in out)


def test_confirmed_prepare_never_requests_api_credentials(edge):
    e,folder,p,c,api=edge;ui=importlib.import_module('connectivity_edge_ui');out=[]
    replies=iter(['prepare','PREPARE','exit'])
    def forbidden(*args):raise AssertionError('local preparation must not create API client')
    ui.menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append,api_factory=forbidden)
    assert json.loads((folder/'provisioning/edge.json').read_text())['phase']=='media-ready'


@pytest.mark.parametrize('action',['finish','boot'])
@pytest.mark.parametrize('fault',['before','after'])
def test_unknown_finish_and_disk_boot_never_replay(edge,action,fault):
    through(edge,'start');api=edge[-1];api.power='stopped'
    if action=='boot':act(edge,'finish',operator='Operator')
    api.fault=fault
    with pytest.raises(ValueError):act(edge,action,operator='Operator')
    count=len(api.mutations);api.fault=None
    if fault=='after':act(edge,action,operator='Operator')
    else:
        with pytest.raises(ValueError,match='uncertain|unresolved'):act(edge,action,operator='Operator')
    assert len(api.mutations)==count


def test_symlinked_guest_journal_fails_before_api_use(edge,tmp_path):
    act(edge,'prepare');e,folder,p,c,api=edge;path=folder/'provisioning/edge.json'
    target=tmp_path/'other.json';path.rename(target);path.symlink_to(target)
    before=len(api.mutations)
    with pytest.raises(ValueError):act(edge,'upload',storage='local')
    assert len(api.mutations)==before


def test_installed_guest_cannot_be_reinstalled(edge):
    through(edge,'start');edge[-1].power='stopped';act(edge,'finish',operator='Operator');act(edge,'boot')
    act(edge,'confirm',operator='Operator',version='26.7')
    count=len(edge[-1].mutations)
    for action in ('prepare','upload','attach','start','finish'):
        with pytest.raises(ValueError):act(edge,action,operator='Operator',storage='local')
    assert len(edge[-1].mutations)==count


def test_guest_status_is_observation_not_a_fresh_installation_claim(edge):
    through(edge,'start');edge[-1].power='stopped';act(edge,'finish',operator='Operator');act(edge,'boot')
    act(edge,'confirm',operator='Operator',version='26.7');edge[-1].power='stopped'
    out=[];ui=importlib.import_module('connectivity_edge_ui')
    ui.checkpoint(act(edge,'status'),out.append)
    assert any('historical' in line.lower() for line in out)
    assert any('stopped' in line for line in out)


def test_unallocated_main_menu_guest_choice_returns_explanation(tmp_path):
    _,p,_=setup();folder=tmp_path/'site';importlib.import_module('connectivity_state').save(folder,p)
    replies=iter(['opnsense','exit']);out=[]
    result=importlib.import_module('connectivity_operations').menu(folder,p,input_fn=lambda _:next(replies),output_fn=out.append)
    assert result['state']=='prepared'
    assert any('Allocate' in line for line in out)


@pytest.mark.parametrize('pending',[{'key':'net0','value':'unsafe','pending':'safe'}, {'key':'ide2','value':'iso','delete':1}])
def test_pending_configuration_cannot_mask_active_devices(edge,pending):
    through(edge,'start');api=edge[-1];request=api.request
    def response(method,path,data=None):
        if path.endswith('/pending'):return [pending]
        return request(method,path,data)
    api.request=response
    with pytest.raises(ValueError,match='pending'):act(edge,'status')


def test_guest_observations_read_current_configuration(edge):
    through(edge,'start');api=edge[-1];request=api.request;seen=[]
    def response(method,path,data=None):
        seen.append(path)
        if path.endswith('/config?current=1'):
            config=request(method,path,data);config['net0']=config['net0'].replace('link_down=1','link_down=0');return config
        return request(method,path,data)
    api.request=response
    with pytest.raises(ValueError):act(edge,'status')
    assert '/nodes/pve/qemu/300/config?current=1' in seen

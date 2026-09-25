import copy
import importlib
import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from test_proxmox_provision import Fake, plan


class GuestAPI(Fake):
    def __init__(self):
        super().__init__();self.states={};self.fail_start=False
    def request(self,method,path,data=None):
        if method=='GET' and path.endswith('/status/current'):
            return {'status':self.states.get(int(path.split('/')[-3]),'stopped')}
        if method=='POST' and path.endswith('/config'):
            self.calls.append((method,path,copy.deepcopy(data)));vmid=int(path.split('/')[-2]);cfg=self.configs[vmid]
            assert data['digest']==cfg['digest']
            for key,value in data.items():
                if key=='digest':continue
                if key=='delete':cfg.pop(value,None)
                else:cfg[key]=value
            return None
        if method=='POST' and path.endswith('/status/start'):
            self.calls.append((method,path,copy.deepcopy(data)))
            if self.fail_start:raise ValueError('Uncertain request')
            self.states[int(path.split('/')[-3])]='running';return 'UPID:pve:start'
        return super().request(method,path,data)


def setup():
    import proxmox_provision
    api=GuestAPI();proxmox_provision.allocate(plan(),api)
    for cfg in api.configs.values():cfg['digest']='a'*40
    api.calls=[]
    return api


def media():return {'kind':'opnsense','volume':'local:iso/rdc-test.iso','sha256':'1'*64,'size':100}


def test_guest_installation_separates_attestation_from_boot(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    m.attach(plan(),'edge',media(),api,folder)
    assert api.configs[201]['boot']=='order=ide2;scsi0'
    assert m.start(plan(),'edge',media(),api,folder)['phase']=='installer-start-requested'
    api.states[201]='stopped'
    result=m.finish(plan(),'edge',media(),api,folder,operator='Alice')
    assert result['phase']=='disk-ready' and result['os_verification']=='operator-attested'
    assert 'ide2' not in api.configs[201] and api.configs[201]['boot']=='order=scsi0'
    result=m.boot(plan(),'edge',media(),api,folder)
    assert result['phase']=='disk-boot-observed'
    assert result['applications']=='not-installed'
    assert all('link_down=1' in value for key,value in api.configs[201].items() if key.startswith('net'))


def test_uncertain_installer_start_is_not_replayed(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    m.attach(plan(),'edge',media(),api,folder);api.fail_start=True
    with pytest.raises(ValueError):m.start(plan(),'edge',media(),api,folder)
    api.fail_start=False
    with pytest.raises(ValueError):m.start(plan(),'edge',media(),api,folder)
    assert len([c for c in api.calls if c[1].endswith('/status/start')])==1


@pytest.mark.parametrize('fault',['foreign','network','running','wrong_media'])
def test_guest_refuses_foreign_or_exposed_configuration(tmp_path,fault):
    m=importlib.import_module('guest_installation');api=setup();medium=media()
    if fault=='foreign':api.configs[201]['description']='other'
    if fault=='network':api.configs[201]['net0']='virtio,bridge=vmbr0'
    if fault=='running':api.states[201]='running'
    if fault=='wrong_media':medium['kind']='ubuntu'
    with pytest.raises(ValueError):m.attach(plan(),'edge',medium,api,tmp_path/'state')
    assert not any(c[0]=='POST' for c in api.calls)


def test_cannot_reinstall_after_disk_ready(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    m.attach(plan(),'edge',media(),api,folder);m.start(plan(),'edge',media(),api,folder)
    api.states[201]='stopped';m.finish(plan(),'edge',media(),api,folder,operator='Alice')
    api.calls=[]
    with pytest.raises(ValueError):m.start(plan(),'edge',media(),api,folder)
    with pytest.raises(ValueError):m.attach(plan(),'edge',media(),api,folder)
    assert not any(c[0]=='POST' for c in api.calls)


def test_console_login_attestation_requires_disk_only_running_guest(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    with pytest.raises(ValueError):m.confirm_login(plan(),'edge',media(),api,folder,operator='Alice')
    m.attach(plan(),'edge',media(),api,folder);m.start(plan(),'edge',media(),api,folder)
    api.states[201]='stopped';m.finish(plan(),'edge',media(),api,folder,operator='Alice')
    m.boot(plan(),'edge',media(),api,folder)
    assert m.confirm_login(plan(),'edge',media(),api,folder,operator='Alice')['phase']=='guest-installed-attested'
    api.states[201]='stopped'
    with pytest.raises(ValueError):m.confirm_login(plan(),'edge',media(),api,folder,operator='Alice')


def test_resumes_config_update_after_response_loss(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    original=api.request
    def lost(method,path,data=None):
        result=original(method,path,data)
        if method=='POST' and path.endswith('/config'):raise ValueError('Lost response')
        return result
    api.request=lost
    with pytest.raises(ValueError):m.attach(plan(),'edge',media(),api,folder)
    api.request=original
    assert m.attach(plan(),'edge',media(),api,folder)['phase']=='media-attached'
    assert len([c for c in api.calls if c[0]=='POST' and c[1].endswith('/config')])==1


def test_remote_drift_blocks_disk_start(tmp_path):
    m=importlib.import_module('guest_installation');api=setup();folder=tmp_path/'state'
    m.attach(plan(),'edge',media(),api,folder);m.start(plan(),'edge',media(),api,folder)
    api.states[201]='stopped';m.finish(plan(),'edge',media(),api,folder,operator='Alice');api.calls=[]
    api.configs[201]['net0']='virtio,bridge=vmbr0'
    with pytest.raises(ValueError):m.boot(plan(),'edge',media(),api,folder)
    assert not any(c[0]=='POST' for c in api.calls)


def test_corrupt_journal_is_rejected_without_mutation(tmp_path):
    from portable_state import directory,write
    m=importlib.import_module('guest_installation');api=setup();folder=directory(tmp_path/'state')
    bind=m.context(plan(),'edge',media())[3]
    write(folder/'edge.json',{'binding':bind})
    with pytest.raises(ValueError):m.attach(plan(),'edge',media(),api,folder)
    assert not any(c[0]=='POST' for c in api.calls)

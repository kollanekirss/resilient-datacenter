import copy
import importlib
import json
from pathlib import Path
import sys
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))


def plan():
    return json.loads((ROOT/'examples/portable-site.json').read_text())


class Fake:
    def __init__(self):
        self.calls = []; self.configs = {}; self.version = '9.1'; self.space = 10**12
        self.bridges = [{'iface': f'vmbr{i}', 'type':'bridge', 'active':1} for i in range(6)]
        self.fail_post = False
    def request(self, method, path, data=None):
        self.calls.append((method,path,copy.deepcopy(data)))
        if path == '/version': return {'version': self.version}
        if path == '/cluster/resources?type=vm':
            return [{'vmid':i,'node':'pve','type':'qemu'} for i in self.configs]
        if path.endswith('/network'): return self.bridges
        if path.endswith('/storage/local-lvm/status'):
            return {'active':1,'enabled':1,'avail':self.space,'content':'images','type':'lvmthin'}
        if path.endswith('/status') and '/tasks/' in path: return {'status':'stopped','exitstatus':'OK'}
        if path == '/nodes/pve/status': return {'memory':{'free':64*1024**3}}
        if path.endswith('/config'): return self.configs[int(path.split('/')[-2])]
        if path.endswith('/status/current'): return {'status':'stopped'}
        if method == 'POST':
            if self.fail_post: raise ValueError('Proxmox request failed; inspect task state before retrying.')
            cfg = dict(data); vmid = cfg.pop('vmid')
            disk = cfg['scsi0'].split(':')[1]
            cfg['scsi0'] = f'local-lvm:vm-{vmid}-disk-0,size={disk}G'
            self.configs[vmid] = cfg
            return 'UPID:pve:example'
        raise AssertionError((method,path))


def test_check_is_read_only_and_shells_are_disconnected():
    m = importlib.import_module('proxmox_provision'); api = Fake()
    result = m.check(plan(), api)
    assert result['state'] == 'ready-for-shell-allocation'
    assert all(c[0] == 'GET' for c in api.calls)
    payloads = m.payloads(plan())
    assert len(payloads) == 6
    edge = payloads[0]
    assert len([k for k in edge if k.startswith('net')]) == 6
    assert all('link_down=1' in value for p in payloads for key,value in p.items() if key.startswith('net'))
    assert all(p['onboot'] == 0 and p['start'] == 0 for p in payloads)


def test_allocate_then_retry_never_recreates_owned_shells():
    m = importlib.import_module('proxmox_provision'); api = Fake()
    assert m.allocate(plan(),api)['state'] == 'shells-allocated'
    assert len([c for c in api.calls if c[0]=='POST']) == 6
    assert m.allocate(plan(),api)['state'] == 'shells-allocated'
    assert len([c for c in api.calls if c[0]=='POST']) == 6


@pytest.mark.parametrize('fault', ['foreign','changed','extra_nic','version','space','bridge','wan_ip'])
def test_block_before_any_mutation(fault):
    m = importlib.import_module('proxmox_provision'); api = Fake()
    if fault == 'foreign': api.configs[201] = {'description':'somebody else'}
    if fault in ('changed','extra_nic'):
        m.allocate(plan(),api); api.calls=[]
        if fault == 'changed': api.configs[201]['memory']=65536
        else: api.configs[201]['net7']='virtio,bridge=vmbr0'
    if fault == 'version': api.version='8.4'
    if fault == 'space': api.space=0
    if fault == 'bridge': api.bridges.pop()
    if fault == 'wan_ip': api.bridges[0]['address']='192.0.2.1'
    with pytest.raises(ValueError): m.allocate(plan(),api)
    assert not any(c[0]=='POST' for c in api.calls)


def test_partial_allocation_can_be_resumed():
    m = importlib.import_module('proxmox_provision'); api = Fake(); original = api.request
    def interrupted(method,path,data=None):
        if method=='POST' and len(api.configs)==2: raise ValueError('Interrupted')
        return original(method,path,data)
    api.request = interrupted
    with pytest.raises(ValueError): m.allocate(plan(),api)
    assert len(api.configs)==2
    api.request=original
    assert m.allocate(plan(),api)['state']=='shells-allocated'
    assert len([c for c in api.calls if c[0]=='POST'])==6


def test_untrusted_credentials_file_rejected(tmp_path):
    m = importlib.import_module('proxmox_api'); path=tmp_path/'auth.json'
    path.write_text(json.dumps({'token_id':'user@pve!rdc','token_secret':'SECRET'}));path.chmod(0o644)
    with pytest.raises(ValueError) as error: m.credentials(path)
    assert 'SECRET' not in str(error.value)
    path.chmod(0o600)
    assert m.credentials(path)['token_secret']=='SECRET'


def test_failed_task_and_uncertain_post_are_not_retried():
    m = importlib.import_module('proxmox_provision'); api=Fake(); api.fail_post=True
    with pytest.raises(ValueError): m.allocate(plan(),api)
    assert len([c for c in api.calls if c[0]=='POST'])==1
    class Failed:
        def request(self,*args): return {'status':'stopped','exitstatus':'ERROR sensitive detail'}
    with pytest.raises(ValueError) as error: m.wait_task(Failed(),'pve','UPID:one')
    assert 'sensitive' not in str(error.value)


def test_task_timeout_is_bounded():
    m = importlib.import_module('proxmox_provision'); elapsed=[0]
    class Running:
        def request(self,*args): return {'status':'running'}
    def sleep(seconds): elapsed[0]+=seconds
    with pytest.raises(ValueError,match='unresolved'):
        m.wait_task(Running(),'pve','UPID:one',timeout=4,clock=lambda:elapsed[0],sleep=sleep)
    assert elapsed[0]==4


def test_transport_keeps_tls_and_refuses_redirects(monkeypatch):
    m = importlib.import_module('proxmox_api'); handlers=[]
    class Broken:
        calls=0
        def open(self,*args,**kwargs):
            self.calls+=1
            raise OSError('SECRET')
    broken=Broken()
    monkeypatch.setattr(m.urllib.request,'build_opener',lambda *items: handlers.extend(items) or broken)
    api=m.Client('https://pve.example.org:8006',{'token_id':'user@pve!rdc','token_secret':'SECRET'})
    tls=next(h for h in handlers if isinstance(h,m.urllib.request.HTTPSHandler))._context
    assert tls.check_hostname and tls.verify_mode==m.ssl.CERT_REQUIRED
    assert next(h for h in handlers if isinstance(h,m.urllib.request.ProxyHandler)).proxies=={}
    redirect=next(h for h in handlers if isinstance(h,m.NoRedirect))
    assert redirect.redirect_request(None,None,302,'',{},'https://other.example') is None
    with pytest.raises(ValueError) as error: api.request('POST','/nodes/pve/qemu',{'vmid':201})
    assert 'SECRET' not in str(error.value) and broken.calls==1


def test_cli_requires_private_credentials_before_network():
    import subprocess
    for action in ('check','allocate-shells'):
        result=subprocess.run([str(ROOT/'rdc'),'portable',action,str(ROOT/'examples/portable-site.json')],capture_output=True,text=True)
        assert result.returncode != 0
        assert 'token-file' in result.stdout

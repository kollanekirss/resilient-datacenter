import hashlib
import importlib
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from test_proxmox_provision import plan


class API:
    def __init__(self):self.calls=[];self.files=[]
    def request(self,method,path,data=None):
        self.calls.append((method,path,data))
        if path.endswith('/status') and '/tasks/' in path:return {'status':'stopped','exitstatus':'OK'}
        if path.endswith('/status'):return {'active':1,'enabled':1,'content':'iso','avail':10**10}
        if path.endswith('/content'):return self.files
        raise AssertionError(path)
    def upload(self,node,storage,filename,stream,size,sha):
        self.calls.append(('UPLOAD',filename,None));data=stream.read()
        assert len(data)==size and hashlib.sha256(data).hexdigest()==sha
        self.files.append({'volid':storage+':iso/'+filename,'size':size})
        return 'UPID:pve:upload'


def test_upload_and_resume_use_receipt_not_file_presence(tmp_path,monkeypatch):
    m=importlib.import_module('guest_upload');cache=tmp_path/'cache';cache.mkdir(mode=0o700)
    data=b'ISO';file=cache/'ubuntu.iso';file.write_bytes(data);file.chmod(0o600)
    record={'kind':'ubuntu','sha256':hashlib.sha256(data).hexdigest(),'size':3,'filename':'ubuntu.iso'}
    monkeypatch.setattr(m,'verify',lambda *_:record)
    api=API();folder=tmp_path/'state'
    first=m.upload(plan(),'ubuntu',cache,'local',api,folder)
    assert m.upload(plan(),'ubuntu',cache,'local',api,folder)==first
    assert len([c for c in api.calls if c[0]=='UPLOAD'])==1
    api.files=[]
    with pytest.raises(ValueError):m.receipt(plan(),'ubuntu',folder,api)


def test_upload_timeout_never_silently_reposts(tmp_path,monkeypatch):
    m=importlib.import_module('guest_upload');cache=tmp_path/'cache';cache.mkdir(mode=0o700)
    file=cache/'ubuntu.iso';file.write_bytes(b'ISO');file.chmod(0o600)
    monkeypatch.setattr(m,'verify',lambda *_:{'kind':'ubuntu','sha256':hashlib.sha256(b'ISO').hexdigest(),'size':3,'filename':'ubuntu.iso'})
    api=API()
    def fail(*_):api.calls.append(('UPLOAD','',None));raise ValueError('Uncertain')
    api.upload=fail
    with pytest.raises(ValueError):m.upload(plan(),'ubuntu',cache,'local',api,tmp_path/'state')
    with pytest.raises(ValueError):m.upload(plan(),'ubuntu',cache,'local',api,tmp_path/'state')
    assert len([c for c in api.calls if c[0]=='UPLOAD'])==1


def test_real_transport_streams_multipart_with_server_checksum(monkeypatch):
    import io
    import proxmox_api as m
    captured={}
    class Reply(io.BytesIO):
        def __enter__(self):return self
        def __exit__(self,*_):self.close()
    class Opener:
        def open(self,request,timeout):
            captured['request']=request;captured['body']=b''.join(request.data)
            return Reply(b'{"data":"UPID:pve:upload"}')
    monkeypatch.setattr(m.urllib.request,'build_opener',lambda *_:Opener())
    api=m.Client('https://pve.example.org:8006',{'token_id':'u@pve!rdc','token_secret':'secret'})
    sha=hashlib.sha256(b'ISO').hexdigest()
    assert api.upload('pve','local','rdc-abcdef.iso',io.BytesIO(b'ISO'),3,sha)=='UPID:pve:upload'
    assert len(captured['body'])==int(captured['request'].get_header('Content-length'))
    assert sha.encode() in captured['body'] and b'checksum-algorithm' in captured['body']
    assert b'filename="rdc-abcdef.iso"' in captured['body']
    assert b'secret' not in captured['body']

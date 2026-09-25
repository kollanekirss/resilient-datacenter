import hashlib
import importlib
import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))

def api(): return importlib.import_module('release_download')

def fixture():
    payload=b'not executed'
    files={'derper-linux-amd64':payload,'source.tar.gz':b'source','notices.tar.gz':b'notices','derper-build.json':b'{}'}
    manifest={'schema_version':1,'repository':'kollanekirss/resilient-datacenter','version':'0.2.0-alpha.1',
              'commit':'a'*40,'target':'linux/amd64','files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    files['release-manifest.json']=json.dumps(manifest).encode()
    return files

class Fake:
    def __init__(self,files,fail=False): self.files=files; self.fail=fail; self.verified=[]
    def download(self,tag,destination):
        for name,data in self.files.items(): (destination/name).write_bytes(data)
    def verify(self,path,tag,commit):
        self.verified.append((path.name,tag,commit))
        if self.fail: raise ValueError('untrusted')

def test_validated_release_is_published_only_after_all_attestations(tmp_path):
    f=Fake(fixture()); dest=tmp_path/'release'
    api().fetch('0.2.0-alpha.1','a'*40,dest,transport=f)
    assert set(p.name for p in dest.iterdir())==set(f.files)
    assert len(f.verified)==5
    assert not (dest/'derper-linux-amd64').stat().st_mode & 0o111

@pytest.mark.parametrize('version,commit',[('../../evil','a'*40),('0.2.0','a'*40),('0.2.0-alpha.1','main'),('--help','a'*40)])
def test_invalid_identity_does_not_download(tmp_path,version,commit):
    f=Fake(fixture())
    with pytest.raises(ValueError): api().fetch(version,commit,tmp_path/'out',transport=f)
    assert not list(tmp_path.iterdir())

@pytest.mark.parametrize('mode',['corrupt','wrong-commit','wrong-repo','extra','missing','wrong-target','unsafe-name','wrong-provenance'])
def test_invalid_release_never_publishes_partial_output(tmp_path,mode):
    files=fixture(); manifest=json.loads(files['release-manifest.json'])
    if mode=='corrupt': files['derper-linux-amd64']=b'corrupt'
    if mode=='wrong-commit': manifest['commit']='b'*40
    if mode=='wrong-repo': manifest['repository']='attacker/repo'
    if mode=='wrong-target': manifest['target']='linux/arm64'
    if mode=='unsafe-name': manifest['files']['../../escape']='a'*64
    if mode=='extra': files['unexpected']=b'extra'
    if mode=='missing': del files['notices.tar.gz']
    files['release-manifest.json']=json.dumps(manifest).encode()
    with pytest.raises(ValueError): api().fetch('0.2.0-alpha.1','a'*40,tmp_path/'out',transport=Fake(files,mode=='wrong-provenance'))
    assert list(tmp_path.iterdir())==[]

def test_existing_destination_and_symlink_parent_are_refused(tmp_path):
    dest=tmp_path/'existing'; dest.mkdir()
    with pytest.raises(ValueError): api().fetch('0.2.0-alpha.1','a'*40,dest,transport=Fake(fixture()))
    link=tmp_path/'link'; link.symlink_to(dest,target_is_directory=True)
    with pytest.raises(ValueError): api().fetch('0.2.0-alpha.1','a'*40,link/'new',transport=Fake(fixture()))

def test_verification_policy_binds_repository_workflow_ref_and_commit(monkeypatch,tmp_path):
    calls=[]
    def run(argv,**kwargs):
        calls.append((argv,kwargs))
        class Result: returncode=0
        return Result()
    monkeypatch.setattr(api().subprocess,'run',run)
    api().GitHub().verify(tmp_path/'artifact','v0.2.0-alpha.1','a'*40)
    argv,kwargs=calls[0]
    for flag,value in {'--repo':'kollanekirss/resilient-datacenter','--source-ref':'refs/tags/v0.2.0-alpha.1',
                       '--source-digest':'a'*40,'--signer-digest':'a'*40,
                       '--signer-workflow':'kollanekirss/resilient-datacenter/.github/workflows/release.yml'}.items():
        assert argv[argv.index(flag)+1]==value
    assert '--deny-self-hosted-runners' in argv and kwargs['timeout']<=120

@pytest.mark.parametrize('mode',['symlink','hardlink','directory'])
def test_non_regular_downloads_are_refused(tmp_path,mode):
    class Unsafe(Fake):
        def download(self,tag,destination):
            super().download(tag,destination)
            path=destination/'source.tar.gz'; path.unlink()
            if mode=='symlink': path.symlink_to(destination/'derper-linux-amd64')
            elif mode=='hardlink':
                import os
                os.link(destination/'derper-linux-amd64',path)
            else: path.mkdir()
    with pytest.raises(ValueError): api().fetch('0.2.0-alpha.1','a'*40,tmp_path/'out',transport=Unsafe(fixture()))
    assert list(tmp_path.iterdir())==[]

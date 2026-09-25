import importlib
from pathlib import Path
import json
import pytest
from test_setup_contracts import ROOT, manifest, infrastructure

def files_api():
    assert (ROOT/'scripts/setup_files.py').exists(),'Private setup output not implemented'
    return importlib.import_module('setup_files')

def test_join_outputs_are_non_executable():
    out=files_api().prepare_outputs('join',manifest())
    assert set(out)=={'node-home-services.yml','NEXT-STEPS.md'}
    assert 'ansible_connection' not in out['node-home-services.yml']

def test_infrastructure_outputs_no_peer_ssh():
    out=files_api().prepare_outputs('independent',infrastructure())
    assert 'infrastructure.yml' in out and 'node-south-services.yml' in out
    assert 'peers:' not in out['infrastructure.yml']

def test_refuse_existing_target(tmp_path):
    p=tmp_path/'node.yml'; p.write_text('keep')
    with pytest.raises(FileExistsError): files_api().write_bundle(tmp_path,{'node.yml':'replace'})
    assert p.read_text()=='keep'

def test_refuse_symlink_even_when_replacing(tmp_path):
    p=tmp_path/'original'; p.write_text('keep'); (tmp_path/'node.yml').symlink_to(p)
    with pytest.raises(ValueError): files_api().write_bundle(tmp_path,{'node.yml':'replace'},overwrite=True)
    assert p.read_text()=='keep'

def test_private_complete_bundle(tmp_path):
    paths=files_api().write_bundle(tmp_path,{'node.yml':'safe'})
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in paths)
    meta=json.loads((tmp_path/'BUNDLE.json').read_text())
    assert meta['state']=='prepared' and 'node.yml' in meta['sha256']

@pytest.mark.parametrize('name',['../escape','/absolute','BUNDLE.json','sub/file',''])
def test_reject_unsafe_output_names(tmp_path,name):
    with pytest.raises(ValueError): files_api().write_bundle(tmp_path,{name:'data'})

def test_invalid_configuration_cannot_be_prepared():
    with pytest.raises(ValueError): files_api().prepare_outputs('join',{'kind':'setup-draft'})

def test_interrupted_bundle_has_no_completion_record(tmp_path,monkeypatch):
    m=files_api(); original=m.os.link; count=0
    def fail_second(src,dst):
        nonlocal count
        count+=1
        if count==2: raise OSError('simulated interruption')
        return original(src,dst)
    monkeypatch.setattr(m.os,'link',fail_second)
    with pytest.raises(OSError): m.write_bundle(tmp_path,{'one.yml':'one','two.yml':'two'})
    assert not (tmp_path/'BUNDLE.json').exists()

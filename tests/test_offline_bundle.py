import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('offline_bundle')


@pytest.fixture
def bundle(tmp_path):
    root=tmp_path/'kit';root.mkdir(mode=0o700)
    (root/'source').mkdir();(root/'source/README.md').write_text('public source')
    manifest={'schema_version':1,'kind':'portable-software','source_commit':'a'*40,
        'target':'ubuntu-24.04-amd64-python3.12','scope':'role-software',
        'images':{},'files':{'source/README.md':{'size':13,'sha256':hashlib.sha256(b'public source').hexdigest()}},
        'created_at':'2026-09-26T00:00:00+00:00'}
    def save(data=manifest):
        raw=(json.dumps(data,sort_keys=True)+'\n').encode();(root/'manifest.json').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()
    return root,manifest,save


def test_manifest_verification_never_executes_or_fetches(bundle,monkeypatch):
    root,m,save=bundle
    result=api().verify(root,save())
    assert result==m


@pytest.mark.parametrize('change',['modified','missing','extra','symlink','directory','fifo'])
def test_untrusted_files_are_rejected(bundle,change):
    root,m,save=bundle;trusted=save();p=root/'source/README.md'
    if change=='modified':p.write_text('attacker data')
    elif change=='missing':p.unlink()
    elif change=='extra':(root/'unexpected').write_text('not in manifest')
    elif change=='symlink':p.unlink();p.symlink_to(root/'manifest.json')
    elif change=='directory':p.unlink();p.mkdir()
    else:p.unlink();os.mkfifo(p)
    with pytest.raises(ValueError):api().verify(root,trusted)


def test_mutating_manifest_and_payload_does_not_replace_trust_anchor(bundle):
    root,m,save=bundle;trusted=save();m['source_commit']='b'*40;save()
    with pytest.raises(ValueError):api().verify(root,trusted)


@pytest.mark.parametrize('name',['../outside','/absolute','source/../escape','source//double','source/./dot','source\\windows'])
def test_paths_are_strict(bundle,name):
    root,m,save=bundle;m['files'][name]=m['files'].pop('source/README.md')
    with pytest.raises(ValueError):api().verify(root,save())


@pytest.mark.parametrize('bad',[True,-1,0,2**50,'13'])
def test_size_contract(bundle,bad):
    root,m,save=bundle;m['files']['source/README.md']['size']=bad
    with pytest.raises(ValueError):api().verify(root,save())


def test_schema_rejects_unknown_fields(bundle):
    root,m,save=bundle;m['command']='curl bad | sh'
    with pytest.raises(ValueError):api().verify(root,save())


def test_symlinked_bundle_root_rejected(bundle,tmp_path):
    root,m,save=bundle;trusted=save();link=tmp_path/'link';link.symlink_to(root)
    with pytest.raises(ValueError):api().verify(link,trusted)


def test_incomplete_build_has_no_manifest(tmp_path):
    root=tmp_path/'kit';root.mkdir()
    with pytest.raises(ValueError):api().verify(root,'a'*64)


def test_readiness_does_not_claim_recovery(bundle):
    root,m,save=bundle
    result=api().report(root,save())
    assert result['whole_site_recovery']=='not-tested'
    assert result['private_recovery_material']=='not-assessed'


def test_standalone_bootstrap_does_not_modify_its_verified_source(bundle):
    import subprocess
    root,m,save=bundle
    folder=root/'source/scripts';folder.mkdir(parents=True)
    (folder/'offline_bundle.py').write_bytes((Path(__file__).resolve().parents[1]/'scripts/offline_bundle.py').read_bytes())
    (folder/'offline_bundle_install.py').write_text('from offline_bundle import report\ndef bootstrap(root,trusted): return report(root,trusted)\n')
    for path in folder.iterdir():
        m['files'][path.relative_to(root).as_posix()]={'size':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    trusted=save()
    result=subprocess.run([sys.executable,str(folder/'offline_bundle.py'),'bootstrap',str(root),'--manifest-sha256',trusted,'--confirm-fresh-guest'],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
    assert not list(root.rglob('__pycache__'))

import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('offline_bundle_build')


def test_apt_resolution_uses_empty_state_and_isolated_sources(tmp_path):
    args=api().apt_options(tmp_path)
    text=' '.join(args)
    assert 'Dir::State::status=/dev/null' in text
    assert 'Dir::Etc::sourceparts=-' in text
    assert 'Dir::Etc::parts=-' in text
    assert 'APT::Get::AllowUnauthenticated=false' in text


def test_source_export_excludes_private_working_files():
    m=api()
    for path in ['.env','inventories/lab/site.json','.work/secrets.json','tests/key.pem','.git/config']:
        assert not m.source_allowed(path)
    assert m.source_allowed('scripts/rdc.py')
    assert m.source_allowed('requirements.txt')


def test_images_keep_original_pinned_manifest_identity():
    pins=api().image_catalogue()
    assert len(pins)==5
    for key,item in pins.items():
        assert item['reference'].endswith('@sha256:'+key)
        assert item['path']=='images/'+key


def test_wrong_platform_does_not_start_acquisition(monkeypatch,tmp_path):
    m=api();monkeypatch.setattr(m.platform,'system',lambda:'Darwin')
    monkeypatch.setattr(m,'run',lambda *a,**k:pytest.fail('not a supported build host'))
    with pytest.raises(ValueError):m.build(tmp_path/'kit')
    assert not (tmp_path/'kit').exists()

import importlib
import io
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('release_build')

@pytest.mark.parametrize('text',['','a,url,UNKNOWN\n','a,url,GPL-3.0\n','bad\n','a,url,MIT\na,url,Apache-2.0\n'])
def test_unreviewed_or_malformed_license_report_is_blocked(text):
    with pytest.raises(ValueError): api().validate_licenses(text)

def test_permissive_notices_are_accepted_without_dropping_rows():
    rows=api().validate_licenses('tailscale.com,url,BSD-3-Clause\nx,url,Apache-2.0\n')
    assert len(rows)==2

def test_manifest_binds_all_assets_to_source(tmp_path):
    from release_download import FILES,validate_manifest
    for name in FILES: (tmp_path/name).write_bytes(name.encode())
    data=api().write_manifest(tmp_path,'0.2.0-alpha.1','b'*40)
    validate_manifest(data,'0.2.0-alpha.1','b'*40)
    assert (tmp_path/'release-manifest.json').exists()
    (tmp_path/'source.tar.gz').unlink()
    with pytest.raises(ValueError): api().write_manifest(tmp_path,'0.2.0-alpha.1','b'*40)

def test_release_workflow_does_not_publish_on_push_or_pull_request():
    import yaml
    path=Path(__file__).resolve().parents[1]/'.github/workflows/release.yml'
    assert path.exists()
    data=yaml.safe_load(path.read_text())
    triggers=data.get('on',data.get(True))
    assert set(triggers)=={'workflow_dispatch'}
    assert data['permissions']=={'contents':'read'}
    job=data['jobs']['release']
    assert job['runs-on']=='ubuntu-24.04'
    assert 'refs/tags/' in job['if']
    for step in job['steps']:
        if 'uses' in step:
            import re
            assert re.fullmatch(r'[^@]+@[a-f0-9]{40}',step['uses'])


def test_build_lock_matches_reported_component_and_toolchain():
    import build_derper
    text=(build_derper.ROOT/'build/derper/go.mod').read_text()
    assert 'require tailscale.com '+build_derper.VERSION+'\n' in text
    assert '\ngo '+build_derper.TOOLCHAIN.removeprefix('go')+'\n' in text


def test_build_environment_discards_go_execution_overrides(monkeypatch):
    import build_derper
    monkeypatch.setenv('GOFLAGS','-toolexec=untrusted')
    monkeypatch.setenv('GOWORK','/tmp/foreign')
    monkeypatch.setenv('CGO_ENABLED','1')
    env=build_derper.build_environment()
    assert 'GOFLAGS' not in env and env['GOWORK']=='off' and env['CGO_ENABLED']=='0'

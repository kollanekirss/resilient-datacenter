import importlib
import json
import subprocess
from pathlib import Path
from test_setup_contracts import ROOT


def api(): return importlib.import_module('source_identity')


def source(tmp_path):
    (tmp_path/'project-version.json').write_text('{"schema_version":1,"version":"0.2.0-dev","channel":"development"}')
    (tmp_path/'versions.yml').write_text("headscale_version: '0.29.4'\ntailscale_version: '1.102.4'\n")
    return tmp_path


def test_archive_has_no_fake_verified_commit(tmp_path):
    result=api().source_identity(source(tmp_path))
    assert result['version']=='0.2.0-dev'
    assert result['commit'] is None and result['provenance']=='unverified'


def test_archive_inside_parent_repo_cannot_inherit_identity(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)],check=True)
    child=tmp_path/'archive'; child.mkdir(); source(child)
    result=api().source_identity(child)
    assert result['commit'] is None and result['dirty'] is None


def test_git_identity_tracks_edits_but_not_private_ignored_files(tmp_path,monkeypatch):
    root=source(tmp_path)
    (root/'.gitignore').write_text('private/\n')
    subprocess.run(['git','init','-q',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'add','.'],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=Test','-c','user.email=test@invalid.test','commit','-qm','initial'],check=True)
    monkeypatch.setenv('GIT_DIR','/PRIVATE_FAKE')
    assert api().source_identity(root)['dirty'] is False
    (root/'private').mkdir(); (root/'private'/'secret').write_text('PRIVATE_TOKEN')
    assert api().source_identity(root)['dirty'] is False
    (root/'versions.yml').write_text("headscale_version: '0.29.5'\n")
    assert api().source_identity(root)['dirty'] is True


def test_malformed_metadata_is_unknown(tmp_path):
    root=source(tmp_path); (root/'project-version.json').write_text('{"version":"PRIVATE_VERSION"}')
    result=api().source_identity(root)
    assert result['version']=='unknown/unreleased'
    assert 'PRIVATE' not in json.dumps(result)

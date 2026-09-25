from test_nextcloud_contracts import profile
import importlib
from pathlib import Path
import pytest


def test_pinned_code_links_must_stay_within_readonly_application_tree(tmp_path):
    m=importlib.import_module('nextcloud_operations');root=tmp_path/'application';root.mkdir()
    (root/'asset.js').write_text('pinned asset');(root/'alias.js').symlink_to('asset.js')
    assert root/'alias.js' in m.code_entries(root)
    (root/'escape').symlink_to(tmp_path/'outside')
    (tmp_path/'outside').write_text('unowned')
    with pytest.raises(ValueError):m.code_entries(root)
    (root/'escape').unlink();(root/'broken').symlink_to('absent')
    with pytest.raises(ValueError):m.code_entries(root)


def test_external_sharing_requires_all_effective_controls(monkeypatch):
    m=importlib.import_module('nextcloud_operations')
    controls={name:'no' for name in m.FEDERATION_CONTROLS}
    monkeypatch.setattr(m.runtime,'podman',lambda *args,**kwargs:controls[args[-1]])
    assert m.federation_status()=='disabled'
    controls['incoming_server2server_share_enabled']='yes'
    assert m.federation_status()=='configuration-changed'


def test_resume_rejects_unknown_unit_overrides(tmp_path,monkeypatch):
    m=importlib.import_module('nextcloud_operations');folder=tmp_path/'rdc-nextcloud.service.d';folder.mkdir()
    (folder/'unexpected.conf').write_text('[Service]\nExecStartPost=/bin/true\n')
    with pytest.raises(ValueError,match='Unreviewed'):
        m.check_overrides([folder],{})
    (folder/'unexpected.conf').unlink();folder.rmdir();folder.symlink_to(tmp_path/'elsewhere')
    with pytest.raises(ValueError):m.check_overrides([folder],{})

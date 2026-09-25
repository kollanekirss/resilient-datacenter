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
    from test_nextcloud_runtime import settings
    monkeypatch.setattr(m.runtime,'read_settings',settings)
    monkeypatch.setattr(m.runtime.regional,'active',lambda value:None)
    controls={name:'no' for name in m.FEDERATION_CONTROLS}
    monkeypatch.setattr(m.runtime,'podman',lambda *args,**kwargs:controls[args[-1]])
    assert m.federation_status()=='disabled'
    controls['incoming_server2server_share_enabled']='yes'
    assert m.federation_status()=='configuration-changed'


def test_file_status_accepts_only_exact_current_connector_controls(monkeypatch):
    m=importlib.import_module('nextcloud_operations')
    from test_nextcloud_runtime import settings
    from test_nextcloud_regional import configuration
    monkeypatch.setattr(m.runtime,'read_settings',settings)
    monkeypatch.setattr(m.runtime.regional,'active',lambda value:configuration())
    controls={name:'no' for name in m.FEDERATION_CONTROLS}
    controls.update(incoming_server2server_share_enabled='yes',outgoing_server2server_share_enabled='yes')
    monkeypatch.setattr(m.runtime,'podman',lambda *args,**kwargs:controls[args[-1]])
    assert m.federation_status()=='approved-gateway-configured'
    controls['incoming_server2server_group_share_enabled']='yes'
    assert m.federation_status()=='configuration-changed'
    controls['incoming_server2server_group_share_enabled']='no'
    monkeypatch.setattr(m.runtime.regional,'active',lambda value:None)
    assert m.federation_status()=='configuration-changed'


def test_resume_rejects_unknown_unit_overrides(tmp_path,monkeypatch):
    m=importlib.import_module('nextcloud_operations');folder=tmp_path/'rdc-nextcloud.service.d';folder.mkdir()
    (folder/'unexpected.conf').write_text('[Service]\nExecStartPost=/bin/true\n')
    with pytest.raises(ValueError,match='Unreviewed'):
        m.check_overrides([folder],{})
    (folder/'unexpected.conf').unlink();folder.rmdir();folder.symlink_to(tmp_path/'elsewhere')
    with pytest.raises(ValueError):m.check_overrides([folder],{})


def test_bootstrap_secrets_removed_before_code_becomes_readable(tmp_path,monkeypatch):
    m=importlib.import_module('nextcloud_operations');root=tmp_path/'code';root.mkdir()
    (root/'config').mkdir();secret=root/'config/config.php';secret.write_text('private bootstrap credential')
    (root/'index.php').write_text('pinned code');seen=[]
    monkeypatch.setattr(m.os,'chown',lambda *args,**kwargs:None)
    def chmod(path,mode):
        assert not secret.exists()
        seen.append((path,mode))
    monkeypatch.setattr(Path,'chmod',chmod)
    m.freeze_code(root)
    assert seen and (root/'index.php',0o644) in seen


def test_cron_does_not_schedule_an_application_activation_job():
    import configparser
    m=importlib.import_module('nextcloud_operations')
    unit=configparser.ConfigParser();unit.read_string(m.cron_unit())
    # Requisite schedules VERIFY_ACTIVE and can replace a concurrent STOP job.
    # The fixed runner checks the owned container while holding the app lock.
    for name in ('Requires','Requisite','Wants','BindsTo','Upholds'):
        assert not unit['Unit'].get(name)

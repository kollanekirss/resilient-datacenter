import importlib
import json
from pathlib import Path
import sys
import pytest
from test_backup_contracts import profile
from test_setup_contracts import manifest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api(): return importlib.import_module('backup_operations')


def test_backup_identity_is_bound_to_exact_installed_owner():
    from setup_contracts import local_ownership
    owner=local_ownership(manifest()); data=profile()
    api().match_owner(data,owner)
    changed=dict(owner,controller_hostname='different.pilot.test')
    with pytest.raises(ValueError): api().match_owner(data,changed,expected=owner)
    with pytest.raises(ValueError): api().match_owner(dict(data,role='controller'),owner)


def test_unknown_and_legacy_ownership_are_blocked():
    data=profile()
    for owner in ({'role':'peer'},{'schema_version':1,'role':'peer'}, {'schema_version':2,'role':'peer','arbitrary':'value'}):
        with pytest.raises(ValueError): api().match_owner(data,owner)


def test_restore_manifest_requires_exact_ownership_and_catalogue(tmp_path):
    from setup_contracts import local_ownership
    from backup_contracts import resources
    owner=local_ownership(manifest())
    meta={'schema_version':1,'ownership':owner,'paths':list(resources(owner).paths),'captured_at':'2026-09-25T10:00:00+00:00','services_originally_active':{'tailscaled':True},'binary_sha256':{'usr/local/bin/tailscale':'a'*64,'usr/local/bin/tailscaled':'b'*64}}
    (tmp_path/'snapshot.json').write_text(json.dumps(meta))
    for name in resources(owner).paths:
        p=tmp_path/'data'/name
        if name.endswith('.json'): p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(owner))
        else: p.mkdir(parents=True)
    assert api().validate_restore(tmp_path,owner)==meta
    meta['paths'].append('etc/shadow');(tmp_path/'snapshot.json').write_text(json.dumps(meta))
    with pytest.raises(ValueError): api().validate_restore(tmp_path,owner)


def test_status_does_not_conflate_snapshot_with_tested_recovery():
    snapshots=[{'id':'a'*64,'time':'2026-09-25T10:00:00Z'}]
    result=api().status_summary(snapshots,now='2026-09-25T12:00:00+00:00')
    assert result['backup_age_seconds']==7200 and result['restore_test']=='not-run'
    assert api().status_summary([],now='2026-09-25T12:00:00+00:00')['state']=='no-backup'

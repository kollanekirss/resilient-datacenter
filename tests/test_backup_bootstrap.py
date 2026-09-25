import importlib
import json
from pathlib import Path
import pytest
from test_gateway_backup import gateway_source,network
from test_backup_snapshot import Services
from backup_snapshot import capture


def fixture(tmp_path):
    source,combined=gateway_source(tmp_path/'source')
    stage=tmp_path/'full';capture(tmp_path/'source',stage,combined,services=Services(active=()))
    root=tmp_path/'replacement';(root/'etc').mkdir(parents=True)
    (root/'etc/server-connectivity-profile.json').write_text(json.dumps(network()))
    (root/'var/lib/tailscale').mkdir(parents=True)
    (root/'var/lib/tailscale/tailscaled.state').write_bytes(b'temporary enrolled identity')
    (root/'usr/local/bin').mkdir(parents=True)
    for name in ('tailscale','tailscaled'):(root/'usr/local/bin'/name).write_bytes(b'reviewed component')
    return stage,root


def test_narrow_stage_keeps_exact_network_identity_and_excludes_application(tmp_path):
    m=importlib.import_module('backup_bootstrap');source,root=fixture(tmp_path)
    target=tmp_path/'network';before=(source/'snapshot.json').read_bytes()
    result=m.derive(source,target,network(),'gateway',root=root)
    assert result['state']=='network-recovery-staged'
    assert (target/'data/var/lib/tailscale/tailscaled.state').read_bytes()==b'network identity'
    assert not (target/'data/etc/rdc-gateway').exists()
    assert (source/'snapshot.json').read_bytes()==before
    assert (root/'var/lib/tailscale/tailscaled.state').read_bytes()==b'temporary enrolled identity'
    assert target.stat().st_mode&0o777==0o700
    m.verify(source,target,network(),'gateway',root=root)
    (target/'data/var/lib/tailscale/tailscaled.state').write_bytes(b'other identity')
    with pytest.raises(ValueError):m.verify(source,target,network(),'gateway',root=root)


@pytest.mark.parametrize('problem',['package','owner','binary','installed','escape'])
def test_bootstrap_refuses_incompatible_or_unsafe_source_before_creating_stage(tmp_path,problem):
    m=importlib.import_module('backup_bootstrap');source,root=fixture(tmp_path)
    owner=network();package='gateway'
    if problem=='package':package='nextcloud'
    if problem=='owner':owner=dict(owner,institution_id='other')
    if problem=='binary':(root/'usr/local/bin/tailscaled').write_bytes(b'unknown version')
    if problem=='installed':(root/'etc/rdc-gateway').mkdir()
    if problem=='escape':(source/'data/var/lib/tailscale/link').symlink_to('../../../etc/rdc-gateway/state.json')
    with pytest.raises(ValueError):m.derive(source,tmp_path/'network',owner,package,root=root)
    assert not (tmp_path/'network').exists()


def test_narrow_restore_can_recover_interrupted_identity_swap(tmp_path):
    m=importlib.import_module('backup_bootstrap');source,root=fixture(tmp_path)
    from test_restore_transaction import Runtime
    import restore_transaction as restore
    target=tmp_path/'network';m.derive(source,target,network(),'gateway',root=root)
    class Interrupted(Runtime):
        def verify(self,owner):raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):restore.apply(target,network(),root=root,runtime=Interrupted(),permissions=lambda *a:None)
    assert restore.recover(network(),root=root,runtime=Runtime())['state']=='previous-data-restored'
    assert (root/'var/lib/tailscale/tailscaled.state').read_bytes()==b'temporary enrolled identity'

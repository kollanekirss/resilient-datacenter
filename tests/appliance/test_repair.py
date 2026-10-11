import importlib
from pathlib import Path

import pytest

from appliance.contracts import ApplianceError


def module(): return importlib.import_module('appliance.repair')


class NeverRunner:
    def run(self, *args, **kwargs): raise AssertionError('repair must not call installer or mutation tools')


@pytest.mark.parametrize('observed_uuid', ['12345678-1234-1234-1234-123456789abc', '87654321-1234-1234-1234-123456789abc'])
def test_target_identity_includes_staged_filesystem_uuid(site, tmp_path, monkeypatch, observed_uuid):
    import json
    from types import SimpleNamespace
    from appliance import state
    from appliance.installer.adapters import pve
    root = tmp_path / 'target'
    lvm = {'device':pve.ROOT_DEVICE, 'disk_path':'/dev/sdb', 'lv_uuid':'lv-one', 'pv_uuid':'pv-one'}
    expected_uuid = '12345678-1234-1234-1234-123456789abc'
    staged = {'schema':1, 'complete':True, 'target':site['target'],
              'root':{**lvm, 'disk_path':'/dev/sda', 'filesystem_uuid':expected_uuid}}
    state.write(root / 'var/lib/rdc-appliance/private/staged.json', staged)
    monkeypatch.setattr(pve, 'installed_root', lambda runner, disk: lvm if disk=='/dev/sdb' else {})
    monkeypatch.setattr(module(), '_resolve_disk', lambda target, runner: '/dev/sdb', raising=False)
    class MountRunner:
        def run(self, argv):
            assert argv[-1] == 'SOURCE,FSTYPE,OPTIONS,UUID'
            return SimpleNamespace(stdout=json.dumps({'filesystems':[{'source':pve.ROOT_DEVICE,
                'fstype':'ext4', 'options':'rw,relatime', 'uuid':observed_uuid}]}))
    if observed_uuid == expected_uuid:
        assert module()._observe_target(root, MountRunner()) == staged
    else:
        with pytest.raises(ApplianceError, match='repair-root-identity'):
            module()._observe_target(root, MountRunner())


@pytest.mark.parametrize('fault', ['', 'duplicate', 'changed'])
def test_repair_resolves_stable_disk_identity_after_usb_renumbering(site, fault):
    import json
    from types import SimpleNamespace
    target=site['target']
    row={'path':'/dev/sdb','type':'disk','size':target['size_bytes'],'serial':target['serial'],
         'wwn':target['wwn'],'model':target['model'],'tran':target['transport']}
    rows=[row]
    if fault=='changed': row['serial']='different'
    if fault=='duplicate': rows.append(dict(row,path='/dev/sdc'))
    class DiskRunner:
        def run(self,argv):
            if argv[0]=='/usr/bin/lsblk': return SimpleNamespace(stdout=json.dumps({'blockdevices':rows}))
            assert argv[0]=='/usr/bin/udevadm'
            aliases=target['by_id'] if argv[-1]=='/dev/sdb' else '/dev/disk/by-id/another-disk'
            return SimpleNamespace(stdout=('DEVLINKS='+aliases+'\n').encode())
    if fault:
        with pytest.raises(ApplianceError,match='repair-disk-identity'):
            module()._resolve_disk(target,DiskRunner())
    else:
        assert module()._resolve_disk(target,DiskRunner())=='/dev/sdb'


@pytest.mark.parametrize('target,code', [
    ({'matches': 2}, 'repair-target-ambiguous'),
    ({'matches': 1, 'owned': False}, 'repair-target-unowned'),
    ({'matches': 1, 'owned': True, 'confirmed': False}, 'repair-not-confirmed'),
])
def test_invalid_target_never_reaches_host_commands(target, code, tmp_path):
    with pytest.raises(ApplianceError, match=code):
        module().repair_host(target, tmp_path / 'export', NeverRunner())


def test_arbitrary_root_refused_even_with_flags(tmp_path):
    target = {'matches': 1, 'owned': True, 'confirmed': True, 'root': str(tmp_path)}
    with pytest.raises(ApplianceError, match='repair-environment'):
        module().repair_host(target, tmp_path / 'export', NeverRunner())


def test_repair_derives_management_files_and_never_activates_network(site, release, tmp_path, monkeypatch):
    from appliance import state
    import copy
    repair = module()
    # Synthetic release exercises the declared base validator without vendor downloads.
    release = copy.deepcopy(release); release.pop('test_only')
    release['components'] = [dict(id=name, version='1', url='https://example.org/' + name,
        sha256='a'*64, size_bytes=1, max_bytes=1,
        provenance={'kind':'official-checksum','url':'https://example.org/sums'})
        for name in ('proxmox-iso','opnsense-dvd','probe-image','restic')]
    root = tmp_path / 'target'; root.mkdir(mode=0o700)
    private = root / 'var/lib/rdc-appliance/private'
    state.write(private / 'site.json', site)
    staged = {'schema':1, 'complete':True, 'target':site['target'], 'build_id':'b'*64}
    monkeypatch.setattr(repair, '_observe_target', lambda root, runner: staged)
    import appliance.host_network as network
    monkeypatch.setattr(network, 'collect_ports', lambda root, runner:
        [dict(site['ports'][role], name=name) for role,name in [('management','enp1s0'),('wan','enp2s0')]])
    opened = tmp_path / 'opened'
    state.write(opened / 'site.json', site)
    state.write(opened / 'release.lock.json', release)
    state.write(opened / 'host.json', {'known-good':{'plan':site, 'resolved_ports':{'management':'old0','wan':'old1'},
                                                    'files':{'/etc/shadow':'not-authorized'}}})
    runner = NeverRunner(); runner.target_root = root
    result = repair.repair_host({'matches':1,'owned':True,'confirmed':True,'root':str(root),
        'target':site['target'],'build_id':'b'*64}, opened, runner)
    text = (root / 'etc/network/interfaces').read_text()
    assert 'enp1s0' in text and 'old0' not in text
    assert 'auto vmbr1' not in text
    assert not (root / 'etc/shadow').exists()
    assert result['network_activated'] is False
    assert state.read(private / 'network/pending.json')['phase'] == 'rolled-back'
    assert state.read(private / 'network/known-good.json')['profile'] == 'management-only'

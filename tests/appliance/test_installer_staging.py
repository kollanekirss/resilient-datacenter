import copy
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from appliance.contracts import ApplianceError, canonical, identity
from appliance.installer.adapters import pve
from appliance.installer.payload import prepare_runtime
from appliance.state import read, write


class FakeRunner:
    def __init__(self): self.calls = []
    def run(self,argv,**kwargs):
        self.calls.append((argv,kwargs))
        return CompletedProcess(argv,0,b'',b'')


@pytest.fixture
def staged_inputs(tmp_path,site):
    payload = tmp_path / 'payload'; payload.mkdir()
    package = tmp_path / 'source/appliance'; (package / 'systemd').mkdir(parents=True)
    (package / '__init__.py').write_text('"""Test-only package fixture."""\n')
    unit = Path(__file__).parents[2] / 'appliance/systemd/rdc-first-boot.service'
    (package / 'systemd/rdc-first-boot.service').write_bytes(unit.read_bytes())
    (package / 'systemd/pve-guests.service.d').mkdir()
    (package / 'systemd/pve-guests.service.d/20-rdc-host-policy.conf').write_bytes(b'[Unit]\nRequires=rdc-host-policy.service\n')
    (package / 'systemd/rdc-network-rollback.timer').write_bytes(b'[Timer]\nOnActiveSec=5s\n')
    runtime = prepare_runtime(package,payload / 'runtime')
    release = json.loads((Path(__file__).parents[2] / 'appliance/releases/v1.lock.json').read_text())
    (payload / 'media').mkdir()
    for component in release['components']:
        raw = ('test-only-' + component['id']).encode()
        content = component.get('expanded',component)
        content.update(sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),max_bytes=len(raw))
        if component['id'] in ('opnsense-dvd','probe-image','restic'):
            (payload / 'media' / component['id']).write_bytes(raw)
    (payload / 'release.lock.json').write_bytes(canonical(release))
    build = {'schema':1,'release_identity':identity(release),'runtime_identity':identity(runtime),
             'adapter_id':pve.ADAPTER_ID,'source_revision':pve.SOURCE_REVISION,
             'qualification':'not-run','qualification_build':True}
    (payload / 'build.json').write_bytes(canonical(build))
    site['release_id'] = release['release_id']
    receipt = {'schema':1,'adapter_id':pve.ADAPTER_ID,'upstream_complete':True,
               'root':{'device':'/dev/mapper/pve-root','disk_path':'/dev/sda','lv_uuid':'root-id','pv_uuid':'pv-id'}}
    return payload,site,receipt


def test_stage_files_receipt_binds_all_files_and_wrapper(tmp_path,staged_inputs):
    from appliance.installer.first_boot import verify_staging
    payload,site,receipt = staged_inputs
    target = tmp_path / 'target'; target.mkdir()
    staged = pve.stage_files(receipt,payload,site,target=target)
    assert verify_staging(target) == staged
    assert (target / 'usr/local/sbin/rdc-appliance').stat().st_mode & 0o111
    assert (target / 'var/lib/rdc-appliance/private/site.json').stat().st_mode & 0o777 == 0o600
    assert b'ipv6.disable=1' in (target / 'etc/default/grub.d/90-rdc-appliance.cfg').read_bytes()
    assert (target / 'etc/systemd/system/pve-guests.service.d/20-rdc-host-policy.conf').exists()
    assert (target / 'etc/systemd/system/rdc-network-rollback.timer').exists()
    assert all('etc/network/interfaces' != item['relative_path'] for item in staged['files'])
    (target / 'var/lib/rdc-appliance/media/opnsense-dvd').write_bytes(b'changed')
    with pytest.raises(ApplianceError): verify_staging(target)


def test_staging_failure_has_no_completion_marker_and_cannot_retry(tmp_path,staged_inputs):
    payload,site,receipt = staged_inputs
    target = tmp_path / 'target'; target.mkdir()
    def fail(): raise ApplianceError('simulated-bootloader-failure')
    with pytest.raises(ApplianceError,match='simulated-bootloader-failure'):
        pve.stage_files(receipt,payload,site,target=target,finalize=fail)
    assert not (target / 'var/lib/rdc-appliance/private/staged.json').exists()
    with pytest.raises(ApplianceError,match='staging-already-exists'):
        pve.stage_files(receipt,payload,site,target=target)


def test_first_boot_is_repeatable_without_overwriting_confirmed_files(tmp_path,staged_inputs,monkeypatch):
    from appliance.installer.first_boot import first_boot
    import appliance.installer.inventory as inventory
    payload,site,receipt = staged_inputs
    target = tmp_path / 'target'; target.mkdir()
    pve.stage_files(receipt,payload,site,target=target)
    ports = [{'name':name,**site['ports'][role]} for role,name in (('management','enp1s0'),('wan','enp2s0'))]
    monkeypatch.setattr(inventory,'port_observations',lambda runner,root:ports)
    runner = FakeRunner()
    runner.target_root = target.resolve()
    first_boot(target,runner)
    config = target / 'etc/network/interfaces'
    assert b'auto vmbr0' in config.read_bytes() and b'auto vmbr1' not in config.read_bytes()
    config.write_bytes(config.read_bytes()+b'# confirmed later local change\n')
    first_boot(target,runner)
    assert config.read_bytes().endswith(b'# confirmed later local change\n')
    assert [c[0][0] for c in runner.calls] == ['/usr/sbin/sysctl','/usr/sbin/nft','/usr/sbin/nft'] * 2
    ports[0]['permanent_mac'] = '02:00:00:00:00:99'
    with pytest.raises(ApplianceError,match='port-identity-unresolved'): first_boot(target,runner)
    assert len(runner.calls) == 6


def test_first_boot_blocks_port_rename_and_uses_saved_good_mapping(tmp_path,staged_inputs,monkeypatch):
    from appliance.installer.first_boot import first_boot
    import appliance.installer.inventory as inventory
    payload,site,receipt = staged_inputs
    target = tmp_path / 'target'; target.mkdir()
    pve.stage_files(receipt,payload,site,target=target)
    ports = [{'name':name,**site['ports'][role]} for role,name in (('management','enp1s0'),('wan','enp2s0'))]
    monkeypatch.setattr(inventory,'port_observations',lambda runner,root:ports)
    runner = FakeRunner(); runner.target_root = target.resolve()
    first_boot(target,runner)
    ports[0]['name'] = 'enp9s0'
    with pytest.raises(ApplianceError,match='port-name-changed'): first_boot(target,runner)
    assert len(runner.calls) == 3
    # A deliberate local repair/confirmed network operation records the new mapping.
    write(target / 'var/lib/rdc-appliance/private/network/known-good.json',
          {'resolved_ports':{'management':'enp9s0','wan':'enp2s0'}})
    first_boot(target,runner)
    assert len(runner.calls) == 6


def test_upstream_success_without_finished_record_is_refused():
    class EarlyEOF:
        def run(self,argv,**kwargs): return CompletedProcess(argv,0,b'',b'INFO: Installation done.\n')
    with pytest.raises(ApplianceError,match='upstream-install-incomplete'):
        pve.install(b'answer',EarlyEOF(),disk_path='/dev/sda',management_name='eth0',prepared=True)


def test_upstream_disk_tuple_cache_and_suffix_ambiguity(tmp_path):
    cache = tmp_path / 'run/proxmox-installer'; cache.mkdir(parents=True)
    env = {'disks':[[0,'/dev/sda',1024,'test',512,'/sys/block/sda']]}
    (cache / 'run-env-info.json').write_bytes(canonical(env))
    (cache / 'run-env-udev.json').write_bytes(canonical({'nics':{'eth0':{'ID_NET_NAME':'eth0'}}}))
    pve.verify_upstream_selection(FakeRunner(),disk_path='/dev/sda',management_name='eth0',root=tmp_path)
    env['disks'].append([1,'/dev/vsda',1024,'test',512,'/sys/block/vsda'])
    (cache / 'run-env-info.json').write_bytes(canonical(env))
    with pytest.raises(ApplianceError,match='upstream-disk-ambiguous'):
        pve.verify_upstream_selection(FakeRunner(),disk_path='/dev/sda',management_name='eth0',root=tmp_path)


def test_installed_root_requires_exact_target_ancestry():
    class Storage:
        def __init__(self,disk): self.disk = disk
        def run(self,argv,**kwargs):
            if argv[0].endswith('/pvs'): data = {'report':[{'pv':[{'pv_name':'/dev/sda3','vg_name':'pve','pv_uuid':'pv'}]}]}
            elif argv[0].endswith('/lsblk'): data = {'blockdevices':[{'path':'/dev/sda3','type':'part','children':[{'path':self.disk,'type':'disk'}]}]}
            else: data = {'report':[{'lv':[{'lv_name':'root','vg_name':'pve','lv_uuid':'lv'}]}]}
            return CompletedProcess(argv,0,json.dumps(data).encode(),b'')
    assert pve.installed_root(Storage('/dev/sda'),'/dev/sda')['lv_uuid'] == 'lv'
    with pytest.raises(ApplianceError,match='installed-root-wrong-disk'):
        pve.installed_root(Storage('/dev/sdb'),'/dev/sda')

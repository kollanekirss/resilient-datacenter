"""Guest collection boundary substitutions; these are not guest qualification."""
import importlib
from types import SimpleNamespace


def test_router_down_observation_uses_proxmox_without_trying_dead_ssh(site,monkeypatch):
    guest=importlib.import_module('appliance.lab_guest')
    pve=importlib.import_module('appliance.proxmox')
    monkeypatch.setattr(guest,'_plan',lambda:site)
    monkeypatch.setattr(pve,'observe_vm',lambda vmid,runner:{'vmid':101,'running':False,'boot_id':None,
        'config':{'name':'pilot-router','onboot':'0'},'nics':{},'iso_present':False,'boot_order':'order=scsi0'})
    actual=guest.observe('router')
    assert actual['vm']['running'] is False and actual['runtime'] is None
    assert len(actual['config_sha256'])==64


def test_bridge_free_clone_is_observed_without_normal_router_nic_parser(site,tmp_path,monkeypatch):
    guest=importlib.import_module('appliance.lab_guest')
    recovery=importlib.import_module('appliance.router_recovery')
    state=importlib.import_module('appliance.state')
    monkeypatch.setattr(guest,'_plan',lambda:site);monkeypatch.setattr(guest,'PRIVATE',tmp_path)
    state.write(tmp_path/'lab-clone.json',{'vmid':10101})
    monkeypatch.setattr(recovery,'_raw_vm',lambda vmid,runner:{'running':False,'pid':None,
        'config':{'onboot':'0','boot':'order=scsi0','net0':'virtio=02:bb:00:00:00:02,link_down=1'}})
    actual=guest.observe('clone')
    assert actual['running'] is False
    assert actual['config']['net0'].endswith('link_down=1')


def test_install_peak_metrics_use_memory_and_allocated_filesystem_bytes():
    guest=importlib.import_module('appliance.lab_guest')
    result=guest._acceptance_resource_sample('MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n',
                                            (1000,250,4096))
    assert result['memory_used_mib']==2048 and result['disk_used_bytes']==3072000
    assert type(result['at_milliseconds']) is int
    assert guest._acceptance_resource_sample('MemTotal: 1 kB\n',None) is None


def test_install_resource_sample_is_serializable_by_strict_guest_protocol(monkeypatch):
    guest=importlib.import_module('appliance.lab_guest')
    from appliance.contracts import canonical
    monkeypatch.setattr(guest.time,'monotonic',lambda:123.456)
    sample=guest._acceptance_resource_sample('MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n',None)
    assert sample['at_milliseconds']==123456
    assert b'123456' in canonical({'resource_samples':[sample]})

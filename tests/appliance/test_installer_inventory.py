"""Observe fresh fixture Linux inventories without touching host devices."""
import copy
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from appliance.contracts import ApplianceError, identity
from appliance.installer import inventory as live_inventory
from appliance.installer.live import live_gate


@pytest.fixture
def observed_linux(tmp_path,site,monkeypatch):
    for path,data in {
        'proc/sys/kernel/random/boot_id':b'boot-one',
        'proc/cpuinfo':b'processor : 0\nflags : vmx\nprocessor : 1\nprocessor : 2\nprocessor : 3\n',
        'proc/meminfo':b'MemTotal: 16777216 kB\n',
        'sys/firmware/efi/efivars/SecureBoot-example':b'\x07\0\0\0\0',
    }.items():
        file=tmp_path / path; file.parent.mkdir(parents=True,exist_ok=True); file.write_bytes(data)
    def disk(path,serial,transport,children=()):
        return {'path':path,'type':'disk','size':site['target']['size_bytes'],'model':'Pilot disk',
                'serial':serial,'wwn':'','tran':transport,'rm':transport=='usb','children':list(children)}
    target=disk('/dev/sda','PILOT_123','sata',[{'path':'/dev/sda1','type':'part','size':1024,'fstype':'ext4','mountpoints':[]}])
    usb=disk('/dev/sdb','BOOT','usb',[{'path':'/dev/sdb1','type':'part','size':1024,'fstype':'iso9660','mountpoints':['/cdrom']}])
    class Linux:
        rows=[target,usb]
        pvs=[]
        media='/dev/sdb1'
        addresses=[]
        def run(self,argv,**kwargs):
            name=Path(argv[0]).name
            if name=='lsblk': data={'blockdevices':self.rows}
            elif name=='findmnt': data={'filesystems':[{'source':self.media,'fstype':'iso9660','options':'ro,relatime'}]}
            elif name=='pvs': data={'report':[{'pv':self.pvs}]}
            elif name=='ip': data=self.addresses
            elif name=='uname': return CompletedProcess(argv,0,b'x86_64\n',b'')
            elif name=='udevadm':
                links={'/dev/sda':site['target']['by_id']+' /dev/disk/by-id/wwn-123',
                       '/dev/sdb':'/dev/disk/by-id/usb-BOOT','/dev/sdc':'/dev/disk/by-id/ata-CANARY'}
                return CompletedProcess(argv,0,('DEVLINKS='+links[argv[-1]]+'\n').encode(),b'')
            else: pytest.fail(argv)
            return CompletedProcess(argv,0,json.dumps(data).encode(),b'')
    ports=[{'name':name,**site['ports'][role],'up':False,'carrier':False}
           for role,name in (('management','enp1s0'),('wan','enp2s0'))]
    monkeypatch.setattr(live_inventory,'port_observations',lambda runner,root:ports)
    live_inventory.record_port_confirmation(site,'management',root=tmp_path)
    live_inventory.record_port_confirmation(site,'wan',root=tmp_path)
    return tmp_path,Linux(),ports


def test_inventory_boot_ancestry_and_selected_alias_are_preserved(observed_linux,site):
    root,runner,_=observed_linux
    result=live_inventory.inventory(runner,root=root,plan=site)
    assert result['disks'][0]['identity']==site['target']
    assert {'/dev/sdb','/dev/sdb1','/dev/disk/by-id/usb-BOOT'} <= set(result['boot_media_ids'])
    assert result['port_names']=={'management':'enp1s0','wan':'enp2s0'}
    assert result['supported'] and result['virtualization']
    live_gate(site,result,identity(site))
    runner.media='/dev/sda1'
    result=live_inventory.inventory(runner,root=root,plan=site)
    with pytest.raises(ApplianceError,match='target-is-boot-media'): live_gate(site,result,identity(site))


def test_inventory_refuses_other_disk_lvm_and_mounted_target(observed_linux,site):
    root,runner,_=observed_linux
    runner.rows[0]['children'][0]['mountpoints']=['/somewhere']
    runner.rows.append({'path':'/dev/sdc','type':'disk','size':4096,'serial':'CANARY','model':'canary',
                        'tran':'sata','rm':False,'children':[{'path':'/dev/sdc1','type':'part','size':2048,
                                                            'fstype':'LVM2_member','mountpoints':[]}]})
    runner.pvs=[{'pv_name':'/dev/sdc1','vg_name':'old','pv_uuid':'old'}]
    result=live_inventory.inventory(runner,root=root,plan=site)
    assert set(result['storage_conflicts'])=={'target-mounted','non-target-special-storage','non-target-volume-group'}
    with pytest.raises(ApplianceError,match='non-target-storage-conflict'): live_gate(site,result,identity(site))


def test_inventory_rejects_missing_boot_ancestry_and_stale_port_confirmation(observed_linux,site):
    root,runner,_=observed_linux
    (root / 'proc/sys/kernel/random/boot_id').write_text('other-boot')
    result=live_inventory.inventory(runner,root=root,plan=site)
    with pytest.raises(ApplianceError,match='port-identification-incomplete'): live_gate(site,result,identity(site))
    runner.media='/dev/not-observed'
    with pytest.raises(ApplianceError,match='inventory-boot-ancestry'):
        live_inventory.inventory(runner,root=root,plan=site)


def test_inventory_detects_unselected_active_port(observed_linux,site):
    root,runner,ports=observed_linux
    ports.append({'name':'enp3s0','permanent_mac':'02:aa:00:00:00:03','pci_path':'0000:03:00.0','driver':'igc','up':True,'carrier':False})
    result=live_inventory.inventory(runner,root=root,plan=site)
    with pytest.raises(ApplianceError,match='unselected-interface-active'): live_gate(site,result,identity(site))

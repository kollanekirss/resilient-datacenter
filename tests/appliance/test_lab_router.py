"""No PVE/FreeBSD execution: exercise orchestration, real policies and artifacts."""
import base64
import copy
import hashlib
import importlib
import json
from pathlib import Path
import subprocess

import pytest

from appliance import proxmox, router, state
from appliance.contracts import ApplianceError, identity
from test_proxmox import Pve
from test_router_config import runtime

KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'x'*32).decode()
HASH='$2y$12$'+'a'*53


def module():
    try:return importlib.import_module('appliance.lab_router')
    except ModuleNotFoundError:pytest.fail('automatic lab router provisioning is missing')


class LabPve(Pve):
    def run(self,argv,stdin=b'',timeout_s=30):
        if argv[:2]==[proxmox.QM,'stop']:
            self.mutations.append(argv);self.status='stopped'
            return subprocess.CompletedProcess(argv,0,b'',b'')
        if argv[:2]==[proxmox.QM,'start']:
            assert all('link_down=1' in v and 'bridge=' in v for k,v in self.config.items() if k.startswith('net'))
        return super().run(argv,stdin,timeout_s)


@pytest.fixture
def prepared(site,release,tmp_path,monkeypatch):
    m=module();run=LabPve();private=tmp_path/'private';captured={}
    monkeypatch.setattr(m,'_require_disposable',lambda p:None)
    monkeypatch.setattr(m,'_bcrypt',lambda p:HASH)
    def keygen(path,runner):
        path.write_bytes(b'PRIVATE KEY');path.chmod(0o600);return KEY
    monkeypatch.setattr(m,'_keypair',keygen)
    def remaster(dvd,output,payload,runner,release,**kwargs):
        captured.update(payload);output.write_bytes(b'ISO');output.chmod(0o600)
        assert kwargs=={'originals':{'/rdc-lab/original-rc':'/etc/rc'}}
        return {'sha256':hashlib.sha256(b'ISO').hexdigest(),'size_bytes':3}
    monkeypatch.setattr(m,'remaster_dvd',remaster)
    monkeypatch.setattr(m,'validate_release',lambda *a,**kw:None)
    monkeypatch.setattr(m,'validate_site',lambda *a,**kw:None)
    monkeypatch.setattr(router,'CHANNEL',tmp_path/'channel'/'router-channel.json')
    class Console:
        def __init__(self,vmid):pass
        def exchange(self,nonce,stage,*,timeout_s=300):
            manifest=json.loads(captured['/rdc-lab/manifest.json'])
            proof={'schema':1,'nonce':nonce,'stage':stage,'plan_id':identity(site),'config_sha256':manifest['policies']['bootstrap']}
            if stage=='verify':
                xml=captured['/rdc-lab/bootstrap.xml']
                observation=runtime(site,xml,{'interface_map':manifest['interface_map']})
                observation['config_xml']=xml.decode()
                proof.update(runtime=observation,host_public_key=KEY,hook_removed=True)
            return proof
        def close(self):pass
    monkeypatch.setattr(m,'SerialConsole',Console)
    return m,run,private,captured,{'password':'fresh random long secret','password_hash':'$6$example','ssh_public':KEY}


def test_setup_installs_then_proves_disk_boot_without_opening_links(site,release,prepared):
    m,run,private,payload,credentials=prepared
    result=m.setup_router(site,release,run,private,credentials)
    assert set(result['checks'])==set(router.CONSOLE_CHECKS) and all(result['checks'].values())
    assert result['state']=='bootstrap-verified' and result['hardware_qualification']=='not-run'
    assert run.status=='running' and run.config['boot']=='order=scsi0' and 'ide2' not in run.config
    assert len([a for a in run.mutations if a[1]=='start'])==2
    assert 'password' not in json.dumps(result) and 'config_xml' not in json.dumps(result)
    assert not (private/'lab-router'/'router-install.iso').exists()
    assert router._channel(site)['host_public_key']==KEY
    count=len(run.mutations)
    with pytest.raises(ApplianceError):m.setup_router(site,release,run,private,credentials)
    assert len(run.mutations)==count


@pytest.mark.parametrize('fault',['nonce','guard','mapping','password','host-key','xml','interrupt'])
def test_disk_proof_failure_stops_owned_guest_and_keeps_latch(site,release,prepared,monkeypatch,fault):
    m,run,private,payload,credentials=prepared;original=m.SerialConsole
    class Bad(original):
        def exchange(self,nonce,stage,**kwargs):
            proof=super().exchange(nonce,stage,**kwargs)
            if stage=='verify':
                if fault=='interrupt':raise KeyboardInterrupt
                if fault=='nonce':proof['nonce']='0'*64
                if fault=='guard':proof['runtime']['guard_installed']=False
                if fault=='mapping':proof['runtime']['interface_map']={}
                if fault=='password':proof['runtime']['config_xml']=proof['runtime']['config_xml'].replace(HASH,'$2y$12$'+'b'*53)
                if fault=='host-key':proof['host_public_key']='ssh-ed25519 invalid'
                if fault=='xml':proof['runtime']['config_xml']='<opnsense/>'
            return proof
    monkeypatch.setattr(m,'SerialConsole',Bad)
    with pytest.raises((ApplianceError,KeyboardInterrupt)):m.setup_router(site,release,run,private,credentials)
    assert run.status=='stopped'
    assert state.read(private/'lab-router'/'setup.json')['state']=='incomplete'
    assert not router.CHANNEL.exists()
    assert not (private/'lab-router'/'router-install.iso').exists()
    count=len(run.mutations)
    with pytest.raises(ApplianceError):m.setup_router(site,release,run,private,credentials)
    assert len(run.mutations)==count


def test_existing_owned_router_is_never_reformatted(site,release,prepared):
    m,run,private,payload,credentials=prepared
    proxmox.ensure_vm(proxmox.vm_spec(site,'router'),run,private);count=len(run.mutations)
    with pytest.raises(ApplianceError):m.setup_router(site,release,run,private,credentials)
    assert len(run.mutations)==count


def test_lab_guard_refuses_normal_host(site):
    with pytest.raises(ApplianceError):module()._require_disposable(site)


def test_installer_uses_official_install_and_restores_original_before_mtree(site,release,prepared,tmp_path):
    m,run,private,payload,credentials=prepared
    m.setup_router(site,release,run,private,credentials)
    install=payload['/rdc-lab/install'].decode();verify=payload['/rdc-lab/verify'].decode()
    assert install.index('original-rc /etc/rc')<install.index('bsdinstall opnsense-install')
    assert install.index('RDC1 ')<install.index('bsdinstall scriptedpart')
    assert 'gpart show da0' in install and 'diskinfo -v da0' in install
    assert 'gpart bootcode -b /boot/pmbr -p /boot/gptboot -i 2 da0' in install
    assert 'BSDINSTALL_CHROOT' in install and 'bsdinstall bootconfig' in install
    assert 'install -m 0600 /rdc-lab/bootstrap.xml "$target/conf/config.xml"' in install
    assert 'SSH_ORIGINAL_COMMAND=rdc-router' in verify and '99-rdc-lab' in verify
    for index,script in enumerate((install,verify)):
        path=tmp_path/str(index);path.write_text(script)
        assert subprocess.run(['/bin/sh','-n',str(path)],capture_output=True).returncode==0

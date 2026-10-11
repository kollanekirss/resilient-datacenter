"""Exercise file mapping/readback with a controlled external-tool adapter.

These tests never create a real ISO or qualify a boot path.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
from subprocess import CompletedProcess

import pytest

from appliance.contracts import ApplianceError
from appliance.installer import iso


@pytest.mark.parametrize('corrupt_readback',[False,True])
def test_remaster_preserves_original_and_requires_readback(tmp_path,monkeypatch,corrupt_readback):
    release = json.loads((Path(__file__).parents[2] / 'appliance/releases/v1.lock.json').read_text())
    bundle = tmp_path / 'bundle'; (bundle / 'media').mkdir(parents=True)
    for name in ('proxmox-iso','opnsense-dvd','probe-image','restic'):
        data = ('fixture-' + name).encode(); (bundle / 'media' / name).write_bytes(data)
        item = next(c for c in release['components'] if c['id']==name)
        item.get('expanded',item).update(sha256=hashlib.sha256(data).hexdigest(),size_bytes=len(data),max_bytes=len(data))
    launcher = b'#!/bin/bash\nreboot_action="reboot"\ntrap "err_reboot" ERR\n# set the hostname\ndhclient\n'
    init = b'#!/bin/sh\nexec switch_root /mnt /sbin/unconfigured.sh\n'
    grub = b'linux /boot/linux26\n'
    initrd = b'test-only initrd'
    monkeypatch.setattr(iso,'LAUNCHER_SHA256',hashlib.sha256(launcher).hexdigest())
    monkeypatch.setattr(iso,'INIT_SCRIPT_SHA256',hashlib.sha256(init).hexdigest())
    monkeypatch.setattr(iso,'GRUB_SHA256',hashlib.sha256(grub).hexdigest())
    monkeypatch.setattr(iso,'INITRD_SHA256',hashlib.sha256(initrd).hexdigest())
    monkeypatch.setattr(iso,'SOURCE_FILES',{})
    monkeypatch.setattr(iso,'verify_bundle',lambda *args:None)
    real_file = Path.is_file
    tools = {'/usr/bin/xorriso','/usr/bin/unsquashfs','/usr/bin/mksquashfs','/usr/bin/unmkinitramfs'}
    monkeypatch.setattr(Path,'is_file',lambda path: str(path) in tools or real_file(path))
    real_access = os.access
    monkeypatch.setattr(os,'access',lambda path,mode: str(path) in tools or real_access(path,mode))
    class FakeTools:
        def __init__(self): self.calls=[]; self.maps={}
        def run(self,argv,**kwargs):
            self.calls.append(argv)
            command = Path(argv[0]).name
            if command=='xorriso' and '-extract' in argv:
                i=argv.index('-extract'); source,destination=argv[i+1],Path(argv[i+2])
                if source=='/':
                    (destination / 'boot/grub').mkdir(parents=True)
                    (destination / '.cd-info').write_text("RELEASE='9.2'\nISORELEASE='1'\nPRODUCT='pve'\n")
                    (destination / 'pve-installer.squashfs').write_bytes(b'upper')
                    (destination / 'pve-base.squashfs').write_bytes(b'base')
                    (destination / 'boot/initrd.img').write_bytes(initrd)
                    (destination / 'boot/grub/grub.cfg').write_bytes(grub)
                else:
                    path = self.maps.get(source)
                    if path is None:
                        prefix = next(p for p in self.maps if source.startswith(p+'/'))
                        path = self.maps[prefix] / source[len(prefix)+1:]
                    destination.write_bytes(b'wrong' if corrupt_readback else path.read_bytes())
            elif command=='unsquashfs':
                destination=Path(argv[argv.index('-d')+1]); destination.mkdir()
                if argv[-1].endswith('pve-installer.squashfs'):
                    (destination / 'usr/sbin').mkdir(parents=True)
                    (destination / 'usr/sbin/unconfigured.sh').write_bytes(launcher)
                else:
                    for path in ('usr/bin/python3.13','usr/lib/python3.13/os.py','usr/lib/python3.13/tomllib/__init__.py','usr/lib/python3.13/json/__init__.py'):
                        file=destination / path;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(b'fixture')
                    (destination / 'usr/bin/python3').symlink_to('python3.13')
            elif command=='unmkinitramfs':
                destination=Path(argv[-1]);destination.mkdir();(destination / 'init').write_bytes(init)
            elif command=='mksquashfs':
                changed=(Path(argv[1]) / 'usr/sbin/unconfigured.sh').read_bytes()
                assert b'dhclient' not in changed and b'appliance.installer.entry' in changed
                assert (Path(argv[1]) / 'usr/local/sbin/rdc-appliance').stat().st_mode & 0o111
                Path(argv[2]).write_bytes(changed)
            elif command=='xorriso':
                assert argv[argv.index('-boot_image')+1:argv.index('-boot_image')+3]==['any','replay']
                for i,arg in enumerate(argv):
                    if arg=='-map': self.maps[argv[i+2]]=Path(argv[i+1])
                Path(argv[argv.index('-outdev')+1]).write_bytes(b'test-only fake ISO')
            else: pytest.fail(argv)
            return CompletedProcess(argv,0,b'',b'')
    runner=FakeTools(); output=tmp_path / 'candidate.iso'
    if corrupt_readback:
        with pytest.raises(ApplianceError,match='iso-readback-mismatch'):
            iso.build_iso(release,bundle,output,runner=runner,qualification_build=True)
        assert not output.exists()
    else:
        assert iso.build_iso(release,bundle,output,runner=runner,qualification_build=True)==output
        manifest=json.loads(output.with_suffix('.iso.json').read_text())
        assert manifest['qualification']=='not-run'
        assert manifest['image']['sha256']==hashlib.sha256(output.read_bytes()).hexdigest()
    assert (bundle / 'media/proxmox-iso').read_bytes()==b'fixture-proxmox-iso'
    assert not list(tmp_path.glob('.appliance-iso-*'))

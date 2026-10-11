"""Offline ISO remastering of one pinned upstream source; no disk-device writes.

Assembly is a qualification candidate. Linux tools and actual media are required
when invoked; mock process tests cannot qualify the resulting boot path.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile

from appliance.contracts import canonical, identity, require
from appliance.plan import validate_release
from .adapters.pve import ADAPTER_ID, LAUNCHER_SHA256, SOURCE_REVISION, SOURCE_FILES, CLI_WRAPPER
from .media import _copy_verified, _safe_parents, _write_new, verify_bundle
from .payload import file_record, owned_path, prepare_runtime

INITRD_SHA256 = '8fdf76b44287af130358c142f1743c30e1b10df21bae1693283736603bef3cba'
INIT_SCRIPT_SHA256 = '8b0ca78470877fddee457fd044f70f88127a5ce761cda63f35e26a73ddd96265'
GRUB_SHA256 = 'f69d3992415aea9f4dbbfd583ca184ad2a95c38efd47f9fcd8ea4ddd44960947'


def patch_launcher(raw: bytes) -> bytes:
    require(hashlib.sha256(raw).hexdigest() == LAUNCHER_SHA256, 'upstream-launcher-mismatch')
    marker = b'# set the hostname\n'
    require(raw.count(marker) == 1, 'upstream-launcher-layout')
    prefix = raw.split(marker)[0]
    prefix = prefix.replace(b'trap "err_reboot" ERR', b'trap "rdc_hold" ERR')
    prefix = prefix.replace(b'trap "err_reboot" INT', b'trap "rdc_hold" INT')
    # Define before any trapped command. Never return from PID1 or reboot on
    # failure; an interrupted installation must be inspected at the console.
    prefix = prefix.replace(b'reboot_action="reboot"', b'''umask 077
rdc_hold() {
    trap - ERR INT
    echo 'Appliance stopped safely. Use local recovery; do not retry an interrupted erase.'
    while :; do /bin/sleep 3600; done
}
reboot_action="reboot"''', 1)
    return prefix + b'''
# Appliance dispatch precedes all upstream network and installer startup.
export PYTHONPATH=/usr/lib/rdc-appliance
export PYTHONNOUSERSITE=1
/usr/bin/python3 -m appliance.installer.entry
rdc_hold
'''


def patch_boot_config(raw: bytes) -> bytes:
    if hashlib.sha256(raw).hexdigest() == GRUB_SHA256:
        # The stock menu contains rescue disk boot and memtest entries. A
        # closed appliance menu removes every alternative installation path.
        return b'''serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input console serial
terminal_output console serial
set timeout=-1
set default=0
menuentry 'Appliance local setup (unqualified)' {
 linux /boot/linux26 ro ramdisk_size=16777216 rw ipv6.disable=1 rdc.appliance=1
 initrd /boot/initrd.img
}
menuentry 'Appliance local setup (serial console)' {
 linux /boot/linux26 ro ramdisk_size=16777216 rw ipv6.disable=1 rdc.appliance=1 console=ttyS0,115200
 initrd /boot/initrd.img
}
menuentry 'UEFI firmware settings' {
 fwsetup
}
'''
    try: text = raw.decode('utf-8')
    except UnicodeError:
        require(False, 'upstream-boot-layout')
    require(not re.search(r'^\s*(?:configfile|source|chainloader)\s', text, re.M), 'upstream-boot-indirection')
    lines = []
    for line in text.splitlines():
        match = re.match(r'^(\s*(?:linux|linuxefi)\s+)(\S+)(.*)$', line)
        if match:
            require(match[2] == '/boot/linux26', 'upstream-kernel-layout')
            args = match[3].split()
            require(not any(a.startswith(('ip=', 'BOOTIF=', 'netroot=')) for a in args), 'upstream-network-boot')
            args = [a for a in args if a not in ('proxdebug','proxmox-debug','proxauto',
                    'proxmox-start-auto-installer','proxtui','proxmox-tui-mode')
                    and not a.startswith(('ipv6.disable=', 'rdc.appliance='))]
            line = match[1] + match[2] + ' ' + ' '.join(args + ['ipv6.disable=1','rdc.appliance=1'])
        lines.append(line)
    return ('\n'.join(lines) + '\n').encode()


def audit_init_script(raw: bytes) -> None:
    require(len(raw) <= 1024 * 1024 and b'switch_root' in raw and b'unconfigured.sh' in raw, 'upstream-init-dispatch')
    # Conservative rejection is deliberate. A new initrd needs source review.
    text = '\n'.join(line for line in raw.decode('utf-8').splitlines() if not line.lstrip().startswith('#'))
    require(not re.search(r'\b(?:dhclient|udhcpc|ifup|ifconfig|dhcpcd|networkctl|NetworkManager|iwd)\b|\bip\s+(?:addr|link|route)', text),
            'upstream-init-networking')


def build_iso(lock: dict, payload: Path, output: Path, *, runner, qualification_build=False) -> Path:
    lock = validate_release(lock, production=True)
    unqualified = lock['profile']['qualification'] != 'qualified' or lock['budgets']['qualification'] != 'qualified'
    require(not unqualified or qualification_build is True, 'qualification-build-required')
    require(lock['adapter_id'] == ADAPTER_ID, 'unsupported-installer-adapter')
    payload, output = _safe_parents(payload), _safe_parents(output)
    require(output.suffix == '.iso' and output.parent.is_dir() and not output.exists(), 'iso-output')
    require(not output.with_suffix('.iso.json').exists(), 'iso-output')
    verify_bundle(payload, lock)
    source = payload / 'media/proxmox-iso'
    tools = ['/usr/bin/xorriso','/usr/bin/unsquashfs','/usr/bin/mksquashfs','/usr/bin/unmkinitramfs']
    for executable in tools:
        require(Path(executable).is_file() and os.access(executable,os.X_OK), 'iso-tool-missing')
    # Need room for extraction, modified live filesystem, image and readback.
    require(shutil.disk_usage(output.parent).free >= 12 * 1024**3, 'iso-workspace-space')
    with tempfile.TemporaryDirectory(prefix='.appliance-iso-', dir=output.parent) as temporary:
        work = Path(temporary); tree = work / 'iso'; live = work / 'live'; base = work / 'base'
        runner.run(['/usr/bin/xorriso','-osirrox','on','-indev',str(source),'-extract','/',str(tree)],timeout_s=7200)
        info = (tree / '.cd-info').read_text()
        require("RELEASE='9.2'" in info and "ISORELEASE='1'" in info and "PRODUCT='pve'" in info, 'upstream-iso-product')
        squash = [p for p in tree.glob('*installer*.squashfs') if p.is_file() and not p.is_symlink()]
        require(len(squash) == 1, 'upstream-live-layout')
        require(not any((tree / name).exists() for name in ('answer.toml','auto-installer-mode.toml','rdc-appliance')), 'upstream-prepared-iso')
        runner.run(['/usr/bin/unsquashfs','-no-progress','-d',str(live),str(squash[0])],timeout_s=7200)
        runner.run(['/usr/bin/unsquashfs','-no-progress','-d',str(base),str(tree / 'pve-base.squashfs')],timeout_s=7200)
        # The actual initrd overlays installer above base. Python is shipped
        # by the base layer; testing only the installer layer is incorrect.
        def layered(relative):
            upper = live / relative
            return upper if upper.exists() or upper.is_symlink() else base / relative
        python = layered('usr/bin/python3')
        require(python.is_symlink() and os.readlink(python) == 'python3.13','upstream-python-layout')
        for relative in ('usr/bin/python3.13','usr/lib/python3.13/os.py',
                         'usr/lib/python3.13/tomllib/__init__.py','usr/lib/python3.13/json/__init__.py'):
            require(layered(relative).is_file(),'upstream-python-runtime-missing')
        launcher = owned_path(live,'usr/sbin/unconfigured.sh')
        patched = patch_launcher(launcher.read_bytes())
        for relative,digest in SOURCE_FILES.items():
            require(file_record(owned_path(live,relative))['sha256'] == digest,'upstream-source-mismatch')
        require(file_record(tree / 'boot/initrd.img')['sha256'] == INITRD_SHA256,'upstream-initrd-mismatch')
        # Examine initrd before trusting that our dispatch is early enough.
        runner.run(['/usr/bin/unmkinitramfs',str(tree / 'boot/initrd.img'),str(work / 'initrd')],timeout_s=300)
        inits = [p for p in (work / 'initrd').rglob('init') if p.is_file() and not p.is_symlink()]
        require(len(inits) == 1, 'upstream-init-layout')
        require(file_record(inits[0])['sha256'] == INIT_SCRIPT_SHA256,'upstream-init-mismatch')
        audit_init_script(inits[0].read_bytes())
        launcher.write_bytes(patched); launcher.chmod(0o755)
        config = owned_path(tree,'boot/grub/grub.cfg')
        require(file_record(config)['sha256'] == GRUB_SHA256,'upstream-grub-mismatch')
        config.write_bytes(patch_boot_config(config.read_bytes()))
        boot_files = [config]
        appliance = tree / 'rdc-appliance'; appliance.mkdir(mode=0o700)
        runtime = prepare_runtime(Path(__file__).parents[1], appliance / 'runtime')
        live_runtime = owned_path(live,'usr/lib/rdc-appliance')
        require(not live_runtime.exists(), 'upstream-runtime-conflict')
        shutil.copytree(appliance / 'runtime',live_runtime)
        live_wrapper = owned_path(live,'usr/local/sbin/rdc-appliance')
        live_wrapper.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        require(not live_wrapper.exists(),'upstream-runtime-conflict')
        _write_new(live_wrapper,CLI_WRAPPER); live_wrapper.chmod(0o755)
        (appliance / 'media').mkdir(mode=0o700)
        by_id = {i['id']:i for i in lock['components']}
        for name in ('opnsense-dvd','probe-image','restic'):
            content = by_id[name].get('expanded',by_id[name])
            _copy_verified(payload / 'media' / name, appliance / 'media' / name, content)
        _write_new(appliance / 'release.lock.json',canonical(lock))
        build = {'schema':1,'adapter_id':ADAPTER_ID,'source_revision':SOURCE_REVISION,
                 'release_identity':identity(lock),'runtime_identity':identity(runtime),
                 'qualification':'not-run','qualification_build':bool(qualification_build),
                 'launcher':file_record(launcher),'init_script':file_record(inits[0])}
        _write_new(appliance / 'build.json',canonical(build))
        hook = tree / 'proxmox-first-boot'
        require(not hook.exists(), 'upstream-hook-conflict')
        _write_new(hook,b'#!/bin/sh\nexec /usr/bin/systemctl start rdc-first-boot.service\n')
        hook.chmod(0o755)
        rebuilt = work / 'installer.squashfs'
        runner.run(['/usr/bin/mksquashfs',str(live),str(rebuilt),'-noappend','-all-root','-comp','zstd','-no-progress'],timeout_s=7200)
        candidate = work / 'candidate.iso'
        command = ['/usr/bin/xorriso','-indev',str(source),'-outdev',str(candidate),'-boot_image','any','replay',
                   '-map',str(rebuilt),'/' + squash[0].name,'-map',str(appliance),'/rdc-appliance',
                   '-map',str(hook),'/proxmox-first-boot']
        for config in boot_files:
            command.extend(['-map',str(config),'/' + config.relative_to(tree).as_posix()])
        command.extend(['-commit','-end'])
        runner.run(command,timeout_s=7200)
        # Read back the actual image's mapped files, not just the input tree.
        readbacks = [(rebuilt,'/' + squash[0].name),(hook,'/proxmox-first-boot')]
        readbacks += [(p,'/' + p.relative_to(tree).as_posix()) for p in boot_files]
        readbacks += [(p,'/rdc-appliance/' + p.relative_to(appliance).as_posix())
                      for p in sorted(appliance.rglob('*')) if p.is_file()]
        for index,(source_path,iso_path) in enumerate(readbacks):
            readback = work / ('readback-' + str(index))
            runner.run(['/usr/bin/xorriso','-osirrox','on','-indev',str(candidate),'-extract',iso_path,str(readback)],timeout_s=7200)
            require(file_record(readback) == file_record(source_path), 'iso-readback-mismatch')
        result = {**build,'image':file_record(candidate),'build_id':identity(build)}
        # No overwrite, including a racing destination; publish report last.
        os.link(candidate,output)
        _write_new(output.with_suffix('.iso.json'),canonical(result))
        descriptor = os.open(output.parent,os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    return output

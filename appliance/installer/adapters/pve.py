"""Pinned Proxmox 9.2-1 / installer 9.2.5 candidate, never self-authorizing.

Source: proxmox/pve-installer at 32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9.
The caller owns fresh inventory, private live-session consent and serialization.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re

from appliance.contracts import ApplianceError, canonical, identity, load_json, require
from appliance.media import verify_file
from appliance.state import write
from appliance.installer.payload import file_record, owned_path, verify_runtime
from appliance.installer.media import _copy_verified, _write_new

SOURCE_REVISION = '32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9'
LAUNCHER_SHA256 = '7a5be4ff18f286b9216811a6216e3ddd098d49206d4c900192c75b3c89b74d7c'
SOURCE_FILES = {
    'usr/bin/proxmox-low-level-installer': 'b0101a3a0bc4131d4f42a87dd69f3b0305fcc65ec8b57ee18e3f9cdabd9dc348',
    'usr/share/perl5/Proxmox/Install.pm': '43a4271c80a40cb2030f5567723ffe2a545f9bc49ea3dbb4bb586efeaf77d25e',
}
ADAPTER_ID = 'pve-9-2-1'
ROOT_DEVICE = '/dev/mapper/pve-root'
CLI_WRAPPER = b'#!/bin/sh\nexec /usr/bin/env PYTHONPATH=/usr/lib/rdc-appliance PYTHONNOUSERSITE=1 /usr/bin/python3 -m appliance "$@"\n'


def answer_bytes(plan: dict, password_hash: str, *, disk_path: str, management_name: str) -> bytes:
    require(type(password_hash) is str and bool(re.fullmatch(
        r'(?:\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}|'
        r'\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43,})', password_hash)),
        'password-hash-required')
    require(type(disk_path) is str and bool(re.fullmatch(r'/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)', disk_path)),
            'installer-disk-selector')
    require(type(management_name) is str and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', management_name)),
            'installer-nic-selector')
    require(bool(re.fullmatch(r'[a-z][a-z0-9-]{0,62}', plan['site_id'])), 'installer-hostname')
    network = plan['networks']['management']
    cidr = str(ipaddress.IPv4Interface(network['host_ip'] + '/' + str(ipaddress.IPv4Network(network['cidr']).prefixlen)))
    q = json.dumps  # These bounded ASCII values share TOML's basic-string escaping.
    return ('[global]\nkeyboard = "en-us"\ncountry = "us"\ntimezone = "UTC"\n'
            f'fqdn = {q(plan["site_id"] + ".home.arpa")}\nmailto = "root@localhost.invalid"\n'
            f'root-password-hashed = {q(password_hash)}\nreboot-on-error = false\n'
            '[network]\nsource = "from-answer"\n'
            f'cidr = {q(cidr)}\ngateway = {q(network["gateway"])}\ndns = {q(network["gateway"])}\n'
            f'filter.ID_NET_NAME = {q(management_name)}\n'
            '[disk-setup]\nfilesystem = "ext4"\n'
            f'disk-list = [{q(disk_path.removeprefix("/dev/"))}]\n'
            '[first-boot]\nsource = "from-iso"\nordering = "before-network"\n').encode('ascii')


def _json(runner, argv):
    try:
        return json.loads(runner.run(argv).stdout)
    except (ValueError, UnicodeError):
        raise ApplianceError('upstream-observation-invalid') from None


def verify_upstream_selection(runner, *, disk_path: str, management_name: str, root=Path('/')):
    """Refresh upstream caches and prove the exact selectors it will consume."""
    runner.run(['/usr/bin/proxmox-low-level-installer', 'dump-env'])
    runner.run(['/usr/bin/proxmox-low-level-installer', 'dump-udev'])
    base = Path(root) / 'run/proxmox-installer'
    env = load_json(base / 'run-env-info.json', limit=4 * 1024 * 1024)
    udev = load_json(base / 'run-env-udev.json', limit=4 * 1024 * 1024)
    disks = env.get('disks', [])
    # Upstream disk-list uses suffix matching. Require it to match exactly one.
    require(type(disks) is list and all(type(d) is list and len(d) >= 6 for d in disks), 'upstream-disk-layout')
    matches = [d for d in disks if type(d[1]) is str and d[1].endswith(disk_path[5:])]
    require(len(matches) == 1 and matches[0][1] == disk_path, 'upstream-disk-ambiguous')
    nics = udev.get('nics', {})
    matches = [key for key, props in nics.items() if props.get('ID_NET_NAME') == management_name]
    require(matches == [management_name], 'upstream-nic-ambiguous')


def installed_root(runner, disk_path: str) -> dict:
    """Before vg activation or mounting, reject any extra PV backing pve."""
    report = _json(runner, ['/usr/sbin/pvs', '--reportformat', 'json', '-o', 'pv_name,vg_name,pv_uuid'])
    rows = [row for group in report.get('report', []) for row in group.get('pv', []) if row.get('vg_name') == 'pve']
    require(len(rows) == 1, 'installed-root-ambiguous')
    pv = rows[0]['pv_name']
    ancestry = _json(runner, ['/usr/bin/lsblk', '--json', '--inverse', '--paths', '--output', 'PATH,TYPE', pv])
    def disks(nodes):
        return [node['path'] for node in nodes if node.get('type') == 'disk'] + [
            path for node in nodes for path in disks(node.get('children', []))]
    require(set(disks(ancestry.get('blockdevices', []))) == {disk_path}, 'installed-root-wrong-disk')
    lvs = _json(runner, ['/usr/sbin/lvs', '--reportformat', 'json', '-o', 'lv_name,vg_name,lv_uuid'])
    roots = [r for g in lvs.get('report', []) for r in g.get('lv', []) if r.get('vg_name') == 'pve' and r.get('lv_name') == 'root']
    require(len(roots) == 1 and bool(roots[0].get('lv_uuid')), 'installed-root-missing')
    return {'device': ROOT_DEVICE, 'lv_uuid': roots[0]['lv_uuid'], 'pv_uuid': rows[0]['pv_uuid'], 'disk_path': disk_path}


def install(answer: bytes, runner, *, disk_path: str, management_name: str, root=Path('/'), prepared=False) -> dict:
    """Only called inside install_site's live-session gate; never reboots."""
    require(type(answer) is bytes and 0 < len(answer) <= 65536, 'installer-answer')
    if not prepared:
        verify_upstream_selection(runner, disk_path=disk_path, management_name=management_name, root=root)
    result = runner.run(['/usr/bin/proxmox-auto-installer'], stdin=answer, timeout_s=7200)
    # The pinned frontend can return zero at EOF without a Finished message.
    # Never infer task completion from exit status alone.
    require(b"INFO: Finished: 'ok'" in result.stderr and b'INFO: Installation done.' in result.stderr,
            'upstream-install-incomplete')
    observed = installed_root(runner, disk_path)
    return {'schema': 1, 'adapter_id': ADAPTER_ID, 'upstream_complete': True, 'root': observed}


def stage_target(receipt: dict, payload: Path, plan: dict, runner, *, target=Path('/target')) -> dict:
    """Mount only the independently matched new root, and publish marker last."""
    require(receipt.get('adapter_id') == ADAPTER_ID and receipt.get('upstream_complete') is True,
            'upstream-install-incomplete')
    runtime = verify_runtime(payload / 'runtime')
    release = load_json(payload / 'release.lock.json')
    build = load_json(payload / 'build.json')
    require(build.get('release_identity') == identity(release) and build.get('runtime_identity') == identity(runtime),
            'payload-build-mismatch')
    require(installed_root(runner, receipt['root']['disk_path']) == receipt['root'], 'installed-root-changed')
    require(target == Path('/target'), 'installer-target-path')
    runner.run(['/usr/bin/proxmox-chroot', 'prepare', '--filesystem', 'ext4'])
    try:
        mounted = _json(runner, ['/usr/bin/findmnt', '--json', '--mountpoint', str(target), '--output', 'SOURCE,FSTYPE,OPTIONS,UUID'])
        rows = mounted.get('filesystems', [])
        require(len(rows) == 1 and rows[0].get('source') == ROOT_DEVICE and rows[0].get('fstype') == 'ext4'
                and 'rw' in rows[0].get('options', '').split(','), 'installed-root-mount')
        require(installed_root(runner,receipt['root']['disk_path']) == receipt['root'],'installed-root-changed')
        require(type(rows[0].get('uuid')) is str and bool(re.fullmatch(r'[a-fA-F0-9-]{32,36}',rows[0]['uuid'])),
                'installed-root-uuid')
        receipt = {**receipt,'root':{**receipt['root'],'filesystem_uuid':rows[0]['uuid']}}
        def finalize():
            units = []
            for unit in (payload / 'runtime/appliance/systemd').glob('*'):
                if unit.suffix == '.service' and b'WantedBy=' in unit.read_bytes():
                    units.append(unit.name)
            require('rdc-first-boot.service' in units,'staging-first-boot-unit')
            runner.run(['/usr/bin/systemctl','--root',str(target),'enable',*sorted(units)])
            runner.run(['/usr/sbin/chroot',str(target),'/usr/sbin/update-grub'],timeout_s=120)
            runner.run(['/usr/sbin/chroot',str(target),'/usr/sbin/proxmox-boot-tool','refresh'],timeout_s=120)
        return stage_files(receipt, payload, plan, target=target,finalize=finalize)
    finally:
        runner.run(['/usr/bin/proxmox-chroot', 'cleanup', '--filesystem', 'ext4'])


def stage_files(receipt, payload, plan, *, target: Path, finalize=None):
    """Filesystem portion separately testable against a disposable directory."""
    from appliance.installer.first_boot import network_dependencies
    runtime = verify_runtime(payload / 'runtime')
    release = load_json(payload / 'release.lock.json')
    build = load_json(payload / 'build.json')
    require(build['release_identity'] == identity(release) and build['runtime_identity'] == identity(runtime),
            'payload-build-mismatch')
    require(plan['release_id'] == release['release_id'], 'bundle-release-mismatch')
    private = owned_path(target, 'var/lib/rdc-appliance/private')
    require(not private.exists(), 'staging-already-exists')
    private.mkdir(parents=True, mode=0o700)
    files = []
    def copy(source, relative, expected, mode=0o600):
        destination = owned_path(target, relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        _copy_verified(source, destination, expected)
        destination.chmod(mode)
        files.append({'relative_path': relative, 'component': dict(expected)})
    for item in runtime['files']:
        copy(payload / 'runtime' / item['path'], 'usr/lib/rdc-appliance/' + item['path'],
             {k:item[k] for k in ('sha256','size_bytes','max_bytes')}, 0o644)
    for name in ('release.lock.json', 'build.json'):
        copy(payload / name, 'var/lib/rdc-appliance/' + name, file_record(payload / name))
    wrapper = owned_path(target,'usr/local/sbin/rdc-appliance')
    wrapper.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    _write_new(wrapper,CLI_WRAPPER)
    wrapper.chmod(0o755)
    files.append({'relative_path':'usr/local/sbin/rdc-appliance','component':file_record(wrapper)})
    by_id = {item['id']:item for item in release['components']}
    for component_id in ('opnsense-dvd','probe-image','restic'):
        component = by_id[component_id]
        expected = component.get('expanded',component)
        copy(payload / 'media' / component_id, 'var/lib/rdc-appliance/media/' + component_id,
             {k:expected[k] for k in ('sha256','size_bytes','max_bytes')}, 0o755 if component_id=='restic' else 0o600)
    for item in runtime['files']:
        if item['path'].startswith('appliance/systemd/') and Path(item['path']).suffix in ('.service','.timer','.conf'):
            unit = payload / 'runtime' / item['path']
            copy(unit,'etc/systemd/system/' + item['path'][len('appliance/systemd/'):],file_record(unit),0o644)
    for relative, raw in network_dependencies().items():
        destination = owned_path(target, relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        _write_new(destination, raw); destination.chmod(0o644)
        files.append({'relative_path': relative, 'component': file_record(destination)})
    write(private / 'site.json', plan)
    from appliance.files import atomic_write, read_optional
    atomic_write(target,'/etc/default/grub.d/90-rdc-appliance.cfg',
                 b'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ipv6.disable=1"\n')
    cmdline = read_optional(target,'/etc/kernel/cmdline')
    if cmdline is not None:
        words = [word for word in cmdline.decode('ascii').split() if not word.startswith('ipv6.disable=')]
        atomic_write(target,'/etc/kernel/cmdline',(' '.join(words + ['ipv6.disable=1'])+'\n').encode())
    if finalize is not None:
        finalize()
    # Mutable site configuration is bound at staging but excluded from the
    # immutable receipt: management transactions can legitimately update it.
    marker = {'schema': 1, 'complete': True, 'plan_id': identity(plan), 'build_id': identity(build),
              'target': plan['target'], 'root': receipt['root'], 'files': files}
    for directory in sorted({owned_path(target, f['relative_path']).parent for f in files}, key=str):
        fd = os.open(directory,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    write(private / 'staged.json', marker)
    return marker

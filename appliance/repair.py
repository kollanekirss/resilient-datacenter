"""Read-only target identification and narrowly owned management repair.

This path never invokes an installer, partitioner, VM creation or formatting.
USB repair operates only on an already mounted /target after fresh root/LVM
ancestry checks. The operator mounts/selects the existing host explicitly.
"""
import json
import os
from pathlib import Path
import platform
import re
import secrets

from .contracts import ApplianceError, identity, load_json, require
from . import state


def validate_repair_target(target):
    require(type(target) is dict and type(target.get('matches')) is int
            and target['matches'] == 1, 'repair-target-ambiguous')
    require(target.get('owned') is True, 'repair-target-unowned')
    require(target.get('confirmed') is True, 'repair-not-confirmed')


def _environment(root, runner):
    real = root == Path('/target') and platform.system() == 'Linux' and os.geteuid() == 0
    require(real or getattr(runner, 'target_root', None) == root, 'repair-environment')


def _resolve_disk(target, runner):
    """Resolve stable identity afresh; a repair USB can change /dev/sd ordering."""
    try:
        rows = json.loads(runner.run(['/usr/bin/lsblk', '--json', '--bytes', '--paths', '--nodeps',
            '--output', 'PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN']).stdout)['blockdevices']
        matches, identifiers = [], []
        for row in rows:
            if row.get('type') != 'disk': continue
            path = row['path']
            require(type(path) is str and re.fullmatch(r'/dev/[A-Za-z0-9_-]+',path) is not None,
                    'repair-disk-identity')
            serial, wwn = str(row.get('serial') or '').strip(), str(row.get('wwn') or '').strip()
            if (target['serial'] and serial == target['serial']) or (target['wwn'] and wwn == target['wwn']):
                identifiers.append(path)
            raw = runner.run(['/usr/bin/udevadm', 'info', '--query=property', '--name', path]).stdout
            props = dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
            if target['by_id'] not in props.get('DEVLINKS','').split(): continue
            transport = str(row.get('tran') or ('virtio' if re.fullmatch(r'/dev/vd[a-z]+',path) else props.get('ID_BUS',''))).strip()
            if transport == 'spi': transport = 'scsi'
            current = {'by_id':target['by_id'], 'serial':serial, 'wwn':wwn,
                       'size_bytes':int(row['size']), 'model':str(row.get('model') or props.get('ID_MODEL') or '(not reported)').strip(),
                       'transport':transport}
            require(current == target, 'repair-disk-identity')
            matches.append(path)
        require(len(matches) == 1 and identifiers == matches, 'repair-disk-identity')
        return matches[0]
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ApplianceError('repair-disk-identity') from None


def _observe_target(root, runner):
    from .installer.adapters.pve import installed_root, ROOT_DEVICE
    staged = state.read(root / 'var/lib/rdc-appliance/private/staged.json')
    require(staged.get('schema') == 1 and staged.get('complete') is True, 'repair-target-unowned')
    recorded = staged.get('root', {})
    require(type(recorded) is dict and bool(recorded.get('filesystem_uuid')), 'repair-root-identity')
    disk = _resolve_disk(staged['target'], runner)
    observed = installed_root(runner, disk)
    require(observed == {**{key: recorded.get(key) for key in ('device', 'lv_uuid', 'pv_uuid')}, 'disk_path':disk},
            'repair-root-identity')
    try:
        result = json.loads(runner.run(['/usr/bin/findmnt', '--json', '--mountpoint', str(root),
            '--output', 'SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    except (ValueError, UnicodeError):
        raise ApplianceError('repair-mount') from None
    mounts = result.get('filesystems', [])
    require(len(mounts) == 1 and mounts[0].get('source') == ROOT_DEVICE
            and mounts[0].get('fstype') == 'ext4' and 'rw' in mounts[0].get('options', '').split(','), 'repair-mount')
    require(mounts[0].get('uuid') == recorded['filesystem_uuid'], 'repair-root-identity')
    return staged


def discover_target(runner, *, root=Path('/target')):
    root = Path(root)
    _environment(root, runner)
    staged = _observe_target(root, runner)
    return {'schema': 1, 'matches': 1, 'owned': True, 'confirmed': False,
            'root': str(root), 'target': staged['target'], 'build_id': staged['build_id']}


def repair_host(target, export, runner):
    from .files import read_optional
    from .host_network import safe_management_files, collect_ports, resolve_ports
    validate_repair_target(target)
    root = Path(target.get('root', '/target'))
    _environment(root, runner)
    staged = _observe_target(root, runner)
    require(target.get('target') == staged['target'] and target.get('build_id') == staged['build_id'], 'repair-root-identity')
    export = Path(export)
    plan = state.read(export / 'site.json')
    from .plan import validate_site, validate_release
    release = validate_release(state.read(export / 'release.lock.json'), production=True)
    validate_site(plan, release)
    host = state.read(export / 'host.json')
    require(plan['target'] == staged['target'], 'repair-plan-identity')
    private = root / 'var/lib/rdc-appliance/private'
    existing = state.read(private / 'site.json')
    require(plan['site_id'] == existing['site_id'], 'repair-plan-identity')
    good = host.get('known-good')
    require(type(good) is dict and good.get('plan', {}).get('site_id') == plan['site_id']
            and good['plan'].get('target') == plan['target'], 'repair-host-manifest')
    validate_site(good['plan'], release)
    # Restore only a derived management-only fallback. Never apply arbitrary
    # archive paths or reactivate links/credentials from a copied router.
    ports = resolve_ports(good['plan'], collect_ports(Path('/'), runner))
    files = safe_management_files(good['plan'], ports)
    op = state.begin(private / 'operations', {'kind': 'repair-management', 'plan_id': identity(plan),
                     'build_id': staged['build_id'], 'nonce': secrets.token_hex(16)})
    from .rollback import _encode, _digest, _restore
    network = private / 'network'
    with state.lock(network):
        # Boot recovery understands this journal before the first file changes.
        # Even an interrupted repair restores the safe management-only target.
        record = {'schema': 1, 'transaction_id': op, 'phase': 'pending', 'created': 0,
                  'deadline': 0, 'boot_id': 'usb-repair', 'challenge': secrets.token_urlsafe(24),
                  'plan': good['plan'], 'before_plan': good['plan'], 'resolved_ports': ports,
                  'before_profile': 'management-only', 'before': _encode(files), 'desired': _encode(files),
                  'original_digests': {p: _digest(read_optional(root, p)) for p in files}}
        state.write(network / 'pending.json', record)
        state.write(private / 'site.json', good['plan'])
        _restore(root, runner, network, record, boot=True)
    state.finish(private / 'operations', op, {'files': sorted(files), 'network_activated': False})
    return {'schema': 1, 'state': 'configured', 'repaired': sorted(files), 'network_activated': False,
            'next_action': 'Unmount the selected host, remove USB and verify direct management after boot.'}

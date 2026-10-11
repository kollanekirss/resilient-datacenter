"""Fresh, read-only Linux disk/NIC observation. Unknown ancestry fails closed."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from appliance.contracts import ApplianceError, identity, require
from appliance.state import read, write


def _json(runner, argv):
    try: return json.loads(runner.run(argv).stdout)
    except (ValueError,UnicodeError): raise ApplianceError('inventory-command-data') from None


def _small(path: Path, limit=65536):
    try:
        with path.open('rb') as stream: raw = stream.read(limit + 1)
        require(len(raw) <= limit, 'inventory-source-size')
        return raw.decode('utf-8').strip()
    except (OSError,UnicodeError): raise ApplianceError('inventory-source-missing') from None


def port_observations(runner, *, root=Path('/')) -> list[dict]:
    links = _json(runner,['/usr/sbin/ip','-json','link','show'])
    result = []
    for row in links:
        name = row.get('ifname','')
        require(bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',name)), 'inventory-nic-name')
        device = root / 'sys/class/net' / name / 'device'
        if not device.exists() or (device.parent / 'wireless').exists(): continue
        pci = device.resolve().name
        driver = (device / 'driver').resolve().name
        require(bool(re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]',pci)), 'inventory-nic-bus')
        output = runner.run(['/usr/sbin/ethtool','-P',name]).stdout.decode('ascii').strip()
        match = re.fullmatch(r'Permanent address: ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})',output)
        require(match is not None and match[1] != '00:00:00:00:00:00', 'inventory-nic-permanent-address')
        result.append({'name':name,'permanent_mac':match[1],'pci_path':pci,'driver':driver,
                       'up':'UP' in row.get('flags',[]),'carrier':'LOWER_UP' in row.get('flags',[])})
    return result


def inventory(runner, *, root=Path('/'), plan=None) -> dict:
    boot_id = _small(root / 'proc/sys/kernel/random/boot_id')
    tree = _json(runner,['/usr/bin/lsblk','--json','--bytes','--paths','--output',
                'PATH,KNAME,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,RM,FSTYPE,MOUNTPOINTS'])
    require(type(tree.get('blockdevices')) is list, 'inventory-disks')
    nodes, ancestors = {}, {}
    def walk(rows, parents=()):
        for node in rows:
            path = node.get('path','')
            require(bool(re.fullmatch(r'/dev/[A-Za-z0-9_./-]+',path)), 'inventory-disk-path')
            if path in nodes and ancestors[path] != parents:
                raise ApplianceError('inventory-shared-storage')
            nodes[path] = node; ancestors[path] = parents
            walk(node.get('children',[]), parents + (path,))
    walk(tree['blockdevices'])
    mounted = _json(runner,['/usr/bin/findmnt','--json','--target','/cdrom','--output','SOURCE,FSTYPE,OPTIONS'])
    sources = mounted.get('filesystems',[])
    require(len(sources) == 1 and sources[0].get('fstype') == 'iso9660'
            and 'ro' in sources[0].get('options','').split(','), 'inventory-boot-media')
    media_device = sources[0].get('source','')
    require(media_device in nodes, 'inventory-boot-ancestry')
    media_paths = set(ancestors[media_device]) | {media_device}
    disks, aliases = [], {}
    conflicts = []
    target_path = None
    for path,node in nodes.items():
        if node.get('type') not in ('disk','rom'): continue
        raw = runner.run(['/usr/bin/udevadm','info','--query=property','--name',path]).stdout.decode('utf-8')
        props = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        names = sorted(n for n in props.get('DEVLINKS','').split() if n.startswith('/dev/disk/by-id/') and '-part' not in n)
        aliases[path] = names
        if node.get('type') == 'rom': continue
        if not names:
            conflicts.append('disk-without-stable-identity'); continue
        selected = plan['target']['by_id'] if plan and plan['target']['by_id'] in names else names[0]
        ident = {'by_id':selected,'serial':str(node.get('serial') or '').strip(),
                 'wwn':str(node.get('wwn') or '').strip(),'size_bytes':int(node['size']),
                 'model':str(node.get('model') or props.get('ID_MODEL') or '(not reported)').strip(),
                 'transport':str(node.get('tran') or ('virtio' if re.fullmatch(r'/dev/vd[a-z]+',path) else props.get('ID_BUS',''))).strip()}
        if ident['transport'] == 'spi': ident['transport'] = 'scsi'
        if not ident['serial'] and not ident['wwn']: conflicts.append('disk-without-independent-identity')
        children = [n for p,n in nodes.items() if path in ancestors[p]]
        disks.append({'identity':ident,'path':path,'aliases':names,'removable':bool(node.get('rm')),
                      'partitions':[{'path':n['path'],'type':n['type'],'filesystem':n.get('fstype') or '',
                                     'size_bytes':int(n.get('size') or 0)} for n in children]})
        if plan and selected == plan['target']['by_id']: target_path = path
    # All non-target special storage is refused: low-level installer also
    # deactivates global VGs. Simpler than pretending only a name collision matters.
    for path,node in nodes.items():
        on_target = target_path is not None and (path == target_path or target_path in ancestors[path])
        if node.get('type') in ('lvm','crypt','raid0','raid1','raid5','raid6','raid10','mpath') or node.get('fstype') in ('LVM2_member','zfs_member','linux_raid_member'):
            if not on_target: conflicts.append('non-target-special-storage')
        if on_target and node.get('mountpoints') and any(node['mountpoints']): conflicts.append('target-mounted')
    pvs = _json(runner,['/usr/sbin/pvs','--reportformat','json','-o','pv_name,vg_name,pv_uuid'])
    rows = [row for group in pvs.get('report',[]) for row in group.get('pv',[])]
    for row in rows:
        pv = row.get('pv_name','')
        if pv not in nodes or not target_path or target_path not in ancestors[pv]:
            conflicts.append('non-target-volume-group')
    boot_media_ids = sorted({alias for path in media_paths for alias in aliases.get(path,[])})
    # Optical media need not have a stable by-id; the observed physical path is
    # still excluded, and target comparison also checks ancestry below.
    boot_media_ids.extend(sorted(media_paths))
    if target_path in media_paths and plan: boot_media_ids.append(plan['target']['by_id'])
    ports = port_observations(runner,root=root)
    addresses = _json(runner,['/usr/sbin/ip','-json','address','show'])
    addr_by_name = {row['ifname']:[a['local'] for a in row.get('addr_info',[])] for row in addresses}
    selected_ports, names, zone_addresses = {}, {}, {}
    if plan:
        for role,wanted in plan['ports'].items():
            matches = [p for p in ports if all(p[k] == wanted[k] for k in wanted)]
            require(len(matches) == 1, 'port-identity-changed')
            selected_ports[role] = {k:matches[0][k] for k in wanted}
            names[role] = matches[0]['name']; zone_addresses[role] = addr_by_name.get(matches[0]['name'],[])
    cpu = _small(root / 'proc/cpuinfo',4 * 1024 * 1024)
    mem = _small(root / 'proc/meminfo')
    memory = re.search(r'^MemTotal:\s+(\d+) kB$',mem,re.M)
    require(memory is not None,'inventory-memory')
    machine = runner.run(['/usr/bin/uname','-m']).stdout.decode('ascii').strip()
    secure_vars = list((root / 'sys/firmware/efi/efivars').glob('SecureBoot-*'))
    secure_boot = None
    if len(secure_vars) == 1:
        data = secure_vars[0].read_bytes()
        if len(data) == 5 and data[4] in (0,1): secure_boot = bool(data[4])
    firmware = 'uefi' if (root / 'sys/firmware/efi').is_dir() else 'bios'
    link_checks = {'management':False,'wan':False}
    checkfile = root / 'run/rdc-appliance/port-checks.json'
    if plan and checkfile.exists():
        checks = read(checkfile)
        if checks.get('boot_id') == boot_id and checks.get('ports_id') == identity(plan['ports']):
            link_checks = checks.get('confirmed',link_checks)
    return {'boot_id':boot_id,'arch':machine,'virtualization':bool(re.search(r'\b(vmx|svm)\b',cpu)),
            'firmware':firmware,'secure_boot':secure_boot,'memory_mib':int(memory[1])//1024,
            'vcpus':len(re.findall(r'^processor\s*:',cpu,re.M)),
            'supported':machine == 'x86_64' and firmware == 'uefi' and secure_boot is False,
            'disks':disks,'boot_media_ids':boot_media_ids,'ports':selected_ports,'port_names':names,
            'port_observations':ports,'addresses':zone_addresses,'storage_conflicts':sorted(set(conflicts)),
            'link_checks':link_checks,'unselected_active':any(p['name'] not in names.values()
                and (p['up'] or addr_by_name.get(p['name'])) for p in ports) if plan else False}


def record_port_confirmation(plan: dict, role: str, *, root=Path('/')) -> None:
    """Called only after the local operator identifies this port/cable role."""
    require(role in ('management','wan'), 'port-role')
    boot_id = _small(root / 'proc/sys/kernel/random/boot_id')
    path = root / 'run/rdc-appliance/port-checks.json'
    value = {'boot_id':boot_id,'ports_id':identity(plan['ports']),'confirmed':{}}
    if path.exists():
        old = read(path)
        if old.get('boot_id') == boot_id and old.get('ports_id') == value['ports_id']: value = old
    value['confirmed'][role] = True
    write(path,value)

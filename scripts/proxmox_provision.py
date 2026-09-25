"""Allocate stopped, disconnected VM shells. Does not install or start guests."""
import hashlib
import json
import re
import time
from urllib.parse import quote
from portable_plan import validate, require, MODULES, ZONES

GIB = 1024**3


def payloads(plan):
    plan = validate(plan)
    digest = hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    result = []
    for role, (zone, _) in MODULES.items():
        vm = plan['vms'][role]
        item = {'vmid':vm['id'], 'name':f"rdc-{plan['site'][:40]}-{role}",
                'description':f'rdc-portable-shell-v1:{digest}:{role}',
                'cores':vm['cpu'], 'sockets':1, 'memory':vm['memory_mib'], 'balloon':0,
                'onboot':0, 'start':0, 'ostype':'other' if role=='edge' else 'l26',
                'scsihw':'virtio-scsi-single', 'scsi0':f"{plan['proxmox']['storage']}:{vm['disk_gib']}",
                'boot':'order=scsi0'}
        bridges = ([plan['proxmox']['wan_bridge']] + [plan['networks'][z]['bridge'] for z in ZONES]
                   if role=='edge' else [plan['networks'][zone]['bridge']])
        for index, bridge in enumerate(bridges):
            item[f'net{index}'] = f'virtio,bridge={bridge},link_down=1'
        result.append(item)
    return result


def owned(config, wanted, storage):
    require(type(config) is dict and config.get('description') == wanted['description'],
            'A reserved VM ID exists without matching site-plan ownership. No existing VM will be changed.')
    require(not config.get('lock') and not config.get('template') and not config.get('pending'),
            'An existing shell is locked, pending or a template. Inspect it before retrying.')
    for key in ('name','cores','sockets','memory','balloon','onboot','ostype','scsihw','boot'):
        require(str(config.get(key,'')) == str(wanted[key]), 'Existing shell configuration differs; refusing to modify it.')
    devices = {k for k in config if re.fullmatch(r'(net|scsi|sata|ide|virtio|unused|hostpci|usb|efidisk|tpmstate)\d+',k)}
    require(devices == {k for k in wanted if re.fullmatch(r'(net|scsi)\d+',k)}, 'Existing shell has unexpected or missing devices.')
    for key in devices:
        value = config[key]
        require(type(value) is str, 'Unexpected device configuration.')
        if key.startswith('net'):
            # Proxmox generates a MAC address; the bridge and link-down policy must remain exact.
            actual = re.sub(r'^virtio=[0-9A-Fa-f:]+', 'virtio', value)
            require(set(actual.split(',')) == set(wanted[key].split(',')), 'Existing shell network configuration differs.')
        else:
            parts = value.split(',')
            require(re.fullmatch(re.escape(storage)+r':vm-'+str(wanted['vmid'])+r'-disk-\d+',parts[0]) is not None,
                    'Existing shell disk is not the expected owned volume.')
            options = dict(part.split('=',1) for part in parts[1:] if '=' in part)
            require(options == {'size':wanted['scsi0'].split(':')[1]+'G'}, 'Existing shell disk configuration differs.')
    require(not any(config.get(k) for k in ('args','hookscript','cicustom')), 'Existing shell has custom execution settings.')


def check(plan, api):
    plan = validate(plan); desired = payloads(plan); node=plan['proxmox']['node']; base='/nodes/'+node
    version=api.request('GET','/version')
    require(type(version) is dict and re.fullmatch(r'9\.\d+(?:\.\d+)?',str(version.get('version',''))),
            'This experimental adapter targets Proxmox VE 9.x only; live compatibility remains unverified.')
    bridges=api.request('GET',base+'/network')
    require(type(bridges) is list, 'Cannot inspect Proxmox bridges.')
    by_name={b.get('iface'):b for b in bridges if type(b) is dict}
    for bridge in [plan['proxmox']['wan_bridge']]+[n['bridge'] for n in plan['networks'].values()]:
        b=by_name.get(bridge,{})
        require(b.get('type')=='bridge' and b.get('active') in (1,True), 'A required active Linux bridge is missing. Configure it independently first.')
    wan=by_name[plan['proxmox']['wan_bridge']]
    require(not any(wan.get(k) for k in ('address','address6','cidr','cidr6','gateway','gateway6')),
            'The WAN bridge has a host address or gateway. Refusing a topology that could expose host management.')
    resources=api.request('GET','/cluster/resources?type=vm')
    require(type(resources) is list, 'Cannot inspect allocated VM IDs.')
    by_id={r.get('vmid'):r for r in resources if type(r) is dict}
    missing=[]
    for wanted in desired:
        vmid=wanted['vmid']
        if vmid not in by_id:
            missing.append(wanted); continue
        record=by_id[vmid]
        require(record.get('node')==node and record.get('type')=='qemu', 'A reserved VM ID belongs to another node or guest type.')
        owned(api.request('GET',base+f'/qemu/{vmid}/config'),wanted,plan['proxmox']['storage'])
        status=api.request('GET',base+f'/qemu/{vmid}/status/current')
        require(type(status) is dict and status.get('status')=='stopped', 'An existing VM is running; shell allocation cannot manage deployed guests.')
    storage=api.request('GET',base+'/storage/'+plan['proxmox']['storage']+'/status')
    require(type(storage) is dict and storage.get('active')==1 and storage.get('enabled')==1
            and 'images' in str(storage.get('content','')).split(',') and storage.get('type') in ('lvmthin','zfspool'),
            'Storage must be enabled, active and support images on lvmthin or zfspool.')
    need=sum(plan['vms'][role]['disk_gib'] for role in MODULES if plan['vms'][role]['id'] in {p['vmid'] for p in missing})*GIB
    require(type(storage.get('avail')) in (int,float) and storage['avail'] >= need+10*GIB,
            'Insufficient free storage for missing disks plus 10 GiB reserve.')
    status=api.request('GET',base+'/status')
    free=status.get('memory',{}).get('free') if type(status) is dict else None
    require(type(free) in (int,float) and free >= sum(p['memory'] for p in desired)*1024**2+2*GIB,
            'Insufficient currently free RAM for the full plan plus 2 GiB host reserve.')
    return {'state':'ready-for-shell-allocation', 'version':version['version'],
            'missing_vm_ids':[p['vmid'] for p in missing], 'existing_vm_ids':[p['vmid'] for p in desired if p not in missing],
            'deployment':'not-performed', 'guest_installation':'not-performed',
            'notice':'API prerequisites checked. Live platform acceptance, OS installation, firewall and service readiness remain unverified.'}


def wait_task(api, node, upid, *, timeout=120, clock=time.monotonic, sleep=time.sleep):
    require(type(upid) is str and upid.startswith('UPID:'), 'Creation outcome is uncertain. Inspect Proxmox tasks before retrying.')
    deadline=clock()+timeout
    while clock()<deadline:
        status=api.request('GET','/nodes/'+node+'/tasks/'+quote(upid,safe='')+'/status')
        require(type(status) is dict, 'Cannot inspect creation task.')
        if status.get('status')=='stopped':
            require(status.get('exitstatus')=='OK', 'VM creation task failed. Existing resources were retained; inspect Proxmox before retrying.')
            return
        require(status.get('status')=='running', 'Creation task state is unknown; inspect Proxmox.')
        sleep(2)
    raise ValueError('Creation task is still unresolved. No cleanup or retry was attempted; inspect Proxmox tasks.')


def allocate(plan, api):
    plan=validate(plan); readiness=check(plan,api); node=plan['proxmox']['node']
    for wanted in payloads(plan):
        if wanted['vmid'] not in readiness['missing_vm_ids']: continue
        # VM create is atomic on the server: a competing allocation is rejected, never overwritten.
        upid=api.request('POST','/nodes/'+node+'/qemu',wanted)
        wait_task(api,node,upid)
        owned(api.request('GET',f"/nodes/{node}/qemu/{wanted['vmid']}/config"),wanted,plan['proxmox']['storage'])
    check(plan,api)
    return {'state':'shells-allocated','guest_installation':'not-performed','network_links':'disconnected',
            'notice':'Stopped VM shells allocated. No operating systems or services installed; no bridges or existing VMs changed.'}

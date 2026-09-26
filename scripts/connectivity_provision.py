"""Proxmox inspection and stopped connectivity shells; never activate networks."""
import hashlib
import ipaddress
import json
import math
import re
from connectivity_plan import validate, ROLES
from portable_plan import require
from proxmox_provision import owned, wait_task

GIB=1024**3
BRIDGES=('wan_bridge','management_bridge','services_bridge','partner_bridge')


def settings(plan,first_vm_id,management_address):
    plan=validate(plan)
    require(plan['state']=='prepared','Finish connectivity planning before host operations.')
    roles=[('opnsense',3072,20),('naming-time',1024,16),('partner-gateway',1024,16),('test-target',512,8)]
    for role in ROLES:
        if plan['answers'][role+'_placement']=='local':roles.append((role.replace('_','-'),1024,16))
    require(type(first_vm_id) is int and 100<=first_vm_id<=999999999-len(roles)+1,'Choose a first VM ID that leaves room for every selected role, between 100 and 999999999.')
    try:address=ipaddress.ip_address(management_address)
    except (TypeError,ValueError):raise ValueError('Use the existing independent Proxmox management IPv4 address.') from None
    require(type(management_address) is str and address.version==4 and not (address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local),
            'Use the existing independent Proxmox management IPv4 address.')
    result={'kind':'connectivity-provisioning','schema_version':1,'plan_revision':plan['revision'],
            'first_vm_id':first_vm_id,'management_address':management_address,
            'vms':[{'role':role,'id':first_vm_id+i,'cpu':2 if role=='opnsense' else 1,'memory_mib':memory,'disk_gib':disk}
                   for i,(role,memory,disk) in enumerate(roles)]}
    result['revision']=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result


def validate_settings(plan,config):
    require(type(config) is dict and type(config.get('schema_version')) is int and config==settings(plan,config.get('first_vm_id'),config.get('management_address')),
            'Provisioning settings do not match this plan/version. Existing resources will not be adopted or changed.')
    return config


def payloads(plan,config):
    validate_settings(plan,config);a=plan['answers'];result=[]
    for vm in config['vms']:
        role=vm['role'];bridges=[a[k] for k in BRIDGES] if role=='opnsense' else [a['partner_bridge' if role=='partner-gateway' else 'services_bridge']]
        item={'vmid':vm['id'],'name':f"rdc-{a['site'][:24]}-{role}",
              'description':f"rdc-connectivity-shell-v1:{config['revision']}:{role}",
              'cores':vm['cpu'],'sockets':1,'memory':vm['memory_mib'],'balloon':0,
              'onboot':0,'start':0,'ostype':'other' if role=='opnsense' else 'l26',
              'scsihw':'virtio-scsi-single','scsi0':f"{a['storage']}:{vm['disk_gib']}",'boot':'order=scsi0'}
        item.update({f'net{i}':f'virtio,bridge={bridge},link_down=1' for i,bridge in enumerate(bridges)})
        result.append(item)
    return result


def preview(plan,config):
    payloads(plan,config)
    lines=['Target Proxmox: '+plan['answers']['proxmox_endpoint']+'; node '+plan['answers']['node'],
           'Planned VM shells (blank disks; stopped; autostart disabled; every NIC disconnected):']
    for vm in config['vms']:
        lines.append(f"  {vm['id']} {vm['role']}: {vm['cpu']} CPU, {vm['memory_mib']} MiB RAM, {vm['disk_gib']} GiB disk")
    lines+=['Required existing bridges: '+', '.join(plan['answers'][key] for key in BRIDGES),
            'Expected independent management address: '+config['management_address'],
            'No bridge changes, VM starts, guest OS installation, public port forwarding or service installation.',
            'These are initial sizing defaults, not production capacity acceptance. External/existing roles are not provisioned here.']
    return '\n'.join(lines)


def capacity(value,minimum):
    return type(value) in (int,float) and minimum<=value<=2**63-1 and math.isfinite(value)


def observe(api,base,wanted,storage):
    owned(api.request('GET',base+f"/qemu/{wanted['vmid']}/config"),wanted,storage)
    status=api.request('GET',base+f"/qemu/{wanted['vmid']}/status/current")
    require(type(status) is dict and status.get('status')=='stopped','A planned VM is running. Shell allocation will not manage an installed or running guest.')


def check(plan,config,api):
    desired=payloads(plan,config);a=plan['answers'];base='/nodes/'+a['node']
    version=api.request('GET','/version')
    require(type(version) is dict and type(version.get('version')) is str and re.fullmatch(r'9\.\d+(?:\.\d+)?',version['version']),
            'This experimental adapter targets Proxmox VE 9.x; compatibility still requires lab acceptance.')
    interfaces=api.request('GET',base+'/network')
    require(type(interfaces) is list and all(type(b) is dict and type(b.get('iface')) is str for b in interfaces),'Cannot inspect host network interfaces.')
    by_name={b['iface']:b for b in interfaces}
    require(len(by_name)==len(interfaces),'Host network response contains duplicate interface records.')
    for key in BRIDGES:
        require(a[key] in by_name,'A planned bridge is missing or not visible. Check SDN.Use on /sdn/zones/localnetwork for both user and token before changing host networking. This wizard does not create bridges yet.')
        b=by_name[a[key]]
        require(b.get('type')=='bridge' and b.get('active') in (1,True),'A planned interface is not an active Linux bridge; review the independent host configuration.')
    wan=by_name[a['wan_bridge']]
    require(not any(wan.get(k) for k in ('address','address6','cidr','cidr6','gateway','gateway6')),
            'The WAN bridge has a host address or gateway; refusing to expose or disrupt Proxmox management.')
    management=by_name[a['management_bridge']];addresses=[]
    for key in ('address','cidr'):
        value=management.get(key)
        if value:
            try:addresses.append(str(ipaddress.ip_interface(value).ip))
            except (TypeError,ValueError):raise ValueError('Cannot verify the management bridge address.') from None
    require(config['management_address'] in addresses,'The declared management address was not observed on the selected management bridge. Verify independent administration before proceeding.')
    resources=api.request('GET','/cluster/resources?type=vm')
    require(type(resources) is list and all(type(r) is dict and type(r.get('vmid')) is int for r in resources),'Cannot inspect visible VM IDs.')
    by_id={r['vmid']:r for r in resources}
    require(len(by_id)==len(resources),'VM resource response contains duplicate IDs.')
    missing=[];existing=[]
    for wanted in desired:
        vmid=wanted['vmid']
        if vmid not in by_id:missing.append(vmid);continue
        require(by_id[vmid].get('node')==a['node'] and by_id[vmid].get('type')=='qemu','A planned VM ID belongs to a different node or guest type.')
        observe(api,base,wanted,a['storage']);existing.append(vmid)
    storage=api.request('GET',base+'/storage/'+a['storage']+'/status')
    require(type(storage) is dict and storage.get('active')==1 and storage.get('enabled')==1
            and storage.get('type') in ('lvmthin','zfspool') and 'images' in str(storage.get('content','')).split(','),
            'Use active enabled lvmthin or zfspool storage supporting VM images.')
    disk=sum(vm['disk_gib'] for vm in config['vms'] if vm['id'] in missing)
    require(capacity(storage.get('avail'),(disk+10)*GIB),'Insufficient free disk capacity for missing shells plus a 10 GiB reserve.')
    status=api.request('GET',base+'/status')
    memory=status.get('memory') if type(status) is dict else None
    require(type(memory) is dict and capacity(memory.get('free'),sum(vm['memory_mib'] for vm in config['vms'])*1024**2+2*GIB),
            'Insufficient free RAM for the selected shells plus a 2 GiB host reserve.')
    return {'state':'ready-for-shell-allocation','version':version['version'],
            'missing_vm_ids':missing,'existing_vm_ids':existing,
            'management_address_observed':True,'independent_console_verified':False,
            'guest_installation':'not-performed','network_activation':'not-performed'}


def journal(plan,config):
    validate_settings(plan,config)
    return {'kind':'connectivity-provisioning-journal','schema_version':1,
            'revision':config['revision'],'vms':{},'last':None}


def validate_journal(plan,config,data):
    reference=journal(plan,config)
    require(type(data) is dict and set(data)==set(reference) and data['kind']==reference['kind']
            and type(data['schema_version']) is int and data['schema_version']==1 and data['revision']==reference['revision']
            and type(data['vms']) is dict,'Provisioning journal does not match this plan/settings.')
    ids={str(vm['id']) for vm in config['vms']}
    require(set(data['vms'])<=ids,'Unexpected VM in provisioning journal.')
    for entry in data['vms'].values():
        require(type(entry) is dict and set(entry)=={'state','upid'} and entry['state'] in ('intent','task','verified'), 'Invalid provisioning task record.')
        require(entry['upid'] is None if entry['state']=='intent' else
                (entry['state']=='verified' and entry['upid'] is None) or
                type(entry['upid']) is str and 5<len(entry['upid'])<=512 and entry['upid'].startswith('UPID:')
                and not any(c.isspace() for c in entry['upid']), 'Invalid provisioning task identifier.')
    last=data['last']
    if last is not None:
        from datetime import datetime
        require(type(last) is dict and set(last)=={'operation','outcome','at'} and last['operation'] in ('check','allocate')
                and last['outcome'] in ('ready-for-shell-allocation','shells-allocated','failed') and type(last['at']) is str,
                'Invalid historical provisioning result.')
        try:parsed=datetime.fromisoformat(last['at'])
        except ValueError:raise ValueError('Invalid historical check time.') from None
        require(parsed.tzinfo is not None,'Historical check time must include its timezone.')
    return data


def allocate(plan,config,api,data,persist):
    validate_journal(plan,config,data);a=plan['answers'];base='/nodes/'+a['node']
    # Poll recorded tasks before inspecting their potentially locked/incomplete VMs.
    for entry in data['vms'].values():
        if entry['state']=='task':wait_task(api,a['node'],entry['upid'])
    readiness=check(plan,config,api)
    require(all(int(key) in readiness['existing_vm_ids'] for key in data['vms']),
            'A previous allocation is unresolved or its shell disappeared. Inspect Proxmox tasks and storage; no request was replayed.')
    for wanted in payloads(plan,config):
        key=str(wanted['vmid'])
        if wanted['vmid'] in readiness['existing_vm_ids']:
            data['vms'][key]={'state':'verified','upid':data['vms'].get(key,{}).get('upid')};persist(data);continue
        require(key not in data['vms'],'A previous allocation is unresolved or its shell disappeared. Inspect Proxmox tasks and storage; no request was replayed.')
        data['vms'][key]={'state':'intent','upid':None};persist(data)
        upid=api.request('POST',base+'/qemu',wanted)
        require(type(upid) is str and 5<len(upid)<=512 and upid.startswith('UPID:') and not any(c.isspace() for c in upid),
                'Allocation outcome is uncertain; inspect Proxmox tasks before proceeding.')
        data['vms'][key]={'state':'task','upid':upid};persist(data)
        wait_task(api,a['node'],upid)
        observe(api,base,wanted,a['storage'])
        data['vms'][key]={'state':'verified','upid':upid};persist(data)
    result=check(plan,config,api)
    require(not result['missing_vm_ids'],'A planned shell is missing at final inspection. Inspect Proxmox resources; allocation is incomplete.')
    result['state']='shells-allocated'
    return result

"""Owned, one-zone Linux guests and bounded private guest-agent transport.

Provisioning never starts or exposes a guest. Requests travel on stdin only;
uncertain execution remains pending and must be queried without resubmission.
"""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
from .contracts import ApplianceError, canonical, identity, integer, require
from . import proxmox, state as records
from .media import verify_file
from .installer.media import _copy_verified, _safe_parents, _write_new
from .installer.payload import file_record
from .guest.helper import MAX_BYTES, validate_request, validate_reply, _unique

HELPER='/usr/lib/rdc-guest/helper'
ROLES=frozenset(('connector','headscale','derp'))


def encode_request(request):
    validate_request(request)
    raw=canonical(request);require(len(raw)<=MAX_BYTES,'guest-request-too-large')
    return raw


def _path(state,vmid):return Path(state)/'role-vms'/(str(vmid)+'.json')


def receipt(vmid,state,*,pending=False):
    record=records.read(_path(state,vmid));proxmox._spec(record['spec'])
    require(record.get('schema')==1 and record['spec']['vmid']==vmid and record['spec']['role'] in ROLES,'guest-receipt')
    require(pending or not record.get('pending'),'guest-operation-needs-inspection')
    return record


def _observe(record,runner):
    spec=record['spec'];observed=proxmox.observe_vm(spec['vmid'],runner);cfg=observed['config']
    expected={**proxmox._base(spec),'agent':'enabled=1,freeze-fs=0','serial0':'socket','vga':'serial0',
              'ide2':record['seed_volume']+',media=cdrom',
              'net0':proxmox._nic_text(spec['nics'][0],record['connected'])}
    require(all(cfg.get(k)==v for k,v in expected.items()),'guest-config-drift')
    require(not any(cfg.get(k) for k in ('args','hookscript','cicustom','lock','template')),'guest-unsafe-config')
    devices={k for k in cfg if re.fullmatch(r'(?:net|scsi|sata|ide|virtio|unused|hostpci|usb|efidisk|tpmstate|serial)[0-9]+',k)}
    require(devices=={'net0','scsi0','ide2','serial0'},'guest-device-drift')
    from .probe import _disk_size
    parts=cfg.get('scsi0','').split(',')
    require(re.fullmatch(re.escape(spec['storage'])+':vm-'+str(spec['vmid'])+r'-disk-[0-9]+',parts[0])
            and len(parts)==2 and parts[1].startswith('size='),'guest-disk-ownership')
    require(_disk_size(parts[1][5:])==record['disk_bytes'],'guest-disk-size')
    require(not record.get('disk_volume') or parts[0]==record['disk_volume'],'guest-disk-changed')
    verify_file(_safe_parents(record['seed_path']),record['seed_image'])
    return observed


def observe_linux(plan,role,runner,state):
    spec=proxmox.vm_spec(plan,role);record=receipt(spec['vmid'],state)
    require(record['spec']==spec,'guest-receipt-binding')
    return _observe(record,runner)


def _owned(vmid,request,runner,state):
    require(state is not None,'guest-state-required')
    record=receipt(vmid,state);spec=record['spec']
    require(spec['role']==request['role'] and spec['plan_id']==request['plan_id'],'guest-request-binding')
    observed=_observe(record,runner);cfg=observed['config']
    require(observed['running'] and cfg.get('description')==spec['ownership'],'guest-not-owned-running')
    require(cfg.get('agent')=='enabled=1,freeze-fs=0','guest-agent-required')
    return record


def _json_result(result):
    require(result.returncode==0 and type(result.stdout) is bytes and len(result.stdout)<=MAX_BYTES+4096,'guest-response-too-large')
    try:
        value=json.loads(result.stdout,object_pairs_hook=_unique)
        require(type(value) is dict,'guest-agent-response');canonical(value)
        return value
    except ApplianceError:raise
    except (ValueError,UnicodeError,RecursionError):raise ApplianceError('guest-agent-response') from None


def _pending(request,code='guest-operation-pending'):
    return {'operation_id':request['operation_id'],'phase':'pending','code':code,'observations':{}}


def _remember_machine(vmid,reply,state):
    machine=reply['observations'].get('machine_id')
    if machine is None:
        require(reply['phase']!='complete','guest-machine-identity');return
    require(type(machine) is str and re.fullmatch(r'[0-9a-f]{32}',machine) and machine!='0'*32,'guest-machine-identity')
    with records.lock(Path(state)/'guest-identities'):
        path=Path(state)/'guest-identities'/(str(vmid)+'.json')
        for other in path.parent.glob('*.json'):
            existing=records.read(other)
            if other==path:require(existing.get('machine_id')==machine,'guest-machine-identity-changed')
            else:require(existing.get('machine_id')!=machine,'guest-machine-identity-duplicate')
        records.write(path,{'schema':1,'vmid':vmid,'machine_id':machine})


def guest_call(vmid,request,runner,*,state=None):
    integer(vmid,100,999999999);raw=encode_request(request);_owned(vmid,request,runner,state)
    path=Path(state)/'guest-operations'/(str(vmid)+'-'+request['operation_id']+'.json')
    query=request['action']=='inspect' and request['parameters']=={'query_operation':True}
    with records.lock(Path(state)/'guest-transport'):
        if path.exists() and not query:
            existing=records.read(path)
            require(existing['request_id']==identity(request),'guest-operation-reused')
            return existing['reply']
        record={'schema':1,'vmid':vmid,'request_id':identity(request),'role':request['role'],
                'plan_id':request['plan_id'],'reply':_pending(request)}
        if not query:records.write(path,record)
        try:
            result=_json_result(runner.run([proxmox.QM,'guest','exec',str(vmid),'--pass-stdin','1',
                '--synchronous','0','--',HELPER],stdin=raw,timeout_s=30))
            pid=integer(result.get('pid'),1,2**31-1)
            # The helper does all mutation once. Polling only observes that PID.
            for attempt in range(30):
                status=_json_result(runner.run([proxmox.QM,'guest','exec-status',str(vmid),str(pid)],timeout_s=30))
                if status.get('exited') in (1,True):break
                require(status.get('exited') in (0,False),'guest-agent-response')
                time.sleep(1)
            else:return _pending(request)
            require(status.get('exitcode')==0 and not status.get('out-truncated') and not status.get('err-truncated'),'guest-helper-exit')
            output=status.get('out-data','');require(type(output) is str,'guest-agent-response')
            require(len(output.encode())<=MAX_BYTES,'guest-response-too-large')
            try:reply=json.loads(output,object_pairs_hook=_unique)
            except (ValueError,UnicodeError,RecursionError):raise ApplianceError('guest-reply-json') from None
            validate_reply(reply,request);_remember_machine(vmid,reply,state)
            # Export is the only consumer of private readback. Do not cache it.
            if request['action']=='snapshot-read':return reply
            if query and path.exists():record=records.read(path)
            records.write(path,{**record,'reply':reply})
            return reply
        except ApplianceError as error:
            if error.code in ('command-timeout','command-failed','command-execution'):
                return _pending(request,'guest-outcome-unknown')
            raise


def query_guest_operation(vmid,request,runner,*,state):
    query={**request,'action':'inspect','parameters':{'query_operation':True}}
    return guest_call(vmid,query,runner,state=state)


def _site(plan,role):
    require(role in ROLES,'guest-role');spec=proxmox.vm_spec(plan,role)
    require(len(spec['nics'])==1,'guest-one-zone')
    nic=spec['nics'][0];network=plan['networks'][nic['zone']]
    try:
        subnet=ipaddress.IPv4Network(network['cidr'],strict=True)
        address=ipaddress.IPv4Address(nic['address']);gateway=ipaddress.IPv4Address(network['gateway'])
    except (KeyError,ValueError,TypeError):raise ApplianceError('guest-address') from None
    require(address in subnet and gateway in subnet and address not in (subnet.network_address,subnet.broadcast_address,gateway),'guest-address')
    return spec,nic,subnet


def seed_files(plan,role):
    spec,nic,subnet=_site(plan,role);gateway=plan['networks'][nic['zone']]['gateway']
    seed={'schema':1,'plan_id':identity(plan),'role':role,'vmid':spec['vmid']}
    network={'version':2,'renderer':'networkd','ethernets':{'role0':{'match':{'macaddress':nic['mac']},'set-name':'role0',
        'dhcp4':False,'dhcp6':False,'accept-ra':False,'link-local':[],
        'addresses':[nic['address']+'/'+str(subnet.prefixlen)],'routes':[{'to':'0.0.0.0/0','via':gateway}],
        'nameservers':{'addresses':[gateway]},'optional':True,'ignore-carrier':True}}}
    user={'hostname':spec['name'],'manage_etc_hosts':True,'timezone':'UTC','users':[],
        'disable_root':True,'ssh_pwauth':False,'ssh_deletekeys':True,'ssh_genkeytypes':[],
        'ssh_publish_hostkeys':{'enabled':False},'package_update':False,'package_upgrade':False,
        'write_files':[{'path':'/etc/rdc-guest.json','permissions':'0600','content':canonical(seed).decode()+'\n'},
                       {'path':'/etc/sysctl.d/90-rdc-guest.conf','permissions':'0644','content':'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv4.ip_forward=0\n'},
                       {'path':'/etc/default/grub.d/90-rdc-guest.cfg','permissions':'0644','content':'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ipv6.disable=1"\n'}],
        'bootcmd':[['/usr/bin/systemctl','mask','--now','ssh.service','ssh.socket','apt-daily.service','apt-daily.timer',
                    'apt-daily-upgrade.service','apt-daily-upgrade.timer','unattended-upgrades.service'],
                   ['/usr/sbin/sysctl','--ignore','-w','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1','net.ipv4.ip_forward=0']],
        'runcmd':[['/usr/sbin/update-grub'],['/usr/bin/systemctl','start','rdc-guest.service']]}
    return {'user-data':b'#cloud-config\n'+canonical(user)+b'\n',
            'meta-data':canonical({'instance-id':'rdc-'+identity(seed),'local-hostname':spec['name']})+b'\n',
            'network-config':canonical(network)+b'\n'}


def build_seed(plan,role,output,runner):
    files=seed_files(plan,role);output=_safe_parents(output)
    require(output.suffix=='.iso' and output.parent.is_dir(),'guest-seed-path')
    with records.lock(output.parent):
        require(not output.exists(),'guest-seed-exists')
        with tempfile.TemporaryDirectory(prefix='.role-seed-',dir=output.parent) as temporary:
            work=Path(temporary);candidate=work/'seed.iso'
            argv=['/usr/bin/genisoimage','-o',str(candidate),'-V','CIDATA','-J','-R','-uid','0','-gid','0','-input-charset','utf-8','-graft-points']
            for name,raw in sorted(files.items()):
                target=work/name;_write_new(target,raw);argv.append(name+'='+str(target))
            runner.run(argv,timeout_s=120)
            for name,raw in files.items():
                result=runner.run(['/usr/bin/isoinfo','-R','-i',str(candidate),'-x','/'+name],timeout_s=60)
                require(result.returncode==0 and result.stdout==raw,'guest-seed-readback')
            image=file_record(candidate);require(image['size_bytes']<=8*1024**2,'guest-seed-size')
            candidate.chmod(0o600);os.link(candidate,output)
            result={'schema':1,'plan_id':identity(plan),'role':role,'image':image}
            records.write(output.with_suffix('.iso.json'),result)
            return result


def _mutate(record,kind,argv,runner,state,*,updates=None,running=False):
    desired={**record,**(updates or {}),'sequence':record['sequence']+1};desired.pop('pending',None);desired.pop('desired',None)
    op=records.begin(Path(state)/'operations',{'kind':kind,'vmid':record['spec']['vmid'],
        'ownership':record['spec']['ownership'],'sequence':desired['sequence'],'desired_id':identity(desired),'running':running})
    records.write(_path(state,record['spec']['vmid']),{**record,'pending':op,'desired':{'receipt':desired,'running':running}})
    runner.run(argv,timeout_s=600)
    return _finish(desired,running,op,runner,state)


def _finish(record,running,op,runner,state):
    observed=_observe(record,runner);require(observed['running'] is running,'guest-running-outcome')
    record={**record,'disk_volume':observed['disk_volume']}
    records.finish(Path(state)/'operations',op,{'config_id':identity(observed['config']),'boot_id':observed['boot_id']})
    records.write(_path(state,record['spec']['vmid']),record)
    return observed


def reconcile_linux(vmid,runner,state):
    with records.lock(Path(state)/'role-vms'):
        old=receipt(vmid,state,pending=True);op=old.get('pending');desired=old.get('desired',{})
        require(type(op) is str and type(desired.get('receipt')) is dict and type(desired.get('running')) is bool,'guest-no-pending-operation')
        value=desired['receipt'];journal=records.read(Path(state)/'operations'/(op+'.json'))
        require(journal['operation'].get('desired_id')==identity(value) and value['spec']==old['spec'],'guest-pending-binding')
        return _finish(value,desired['running'],op,runner,state)


def provision_linux(plan,role,runner,state,*,release=None,inputs=None,image_receipt=None):
    """Import a previously built and byte-pinned image, stopped and disconnected."""
    spec,_,_=_site(plan,role)
    components=[] if release is None else [c for c in release.get('components',[]) if c['id']=='role-image']
    require(inputs is not None,'role-image-not-built')
    if not components:
        candidate=Path(image_receipt) if image_receipt is not None else Path(inputs)/'role-image.qcow2.json'
        require(candidate.exists(),'role-image-not-built')
        from .guest.image import read_build_receipt
        built=read_build_receipt(candidate)
        component={'id':'role-image','version':built['recipe_id'],'filename':built['filename'],**built['image']}
    else:
        require(len(components)==1,'role-image-pin');component=components[0]
    image=_safe_parents(Path(inputs)/component['filename'])
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(image)) is not None,'guest-image-path')
    verify_file(image,component)
    with records.lock(Path(state)/'role-vms'):
        path=_path(state,spec['vmid'])
        if path.exists():
            current=receipt(spec['vmid'],state)
            require(current['spec']==spec and current['source_image']==component['sha256'],'guest-image-or-plan-changed')
            return _observe(current,runner)
        info=_json_result(runner.run(['/usr/bin/qemu-img','info','--output=json',str(image)]))
        require(info.get('format')=='qcow2' and type(info.get('virtual-size')) is int and 0<info['virtual-size']<=spec['disk_gib']*1024**3,'guest-image-format')
        require(not any(info.get(k) for k in ('backing-filename','full-backing-filename','encrypted')) and not any(info.get('format-specific',{}).get('data',{}).get(k) for k in ('data-file','encrypt')),'guest-image-external-data')
        resources=proxmox._json(runner,'/cluster/resources','--type','vm')
        require(type(resources) is list and all(r.get('vmid')!=spec['vmid'] for r in resources),'vmid-in-use')
        node=proxmox._name(proxmox._run(runner,['/usr/bin/hostname','-s']).strip());base='/nodes/'+node+'/storage/'+spec['storage']
        storage=proxmox._json(runner,base+'/status')
        require(storage.get('active')==1 and storage.get('enabled')==1 and storage.get('type')=='lvmthin' and 'images' in storage.get('content','').split(',') and type(storage.get('avail')) is int and storage['avail']>=(spec['disk_gib']+2)*1024**3,'guest-storage')
        require(proxmox._json(runner,base+'/content','--content','images','--vmid',str(spec['vmid']))==[],'vm-unowned-disk')
        local=proxmox._json(runner,'/storage/local')
        require(local.get('type')=='dir' and local.get('path')=='/var/lib/vz' and 'iso' in local.get('content','').split(','),'guest-seed-storage')
        work=Path(state)/'role-seeds'/str(spec['vmid'])
        with records.lock(work):pass
        seed=work/(identity(plan)+'.iso')
        if not seed.exists():seed_record=build_seed(plan,role,seed,runner)
        else:
            seed_record=records.read(seed.with_suffix('.iso.json'))
            require(seed_record['plan_id']==identity(plan) and seed_record['role']==role,'guest-seed-binding');verify_file(seed,seed_record['image'])
        volume='local:iso/rdc-'+role+'-'+seed_record['image']['sha256']+'.iso'
        destination=_safe_parents(proxmox._run(runner,['/usr/sbin/pvesm','path',volume]).strip())
        require(destination==Path('/var/lib/vz/template/iso')/volume.split('/')[-1],'guest-seed-storage-path')
        if destination.exists():verify_file(destination,seed_record['image'])
        else:_copy_verified(seed,destination,seed_record['image'])
        current={'schema':1,'spec':spec,'phase':'prepared','sequence':0,'connected':False,'disk_bytes':info['virtual-size'],
            'source_image':component['sha256'],'image_recipe_id':component['version'],'seed_volume':volume,'seed_path':str(destination),'seed_image':seed_record['image']}
        options={**proxmox._base(spec),'agent':'enabled=1,freeze-fs=0','serial0':'socket','vga':'serial0','ide2':volume+',media=cdrom',
                 'scsi0':spec['storage']+':0,import-from='+str(image)}
        argv=[proxmox.QM,'create',str(spec['vmid'])]
        for key,value in options.items():argv+=['--'+key,value]
        _mutate(current,'guest-import',argv,runner,state);current=receipt(spec['vmid'],state)
        if current['disk_bytes']!=spec['disk_gib']*1024**3:
            _mutate(current,'guest-grow',[proxmox.QM,'resize',str(spec['vmid']),'scsi0',str(spec['disk_gib'])+'G'],runner,state,
                    updates={'disk_bytes':spec['disk_gib']*1024**3})
        return _observe(receipt(spec['vmid'],state),runner)


def start_linux(plan,role,runner,state):
    spec=proxmox.vm_spec(plan,role)
    with records.lock(Path(state)/'role-vms'):
        record=receipt(spec['vmid'],state);require(record['spec']==spec and record['phase']=='prepared','guest-receipt-binding')
        observed=_observe(record,runner)
        if observed['running']:return observed
        if record['connected']:
            _mutate(record,'guest-isolate',[proxmox.QM,'set',str(spec['vmid']),'--net0',proxmox._nic_text(spec['nics'][0],False)],runner,state,updates={'connected':False})
            record=receipt(spec['vmid'],state)
        return _mutate(record,'guest-start',[proxmox.QM,'start',str(spec['vmid'])],runner,state,running=True)


def record_link(vmid,connected,state):
    require(type(connected) is bool,'guest-link-state');record=receipt(vmid,state)
    records.write(_path(state,vmid),{**record,'connected':connected})


def inspect_runtime(plan,role,runner,state):
    """Require fresh image, kernel and network observations before attachment."""
    import secrets
    spec,nic,subnet=_site(plan,role);record=receipt(spec['vmid'],state)
    require(record['spec']==spec,'guest-receipt-binding')
    request={'schema':1,'operation_id':'runtime-'+secrets.token_hex(16),'plan_id':identity(plan),'role':role,'action':'inspect','parameters':{'runtime':True}}
    reply=guest_call(spec['vmid'],request,runner,state=state)
    require(reply['phase']=='complete','guest-runtime-unavailable')
    observations=reply['observations'];runtime=observations.get('runtime',{})
    require(type(observations.get('boot_id')) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',observations['boot_id']),'guest-boot-identity')
    require(observations.get('role')==role and observations.get('plan_id')==identity(plan),'guest-runtime-binding')
    require(runtime.get('image',{}).get('recipe_id')==record.get('image_recipe_id') and bool(record.get('image_recipe_id')),'guest-runtime-image')
    require(runtime.get('forwarding') is False and runtime.get('ipv6_disabled') is True and runtime.get('ssh_masked') is True,'guest-runtime-isolation')
    addresses=runtime.get('addresses');routes=runtime.get('routes')
    require(type(addresses) is list and type(routes) is list,'guest-runtime-network')
    interfaces={a.get('ifname'):a for a in addresses}
    require(len(interfaces)==len(addresses) and set(interfaces)<=({'lo','role0','tailscale0'} if role=='connector' else {'lo','role0'}) and 'role0' in interfaces,'guest-runtime-network')
    physical=interfaces['role0'];require(physical.get('address','').lower()==nic['mac'],'guest-runtime-network')
    assigned=physical.get('addr_info',[])
    require(len(assigned)==1 and assigned[0].get('family')=='inet' and assigned[0].get('local')==nic['address'] and assigned[0].get('prefixlen')==subnet.prefixlen,'guest-runtime-network')
    defaults=[r for r in routes if r.get('dst')=='default']
    require(len(defaults)==1 and defaults[0].get('gateway')==plan['networks'][nic['zone']]['gateway'] and defaults[0].get('dev')=='role0','guest-runtime-network')
    require(all(r.get('dev') in ('role0','lo') for r in routes),'guest-runtime-network')
    records.write(Path(state)/'guest-runtime'/(str(spec['vmid'])+'.json'),{'schema':1,'plan_id':identity(plan),'vmid':spec['vmid'],
        'machine_id':observations.get('machine_id'),'guest_boot_id':observations['boot_id'],'host_boot_id':_observe(record,runner)['boot_id'],'checked_at':int(time.time()),'reply_id':identity(reply)})
    return reply


def set_linux_link(plan,role,connected,runner,state):
    """Called by the host only after its router-readiness gate has passed."""
    require(type(connected) is bool,'guest-link-state');spec=proxmox.vm_spec(plan,role)
    if connected:inspect_runtime(plan,role,runner,state)
    with records.lock(Path(state)/'role-vms'):
        record=receipt(spec['vmid'],state);require(record['spec']==spec,'guest-receipt-binding')
        observed=_observe(record,runner)
        require(observed['running'],'guest-not-running')
        if connected:
            inspected=records.read(Path(state)/'guest-runtime'/(str(spec['vmid'])+'.json'))
            require(inspected.get('plan_id')==identity(plan) and inspected.get('host_boot_id')==observed['boot_id'] and 0<=int(time.time())-inspected.get('checked_at',0)<=120,'guest-runtime-stale')
        if record['connected']==connected:return observed
        return _mutate(record,'guest-link',[proxmox.QM,'set',str(spec['vmid']),'--net0',proxmox._nic_text(spec['nics'][0],connected)],
                       runner,state,updates={'connected':connected},running=True)

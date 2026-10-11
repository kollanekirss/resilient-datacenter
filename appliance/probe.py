"""Private NoCloud seed and explicit, journaled neutral-probe provisioning.

No call silently starts a VM. Console claims are fresh in-process attestations,
not guest or packet qualification. A seed is private site data, never ISO input.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from .contracts import ApplianceError, canonical, identity, require
from . import proxmox, state as records
from .media import verify_file
from .installer.media import _copy_verified, _safe_parents, _write_new
from .installer.payload import file_record

CONSOLE_CHECKS = ('cloud_init_done','workload_mac_address','ipv6_disabled','no_optional_roles','unique_login')
_TOKEN = object()


@dataclass(frozen=True)
class ProbeAttestation:
    plan_id: str
    vmid: int
    boot_id: str
    config_id: str
    checked_at: float
    token: object


def _site(plan):
    spec = proxmox.vm_spec(plan,'probe')
    require(len(spec['nics']) == 1 and spec['nics'][0]['zone'] == 'workload','probe-workload-only')
    nic = spec['nics'][0]; network = plan['networks']['workload']
    try:
        subnet = ipaddress.IPv4Network(network['cidr'],strict=True)
        address = ipaddress.IPv4Address(nic['address']); gateway = ipaddress.IPv4Address(network['gateway'])
    except (KeyError,ValueError,TypeError): raise ApplianceError('probe-address') from None
    require(address in subnet and gateway in subnet and address not in
            (subnet.network_address,subnet.broadcast_address,gateway),'probe-address')
    return spec,nic,subnet


def seed_files(plan, *, password_hash: str, ssh_public_key: str | None = None) -> dict[str,bytes]:
    spec,nic,subnet = _site(plan)
    require(type(password_hash) is str and re.fullmatch(
        r'\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}',password_hash) is not None,
        'probe-password-hash')
    keys=[]
    if ssh_public_key is not None:
        require(type(ssh_public_key) is str and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}=?',ssh_public_key) is not None,
                'probe-public-key')
        try: raw=base64.b64decode(ssh_public_key.split()[1],validate=True)
        except ValueError: raise ApplianceError('probe-public-key') from None
        require(len(raw)==51 and raw[:19]==b'\0\0\0\x0bssh-ed25519\0\0\0\x20','probe-public-key')
        keys=[ssh_public_key]
    instance='rdc-probe-'+identity({'plan':plan,'password_hash':password_hash,'ssh_public_key':ssh_public_key})
    network={'version':2,'ethernets':{'probe0':{'match':{'macaddress':nic['mac']},'set-name':'probe0',
        'dhcp4':False,'dhcp6':False,'accept-ra':False,'link-local':[],
        'addresses':[nic['address']+'/'+str(subnet.prefixlen)],
        'routes':[{'to':'0.0.0.0/0','via':plan['networks']['workload']['gateway']}],
        'nameservers':{'addresses':[plan['networks']['workload']['gateway']]},'optional':True}}}
    sysctl='net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv4.ip_forward=0\n'
    user={'hostname':spec['name'],'manage_etc_hosts':True,'timezone':'UTC','disable_root':True,
        'users':[{'name':'probe','shell':'/bin/bash','groups':['adm','sudo'],'sudo':'ALL=(ALL) ALL',
                  'lock_passwd':False,'hashed_passwd':password_hash,'ssh_authorized_keys':keys}],
        'ssh_pwauth':False,'ssh_deletekeys':True,'ssh_genkeytypes':['ed25519'],
        'ssh_publish_hostkeys':{'enabled':False},'package_update':False,'package_upgrade':False,
        'package_reboot_if_required':False,'packages':[],
        'bootcmd':[
            ['/usr/sbin/sysctl','--ignore','-w','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1','net.ipv4.ip_forward=0'],
            ['/usr/bin/systemctl','mask','--now','apt-daily.service','apt-daily-upgrade.service',
             'apt-daily.timer','apt-daily-upgrade.timer','unattended-upgrades.service','snapd.service','snapd.socket',
             'snapd.snap-repair.timer','motd-news.timer','ua-timer.timer','fwupd-refresh.timer','update-notifier-download.timer']],
        'write_files':[
            {'path':'/etc/sysctl.d/90-rdc-probe.conf','permissions':'0644','content':sysctl},
            {'path':'/etc/default/grub.d/90-rdc-probe.cfg','permissions':'0644',
             'content':'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ipv6.disable=1"\n'},
            {'path':'/etc/rdc-probe.json','permissions':'0644','content':canonical({
                'schema':1,'plan_id':identity(plan),'role':'neutral-probe','mac':nic['mac'],'address':nic['address']}).decode()+'\n'}],
        'runcmd':[['/usr/sbin/update-grub']],
        'final_message':'Local probe seed applied. Verify from the disconnected console before attaching workload.'}
    return {'user-data':b'#cloud-config\n'+canonical(user)+b'\n',
            'meta-data':canonical({'instance-id':instance,'local-hostname':spec['name']})+b'\n',
            'network-config':canonical(network)+b'\n'}


def build_seed(plan, output: Path, runner, *, password_hash: str, ssh_public_key: str | None = None) -> dict:
    files=seed_files(plan,password_hash=password_hash,ssh_public_key=ssh_public_key)
    spec,_,_=_site(plan); output=_safe_parents(output)
    require(output.suffix=='.iso' and output.parent.is_dir(),'probe-seed-path')
    with records.lock(output.parent):
        require(not output.exists() and not output.with_suffix('.iso.json').exists(),'probe-seed-exists')
        with tempfile.TemporaryDirectory(prefix='.probe-seed-',dir=output.parent) as temporary:
            work=Path(temporary); candidate=work/'seed.iso'
            # genisoimage/isoinfo are shipped with the pinned PVE installation
            # (qemu-server dependency); xorriso is only a USB build prerequisite.
            command=['/usr/bin/genisoimage','-o',str(candidate),'-V','CIDATA','-J','-R',
                     '-uid','0','-gid','0','-input-charset','utf-8',
                     '-p','rdc-appliance-probe-v1','-graft-points']
            for name,raw in sorted(files.items()):
                path=work/name; _write_new(path,raw); command += [name+'='+str(path)]
            runner.run(command,timeout_s=120)
            for name,raw in files.items():
                check=runner.run(['/usr/bin/isoinfo','-R','-i',str(candidate),'-x','/'+name],timeout_s=60)
                require(check.returncode==0 and check.stdout==raw,'probe-seed-readback')
            image=file_record(candidate); require(image['size_bytes']<=8*1024*1024,'probe-seed-size')
            receipt={'schema':1,'plan_id':identity(plan),'ownership':spec['ownership'],'image':image,
                     'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()},'qualification':'not-run'}
            candidate.chmod(0o600); os.link(candidate,output)
            records.write(output.with_suffix('.iso.json'),receipt)
            fd=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            return receipt


def _seed(plan, seed):
    seed=_safe_parents(seed); receipt=records.read(seed.with_suffix('.iso.json'))
    spec,_,_=_site(plan)
    require(receipt.get('schema')==1 and receipt.get('plan_id')==identity(plan)
            and receipt.get('ownership')==spec['ownership'],'probe-seed-binding')
    info=seed.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600
            and info.st_nlink==1,'probe-seed-private')
    verify_file(seed,receipt['image'])
    return receipt


def _path(state,vmid):return Path(state)/'probe'/(str(vmid)+'.json')


def _read(plan,state,*,pending=False):
    spec,_,_=_site(plan); record=records.read(_path(state,spec['vmid']))
    require(record.get('schema')==1 and record['spec']['ownership']==spec['ownership']
            and record['spec']['plan_id']==spec['plan_id'],'probe-receipt-binding')
    require(pending or not record.get('pending'),'probe-operation-needs-inspection')
    return record


def _disk_size(text):
    match=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)([KMGT]?)',text)
    require(match is not None,'probe-disk-size')
    value=Decimal(match[1])*(1024**('KMGT'.index(match[2])+1) if match[2] else 1)
    require(value==int(value),'probe-disk-size')
    return int(value)


def _observe(record,runner):
    spec=record['spec']; observed=proxmox.observe_vm(spec['vmid'],runner); cfg=observed['config']
    require(not any(cfg.get(k) for k in ('args','hookscript','cicustom','lock','template')),'probe-unsafe-config')
    expected={**proxmox._base(spec),'serial0':'socket','vga':'serial0',
              'ide2':record['seed_volume']+',media=cdrom'}
    expected['net0']=proxmox._nic_text(spec['nics'][0],record['connected'])
    require(all(cfg.get(k)==v for k,v in expected.items()),'probe-config-drift')
    devices={k for k in cfg if re.fullmatch(r'(?:net|scsi|sata|ide|virtio|unused|hostpci|usb|efidisk|tpmstate|serial)[0-9]+',k)}
    require(devices=={'net0','scsi0','ide2','serial0'},'probe-device-drift')
    parts=cfg.get('scsi0','').split(',')
    require(re.fullmatch(re.escape(spec['storage'])+':vm-'+str(spec['vmid'])+r'-disk-[0-9]+',parts[0]) is not None
            and len(parts)==2 and parts[1].startswith('size='),'probe-disk-ownership')
    require(_disk_size(parts[1][5:])==record['disk_bytes'],'probe-disk-size')
    require(not record.get('disk_volume') or parts[0]==record['disk_volume'],'probe-disk-changed')
    verify_file(_safe_parents(record['seed_path']),record['seed_image'])
    return observed


def _mutate(record,kind,argv,runner,state,*,updates=None,running=False):
    desired={**record,**(updates or {}),'sequence':record['sequence']+1}
    desired.pop('pending',None);desired.pop('desired',None)
    intent={'kind':kind,'vmid':record['spec']['vmid'],'ownership':record['spec']['ownership'],
            'plan_id':record['spec']['plan_id'],'sequence':desired['sequence'],'desired_id':identity(desired),'running':running}
    op=records.begin(Path(state)/'operations',intent)
    records.write(_path(state,record['spec']['vmid']),{**record,'pending':op,'desired':{'receipt':desired,'running':running}})
    runner.run(argv,timeout_s=600 if kind=='probe-import' else 180)
    return _finish(desired,running,op,runner,state)


def _finish(desired,running,op,runner,state):
    observed=_observe(desired,runner)
    require(observed['running'] is running,'probe-running-outcome')
    result={**desired,'disk_volume':observed['disk_volume']}
    records.finish(Path(state)/'operations',op,{'config_id':identity(observed['config']),'boot_id':observed['boot_id']})
    records.write(_path(state,desired['spec']['vmid']),result)
    return observed


def reconcile_probe(plan,runner,state):
    """Explicit observation only; uncertain imports/starts/links are never replayed."""
    with records.lock(Path(state)/'probe'):
        pending=_read(plan,state,pending=True)
        require(type(pending.get('pending')) is str and type(pending.get('desired')) is dict,'probe-no-pending-operation')
        op=pending['pending']; desired=pending['desired']['receipt']; running=pending['desired']['running']
        journal=records.read(Path(state)/'operations'/(op+'.json')); intent=journal.get('operation',{})
        require(identity(intent)==op and intent.get('desired_id')==identity(desired)
                and desired['spec']==pending['spec'] and intent.get('running') is running
                and type(running) is bool,'probe-pending-binding')
        return _finish(desired,running,op,runner,state)


def prepare_probe(plan,release,image: Path,seed: Path,runner,state):
    """Import only the pinned Ubuntu image; leave the owned VM stopped/offline."""
    from .plan import validate_site
    validate_site(plan,release); spec,_,_=_site(plan)
    with records.lock(Path(state)/'probe'):
        path=_path(state,spec['vmid'])
        if path.exists():
            current=_read(plan,state); observed=_observe(current,runner)
            require(not observed['running'] and not current['connected'],'probe-must-be-disconnected-stopped')
            if current['phase']=='prepared':return observed
            require(current['phase']=='imported','probe-phase')
        else:
            image=_safe_parents(image)
            require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(image)) is not None,'probe-image-path')
            components=[c for c in release['components'] if c['id']=='probe-image'];require(len(components)==1,'probe-image-pin')
            component=components[0];verify_file(image,component.get('expanded',component))
            try:info=json.loads(runner.run(['/usr/bin/qemu-img','info','--output=json',str(image)]).stdout)
            except (ValueError,UnicodeError):raise ApplianceError('probe-image-format') from None
            require(type(info) is dict and info.get('format')=='qcow2' and type(info.get('virtual-size')) is int
                    and 0<info['virtual-size']<=spec['disk_gib']*1024**3,'probe-image-format')
            require(not any(info.get(k) for k in ('backing-filename','full-backing-filename','encrypted'))
                    and not any(info.get('format-specific',{}).get('data',{}).get(k) for k in ('data-file','encrypt')),
                    'probe-image-external-data')
            seed_record=_seed(plan,seed)
            resources=proxmox._json(runner,'/cluster/resources','--type','vm')
            require(type(resources) is list and all(r.get('vmid')!=spec['vmid'] for r in resources),'vmid-in-use')
            node=proxmox._name(proxmox._run(runner,['/usr/bin/hostname','-s']).strip())
            base='/nodes/'+node+'/storage/'+spec['storage']
            storage=proxmox._json(runner,base+'/status')
            require(storage.get('active')==1 and storage.get('enabled')==1 and storage.get('type')=='lvmthin'
                    and 'images' in storage.get('content','').split(',') and type(storage.get('avail')) is int
                    and storage['avail']>=(spec['disk_gib']+2)*1024**3,'vm-storage')
            require(proxmox._json(runner,base+'/content','--content','images','--vmid',str(spec['vmid']))==[],'vm-unowned-disk')
            local=proxmox._json(runner,'/storage/local')
            require(local.get('type')=='dir' and local.get('path')=='/var/lib/vz'
                    and 'iso' in local.get('content','').split(','),'probe-seed-storage')
            volume='local:iso/rdc-probe-'+seed_record['image']['sha256']+'.iso'
            destination=_safe_parents(proxmox._run(runner,['/usr/sbin/pvesm','path',volume]).strip())
            expected=Path('/var/lib/vz/template/iso')/volume.split('/')[-1]
            require(destination==expected or getattr(runner,'seed_target',None)==destination,'probe-seed-storage-path')
            require(destination.parent.is_dir(),'probe-seed-storage-path')
            if destination.exists():verify_file(destination,seed_record['image'])
            else:_copy_verified(seed,destination,seed_record['image'])
            info_seed=destination.stat()
            require(stat.S_IMODE(info_seed.st_mode)==0o600 and info_seed.st_uid==os.geteuid()
                    and info_seed.st_nlink==1,'probe-seed-private')
            current={'schema':1,'spec':spec,'phase':'imported','sequence':0,'connected':False,
                     'disk_bytes':info['virtual-size'],'source_image':component['sha256'],
                     'seed_volume':volume,'seed_path':str(destination),'seed_image':seed_record['image']}
            options={**proxmox._base(spec),'serial0':'socket','vga':'serial0','ide2':volume+',media=cdrom',
                     'scsi0':spec['storage']+':0,import-from='+str(image)}
            argv=[proxmox.QM,'create',str(spec['vmid'])]
            for key,value in options.items():argv+=['--'+key,value]
            _mutate(current,'probe-import',argv,runner,state)
            current=_read(plan,state)
        target=spec['disk_gib']*1024**3
        if current['disk_bytes']!=target:
            _mutate(current,'probe-grow',[proxmox.QM,'resize',str(spec['vmid']),'scsi0',str(spec['disk_gib'])+'G'],
                    runner,state,updates={'disk_bytes':target,'phase':'prepared'})
        else:records.write(path,{**current,'phase':'prepared'})
        return _observe(_read(plan,state),runner)


def start_probe(plan,runner,state):
    """Explicit disconnected first boot; no creation, no automatic start."""
    with records.lock(Path(state)/'probe'):
        record=_read(plan,state);require(record['phase']=='prepared','probe-start-isolation')
        observed=_observe(record,runner);require(not observed['running'],'probe-must-be-stopped')
        if record['connected']:
            _mutate(record,'probe-isolate',[proxmox.QM,'set',str(record['spec']['vmid']),
                    '--net0',proxmox._nic_text(record['spec']['nics'][0],False)],runner,state,
                    updates={'connected':False})
            record=_read(plan,state)
        return _mutate(record,'probe-start',[proxmox.QM,'start',str(record['spec']['vmid'])],runner,state,running=True)


def attest_console(plan,checks,runner,state):
    require(type(checks) is dict and set(checks)==set(CONSOLE_CHECKS) and all(v is True for v in checks.values()),'probe-console-checks')
    record=_read(plan,state);observed=_observe(record,runner)
    require(record['phase']=='prepared' and not record['connected'] and observed['running'] and observed['boot_id'],'probe-console-isolation')
    return ProbeAttestation(identity(plan),record['spec']['vmid'],observed['boot_id'],identity(observed['config']),time.monotonic(),_TOKEN)


def attach_workload(plan,runner,state,*,attestation):
    """Connect only the existing workload NIC after fresh guest/router checks."""
    from . import router
    require(type(attestation) is ProbeAttestation and attestation.token is _TOKEN,'probe-console-attestation-required')
    with records.lock(Path(state)/'probe'):
        record=_read(plan,state);observed=_observe(record,runner)
        require(not record['connected'] and observed['running'],'probe-attachment-state')
        require(attestation.plan_id==identity(plan) and attestation.vmid==record['spec']['vmid']
                and attestation.boot_id==observed['boot_id'] and attestation.config_id==identity(observed['config'])
                and 0<=time.monotonic()-attestation.checked_at<=300,'probe-console-attestation-stale')
        fresh=router.collect_router(plan,runner);ready=router.router_ready(plan,fresh)
        require(ready['checks_passed'] and fresh.get('stage')=='transit' and fresh.get('guard_blocking') is False,'probe-router-not-ready')
        _,router_vm=router._vm(plan,runner)
        nic=next(n for n in proxmox.vm_spec(plan,'router')['nics'] if n['zone']=='workload')
        require(router_vm['boot_id']==fresh['vm_boot_id'] and router_vm['nics']['net'+str(nic['index'])]['connected'],
                'probe-router-workload-disconnected')
        # Re-observe the probe after the router channel roundtrip, before intent.
        current=_observe(record,runner)
        require(current['boot_id']==observed['boot_id'] and current['config']==observed['config']
                and 0<=time.monotonic()-attestation.checked_at<=300,'probe-console-attestation-stale')
        return _mutate(record,'probe-connect-workload',[proxmox.QM,'set',str(record['spec']['vmid']),
                       '--net0',proxmox._nic_text(record['spec']['nics'][0],True)],runner,state,
                       updates={'connected':True},running=True)

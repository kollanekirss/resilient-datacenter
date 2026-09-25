"""Resumable isolated console installation; operator attestation is not OS verification."""
import copy
import hashlib
import json
import re
from portable_plan import validate, require, MODULES
from portable_state import lock, read, write
from proxmox_provision import payloads, owned, wait_task


def context(plan,role,medium):
    plan=validate(plan);require(role in MODULES,'Select a planned guest role.')
    kind='opnsense' if role=='edge' else 'ubuntu'
    require(type(medium) is dict and medium.get('kind')==kind and re.fullmatch(r'[a-z][a-z0-9-]{0,62}:iso/[A-Za-z0-9_.-]+\.iso',str(medium.get('volume','')))
            and re.fullmatch('[a-f0-9]{64}',str(medium.get('sha256',''))),'Wrong or invalid verified media for this guest.')
    wanted=next(p for p in payloads(plan) if p['vmid']==plan['vms'][role]['id'])
    binding=hashlib.sha256(json.dumps({'plan':plan,'role':role,'media':medium},sort_keys=True).encode()).hexdigest()
    return plan,wanted,f"/nodes/{plan['proxmox']['node']}/qemu/{wanted['vmid']}",binding


def marker(binding,phase):return 'rdc-guest-v1:'+binding+':'+phase


def observed(api,base,wanted,plan,medium,binding,stage):
    cfg=api.request('GET',base+'/config');status=api.request('GET',base+'/status/current')
    require(type(cfg) is dict and re.fullmatch('[a-f0-9]{40}',str(cfg.get('digest',''))),'Cannot obtain a configuration compare-and-swap digest.')
    require(type(status) is dict and status.get('status') in ('running','stopped'),'Cannot observe guest power state.')
    clone=copy.deepcopy(cfg)
    if stage!='shell':
        require(cfg.get('description')==marker(binding,stage),'Guest phase or ownership differs; inspect before continuing.')
        if stage=='attached':
            require(cfg.get('ide2')==medium['volume']+',media=cdrom' and cfg.get('boot')=='order=ide2;scsi0','Installer media or boot order differs.')
            clone.pop('ide2');clone['boot']=wanted['boot']
        clone['description']=wanted['description']
    owned(clone,wanted,plan['proxmox']['storage'])
    return cfg,status['status']


def load_state(folder,role,binding):
    path=folder/(role+'.json')
    record=read(path) if path.exists() else {'binding':binding,'phase':'new'}
    require(type(record) is dict and record.get('binding')==binding,'Guest journal belongs to different media or site plan.')
    return path,record


def update(api,base,cfg,data,node):
    result=api.request('POST',base+'/config',dict(data,digest=cfg['digest']))
    if result is not None:wait_task(api,node,result)


def attach(plan,role,medium,api,folder):
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        require(record['phase'] in ('new','attach-requested','media-attached'),'Installer cannot be reattached after a start request.')
        cfg=api.request('GET',base+'/config')
        stage='attached' if cfg.get('description')==marker(binding,'attached') else 'shell'
        cfg,power=observed(api,base,wanted,plan,medium,binding,stage)
        require(power=='stopped','Power off the guest through its console before attaching installation media.')
        if stage=='shell':
            write(path,{'binding':binding,'phase':'attach-requested'})
            update(api,base,cfg,{'ide2':medium['volume']+',media=cdrom','boot':'order=ide2;scsi0','description':marker(binding,'attached')},plan['proxmox']['node'])
            observed(api,base,wanted,plan,medium,binding,'attached')
        result={'binding':binding,'phase':'media-attached','guest_os':'not-installed','network_links':'disconnected'}
        write(path,result);return result


def start(plan,role,medium,api,folder):
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        require(record['phase'] in ('media-attached','installer-start-requested'),'Attach media before starting the installer; completed guests cannot be reinstalled.')
        cfg,power=observed(api,base,wanted,plan,medium,binding,'attached')
        if record['phase']=='installer-start-requested':
            require(power=='running','Previous installer start may have completed. Inspect the console; do not replay it. Finish installation or start manually if it never ran.')
            return dict(record,power=power)
        require(power=='stopped','An unexpected running installer needs console inspection.')
        result={'binding':binding,'phase':'installer-start-requested','guest_os':'not-verified','network_links':'disconnected'}
        write(path,result)  # durable before the potentially uncertain POST
        upid=api.request('POST',base+'/status/start',{})
        wait_task(api,plan['proxmox']['node'],upid)
        return result


def finish(plan,role,medium,api,folder,*,operator):
    require(type(operator) is str and 1<=len(operator)<=80 and all(c.isalnum() or c in ' .@_-' for c in operator),'Record the operator who confirmed installation and local credentials.')
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        require(record['phase'] in ('installer-start-requested','finish-requested','disk-ready'),'No installer session is ready for completion.')
        cfg=api.request('GET',base+'/config')
        stage='disk-ready' if cfg.get('description')==marker(binding,'disk-ready') else 'attached'
        cfg,power=observed(api,base,wanted,plan,medium,binding,stage)
        require(power=='stopped','Complete installation, set private credentials and shut down inside the guest before finishing.')
        if stage=='attached':
            write(path,{'binding':binding,'phase':'finish-requested','operator':operator})
            update(api,base,cfg,{'delete':'ide2','boot':'order=scsi0','description':marker(binding,'disk-ready')},plan['proxmox']['node'])
            observed(api,base,wanted,plan,medium,binding,'disk-ready')
        result={'binding':binding,'phase':'disk-ready','operator':operator,'os_verification':'operator-attested',
                'applications':'not-installed','network_links':'disconnected'}
        write(path,result);return result


def boot(plan,role,medium,api,folder):
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        require(record['phase'] in ('disk-ready','disk-start-requested','disk-boot-observed'),'Finish console installation before booting the disk.')
        cfg,power=observed(api,base,wanted,plan,medium,binding,'disk-ready')
        if power=='stopped':
            require(record['phase']=='disk-ready','A previous disk start is unresolved or the guest stopped. Inspect/start via the console, then rerun boot observation.')
            record=dict(record,phase='disk-start-requested');write(path,record)
            upid=api.request('POST',base+'/status/start',{});wait_task(api,plan['proxmox']['node'],upid)
        cfg,power=observed(api,base,wanted,plan,medium,binding,'disk-ready')
        require(power=='running','Guest is not running after disk-start request.')
        result=dict(record,phase='disk-boot-observed',power='running',boot_source='disk-only',
                    os_verification='operator-attested',applications='not-installed',network_links='disconnected',
                    notice='Running disk-only VM observed; OS identity and login were attested by the operator, not probed automatically.')
        write(path,result);return result


def status(plan,role,medium,api,folder):
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        cfg=api.request('GET',base+'/config')
        stage=('disk-ready' if cfg.get('description')==marker(binding,'disk-ready') else
               'attached' if cfg.get('description')==marker(binding,'attached') else 'shell')
        cfg,power=observed(api,base,wanted,plan,medium,binding,stage)
        return dict(record,observed_stage=stage,power=power,network_links='disconnected',applications='not-installed')


def confirm_login(plan,role,medium,api,folder,*,operator):
    require(type(operator) is str and 1<=len(operator)<=80 and all(c.isalnum() or c in ' .@_-' for c in operator),
            'Name the operator who verified the installed OS and successful console login.')
    plan,wanted,base,binding=context(plan,role,medium)
    with lock(folder) as folder:
        path,record=load_state(folder,role,binding)
        require(record['phase'] in ('disk-boot-observed','guest-installed-attested'),'Observe a disk-only start before confirming console login.')
        cfg,power=observed(api,base,wanted,plan,medium,binding,'disk-ready')
        require(power=='running','Guest must be running for console-login attestation.')
        result=dict(record,phase='guest-installed-attested',operator=operator,os_verification='operator-attested',
                    power=power,applications='not-installed',network_links='disconnected')
        write(path,result);return result

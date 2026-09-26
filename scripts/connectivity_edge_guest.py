"""Isolated OPNsense console lifecycle; no networking or automatic reinstall."""
import copy
import re
from datetime import datetime, timezone
from portable_plan import require
from proxmox_provision import owned, wait_task


def marker(state,stage):
    return 'rdc-connectivity-edge-v1:'+state['revision']+':'+state['medium']['sha256']+':'+stage


def inspect(api,base,wanted,storage,state):
    cfg=api.request('GET',base+'/config?current=1')
    pending=api.request('GET',base+'/pending')
    require(type(pending) is list and all(type(item) is dict and 'pending' not in item and not item.get('delete') for item in pending),
            'Guest has pending configuration changes; inspect and resolve them in Proxmox before continuing.')
    power=api.request('GET',base+'/status/current')
    require(type(cfg) is dict and re.fullmatch('[a-f0-9]{40}',str(cfg.get('digest',''))),'Cannot obtain the guest configuration digest.')
    require(type(power) is dict and power.get('status') in ('running','stopped'),'Cannot inspect guest power state.')
    stage='shell';clone=copy.deepcopy(cfg)
    if cfg.get('description')==marker(state,'attached'):
        stage='attached'
        require(state['upload'] is not None and cfg.get('ide2')==volume(state)+',media=cdrom' and cfg.get('boot')=='order=ide2;scsi0',
                'Installer media or boot order differs from the journal.')
        clone.pop('ide2');clone['boot']=wanted['boot'];clone['description']=wanted['description']
    elif cfg.get('description')==marker(state,'disk'):
        stage='disk';clone['description']=wanted['description']
    owned(clone,wanted,storage)
    return cfg,{'stage':stage,'power':power['status'],'boot':'installer-first' if stage=='attached' else 'disk-only'}


def volume(state):return state['upload']['storage']+':iso/'+state['upload']['filename']


def operator_name(value):
    require(type(value) is str and 1<=len(value)<=80 and all(c.isalnum() or c in ' .@_-' for c in value),'Name the operator who completed the console checks; do not enter a password.')


def perform(action,state,api,node,wanted,storage,persist,*,operator=None,version=None):
    base=f"/nodes/{node}/qemu/{wanted['vmid']}"
    transitions={'attach':('uploaded','media-attached','shell','attached'),
                 'start':('media-attached','installer-running','attached','attached'),
                 'finish':('installer-running','disk-ready','attached','disk'),
                 'boot':('disk-ready','disk-running','disk','disk')}
    pending=state['pending']
    require(pending is None or pending['action']==action,'A different guest operation is unresolved; resume that checkpoint first.')
    if pending and pending['upid']:wait_task(api,node,pending['upid'])
    cfg,seen=inspect(api,base,wanted,storage,state)
    if action=='confirm':
        require(state['phase'] in ('disk-running','installed-attested') and seen['stage']=='disk' and seen['power']=='running',
                'Observe disk-only boot before attesting console login.')
        operator_name(operator)
        require(type(version) is str and re.fullmatch(re.escape(state['catalogue']['version'])+r'(?:\.[0-9]+)*(?:_[0-9]+)?',version),
                'Record the OPNsense version observed at the console; it must belong to the pinned release.')
        state['attestation']={'operator':operator,'version':version,'at':datetime.now(timezone.utc).isoformat()}
        state['phase']='installed-attested';persist(state);return seen
    require(action in transitions,'Unsupported guest action.')
    before,after,old,new=transitions[action]
    require(state['phase'] in (before,after),'Complete the preceding guest checkpoint first; completed guests cannot be reinstalled.')
    if action=='finish':operator_name(operator)
    target_power='running' if action in ('start','boot') else 'stopped'
    if state['phase']==after:
        require(seen['stage']==new and seen['power']==target_power,'Guest no longer matches this checkpoint. Inspect the console; no request was replayed.')
        return seen
    if pending:
        require(seen['stage']==new and seen['power']==target_power,
                'Previous guest request is uncertain or unresolved. Inspect the task and console; it will not be replayed.')
    else:
        require(seen['stage']==old,'Unexpected guest phase; no configuration will be adopted.')
        require(seen['power']=='stopped','The guest must be stopped. Complete installation and shut down from its console before continuing.')
        state['pending']={'action':action,'upid':None};persist(state)
        if action in ('start','boot'):
            result=api.request('POST',base+'/status/start',{})
            require(valid_upid(result),'Guest start outcome is uncertain; inspect the console and task.')
        else:
            data={'digest':cfg['digest'],'description':marker(state,new)}
            if action=='attach':data.update(ide2=volume(state)+',media=cdrom',boot='order=ide2;scsi0')
            else:data.update(delete='ide2',boot='order=scsi0')
            result=api.request('POST',base+'/config',data)
            require(result is None or valid_upid(result),'Guest configuration outcome is uncertain; inspect Proxmox.')
        if result:
            state['pending']['upid']=result;state['tasks'][action]=result;persist(state)
            wait_task(api,node,result)
        cfg,seen=inspect(api,base,wanted,storage,state)
        require(seen['stage']==new and seen['power']==target_power,'Guest did not reach the expected state; inspect before resuming.')
    state['phase']=after;state['pending']=None;persist(state)
    return seen


def valid_upid(value):
    return type(value) is str and 5<len(value)<=512 and value.startswith('UPID:') and not any(c.isspace() for c in value)

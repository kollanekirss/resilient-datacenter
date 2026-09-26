"""Journaled OPNsense media and console installation for the connectivity plan."""
import re
import uuid
from pathlib import Path
from connectivity_state import load, NAME
from connectivity_operations import saved_settings
import connectivity_provision as provision
import connectivity_edge_guest as guest
import guest_media
from portable_plan import require, name
from portable_state import directory, lock, read, write, regular
from proxmox_provision import wait_task

PHASES=('new','media-ready','uploaded','media-attached','installer-running','disk-ready','disk-running','installed-attested')
ACTIONS=('prepare','upload','attach','start','finish','boot','confirm','status')


def initial(config):
    return {'schema_version':1,'revision':config['revision'],'catalogue':guest_media.catalogue()['opnsense'],
            'phase':'new','medium':None,'upload':None,'pending':None,'tasks':{},'attestation':None}


def validate(config,state):
    reference=initial(config)
    require(type(state) is dict and set(state)==set(reference) and type(state['schema_version']) is int and state['schema_version']==1
            and state['revision']==config['revision'] and state['catalogue']==reference['catalogue'] and state['phase'] in PHASES,
            'Guest journal is invalid or belongs to another configuration/media pin.')
    medium=state['medium']
    if medium is not None:
        require(type(medium) is dict and set(medium)=={'kind','version','source_sha256','sha256','size','filename'}
                and medium['kind']=='opnsense' and medium['version']==reference['catalogue']['version']
                and medium['source_sha256']==reference['catalogue']['sha256'] and medium['filename']=='opnsense.iso'
                and type(medium['sha256']) is str and re.fullmatch('[a-f0-9]{64}',medium['sha256'])
                and type(medium['size']) is int and 0<medium['size']<=reference['catalogue']['iso_max_bytes'],'Invalid prepared media identity.')
    require(state['phase']=='new' or medium is not None,'Prepared media identity is missing.')
    upload=state['upload']
    if upload is not None:
        require(type(upload) is dict and set(upload)=={'storage','filename'} and name(upload['storage'])
                and type(upload['filename']) is str and re.fullmatch(r'rdc-[a-f0-9]{32}\.iso',upload['filename']), 'Invalid upload record.')
    require(PHASES.index(state['phase'])<2 or upload is not None,'Uploaded media identity is missing.')
    pending=state['pending']
    if pending is not None:
        require(type(pending) is dict and set(pending)=={'action','upid'} and pending['action'] in ('upload','attach','start','finish','boot')
                and (pending['upid'] is None or guest.valid_upid(pending['upid'])),'Invalid pending guest request.')
        expected={'upload':'media-ready','attach':'uploaded','start':'media-attached','finish':'installer-running','boot':'disk-ready'}
        require(state['phase']==expected[pending['action']],'Pending request does not match the guest checkpoint.')
    require(type(state['tasks']) is dict and set(state['tasks'])<={'upload','attach','start','finish','boot'}
            and all(guest.valid_upid(value) for value in state['tasks'].values()),'Invalid retained guest task history.')
    if pending and pending['upid']:
        require(state['tasks'].get(pending['action'])==pending['upid'],'Pending task history differs.')
    if PHASES.index(state['phase'])>=2:require('upload' in state['tasks'],'Verified upload task evidence is missing.')
    attestation=state['attestation']
    if attestation is not None:
        from datetime import datetime
        require(type(attestation) is dict and set(attestation)=={'operator','version','at'} and type(attestation['version']) is str
                and re.fullmatch(re.escape(reference['catalogue']['version'])+r'(?:\.[0-9]+)*(?:_[0-9]+)?',attestation['version'])
                and type(attestation['at']) is str,'Invalid console attestation.')
        guest.operator_name(attestation['operator'])
        try:require(datetime.fromisoformat(attestation['at']).tzinfo is not None,'Attestation time needs a timezone.')
        except ValueError:raise ValueError('Invalid console attestation timestamp.') from None
    require((state['phase']=='installed-attested')==(attestation is not None),'Console attestation does not match the checkpoint.')
    return state


def verify_upload(state,api,node):
    require(state['upload'] is not None and 'upload' in state['tasks'],'No verified media upload task is recorded.')
    wait_task(api,node,state['tasks']['upload'])
    listing=api.request('GET',f"/nodes/{node}/storage/{state['upload']['storage']}/content")
    require(type(listing) is list and sum(type(item) is dict and item.get('volid')==guest.volume(state)
            and type(item.get('size')) is int and item['size']==state['medium']['size'] for item in listing)==1,
            'Uploaded media is missing or changed; attachment is blocked.')


def transfer(state,cache,storage,api,node,persist):
    require(state['phase'] in ('media-ready','uploaded'),'Prepare pinned media before uploading it.')
    require(name(storage),'Use a valid ISO storage identifier.')
    require(guest_media.verify(cache,'opnsense')==state['medium'],'Cached media identity changed; upload is blocked.')
    if state['upload'] is not None:require(storage==state['upload']['storage'],'Resume with the original ISO storage.')
    if state['phase']=='uploaded':verify_upload(state,api,node);return
    if state['pending']:
        require(state['pending']['action']=='upload' and state['pending']['upid'],
                'Previous upload outcome is uncertain. Inspect Proxmox tasks and media; it will not be replayed.')
    else:
        status=api.request('GET',f'/nodes/{node}/storage/{storage}/status')
        require(type(status) is dict and status.get('active')==1 and status.get('enabled')==1
                and 'iso' in str(status.get('content','')).split(',') and provision.capacity(status.get('avail'),state['medium']['size']+provision.GIB),
                'ISO storage is unavailable or lacks capacity plus a 1 GiB reserve.')
        state['upload']={'storage':storage,'filename':'rdc-'+uuid.uuid4().hex+'.iso'}
        state['pending']={'action':'upload','upid':None};persist(state)
        with regular(cache/'opnsense.iso') as stream:
            upid=api.upload(node,storage,state['upload']['filename'],stream,state['medium']['size'],state['medium']['sha256'])
        require(guest.valid_upid(upid),'Upload outcome is uncertain; inspect Proxmox.')
        state['pending']['upid']=upid;state['tasks']['upload']=upid;persist(state)
    verify_upload(state,api,node)
    state['phase']='uploaded';state['pending']=None;persist(state)


def run(folder,plan,action,*,api=None,storage=None,operator=None,version=None):
    require(action in ACTIONS,'Unsupported edge checkpoint.')
    folder=Path(folder)
    with lock(folder):
        require(load(folder/NAME)==plan,'Connectivity plan changed; reopen the wizard.')
        config=saved_settings(folder,plan)
        require(config is not None,'Allocate the connectivity shells first.')
        state_dir=folder/'provisioning';allocation_path=state_dir/'journal.json'
        allocation=provision.validate_journal(plan,config,read(allocation_path))
        edge=next(vm for vm in config['vms'] if vm['role']=='opnsense')
        require(allocation['vms'].get(str(edge['id']),{}).get('state')=='verified','The OPNsense shell allocation is not verified.')
        path=state_dir/'edge.json'
        if allocation.get('edge_installation'):
            require(path.exists() and not path.is_symlink(),'Guest journal is missing or symlinked; installation history cannot be reset.')
            state=validate(config,read(path))
        else:
            require(not path.exists() and not path.is_symlink(),'Unbound guest journal will not be adopted.')
            state=initial(config)
        def persist(value):validate(config,value);write(path,value)
        if action=='status' and not allocation.get('edge_installation'):
            return {'phase':'not-started','os_verification':'not-verified','network_links':'disconnected','observed':None}
        if not allocation.get('edge_installation'):
            require(action=='prepare','Prepare pinned installation media first.')
            allocation['edge_installation']=True;write(allocation_path,allocation);persist(state)
        node=plan['answers']['node'];wanted=next(item for item in provision.payloads(plan,config) if item['vmid']==edge['id'])
        observed=None
        if action=='prepare':
            require(state['phase'] in ('new','media-ready') and state['pending'] is None,'Media is already bound to installation progress.')
            state['medium']=guest_media.prepare('opnsense',state_dir/'media');state['phase']='media-ready';persist(state)
        else:
            require(api is not None,'This checkpoint needs an authenticated Proxmox connection.')
            if action=='upload':
                _,observed=guest.inspect(api,f'/nodes/{node}/qemu/{edge["id"]}',wanted,plan['answers']['storage'],state)
                require(observed['stage']=='shell' and observed['power']=='stopped','Upload requires the owned stopped edge shell.')
                transfer(state,state_dir/'media',storage,api,node,persist)
            elif action=='status':
                # Observation is read-only and never clears a pending/failed request.
                if state['medium'] is not None:
                    _,observed=guest.inspect(api,f'/nodes/{node}/qemu/{edge["id"]}',wanted,plan['answers']['storage'],state)
            else:
                if action=='attach':verify_upload(state,api,node)
                observed=guest.perform(action,state,api,node,wanted,plan['answers']['storage'],persist,operator=operator,version=version)
        return {'phase':state['phase'],'pending':state['pending'],'os_verification':'operator-attested' if state['attestation'] else 'not-verified',
                'network_links':'disconnected','observed':observed,'attestation':state['attestation']}

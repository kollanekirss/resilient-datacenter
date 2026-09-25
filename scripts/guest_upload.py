"""Verified media uploads with durable intent, unique volumes and task receipts."""
import hashlib
import json
import re
import uuid
from portable_plan import validate,require,name
from portable_state import lock,read,write,regular
from guest_media import verify
from proxmox_provision import wait_task


def binding(plan):return hashlib.sha256(json.dumps(validate(plan),sort_keys=True).encode()).hexdigest()


def receipt(plan,kind,folder,api):
    from pathlib import Path
    require(kind in ('ubuntu','opnsense'),'Unknown media kind.')
    record=read(Path(folder)/('upload-'+kind+'.json'))
    require(type(record) is dict and record.get('binding')==binding(plan) and record.get('phase')=='uploaded'
            and record.get('kind')==kind and name(record.get('storage'))
            and re.fullmatch(r'rdc-[a-f0-9-]+\.iso',str(record.get('filename','')))
            and re.fullmatch('[a-f0-9]{64}',str(record.get('sha256','')))
            and type(record.get('size')) is int and record['size']>0,
            'No completed media upload receipt matches this site plan.')
    node=plan['proxmox']['node'];volume=record['storage']+':iso/'+record['filename']
    wait_task(api,node,record.get('task'),timeout=10)
    listing=api.request('GET',f"/nodes/{node}/storage/{record['storage']}/content")
    require(type(listing) is list and any(type(x) is dict and x.get('volid')==volume and x.get('size')==record['size'] for x in listing),
            'Uploaded ISO is missing or its size changed. Do not attach unverified media.')
    return {'kind':kind,'volume':volume,'sha256':record['sha256'],'size':record['size']}


def upload(plan,kind,cache,storage,api,folder):
    plan=validate(plan);require(name(storage),'Use a valid ISO storage identifier.')
    medium=verify(cache,kind);node=plan['proxmox']['node']
    with lock(folder) as folder:
        path=folder/('upload-'+kind+'.json')
        if path.exists():
            record=read(path)
            require(record.get('binding')==binding(plan) and record.get('sha256')==medium['sha256'] and record.get('storage')==storage,
                    'Existing upload belongs to different media, storage or plan.')
            require(record.get('phase') in ('upload-requested','uploaded'),'Invalid upload journal.')
            require(record.get('task'),'A previous upload has an uncertain outcome. Inspect Proxmox and abandon that upload record explicitly before starting a new unique upload.')
        else:
            status=api.request('GET',f'/nodes/{node}/storage/{storage}/status')
            require(type(status) is dict and status.get('active')==1 and status.get('enabled')==1 and 'iso' in str(status.get('content','')).split(',')
                    and type(status.get('avail')) in (int,float) and status['avail']>=medium['size']+1024**3,
                    'ISO storage is unavailable, lacks ISO support or lacks capacity plus 1 GiB reserve.')
            filename='rdc-'+uuid.uuid4().hex+'.iso'
            record={'binding':binding(plan),'kind':kind,'phase':'upload-requested','storage':storage,
                    'filename':filename,'sha256':medium['sha256'],'size':medium['size']}
            write(path,record)
            with regular(cache/medium['filename']) as stream:
                record['task']=api.upload(node,storage,filename,stream,medium['size'],medium['sha256'])
            write(path,record)
        wait_task(api,node,record['task'],timeout=1800)
        record['phase']='uploaded';write(path,record)
        return receipt(plan,kind,folder,api)


def abandon(plan,kind,folder):
    """Explicit local reset for an uncertain upload. Never delete remote media."""
    require(kind in ('ubuntu','opnsense'),'Unknown media kind.')
    with lock(folder) as folder:
        path=folder/('upload-'+kind+'.json');record=read(path)
        require(record.get('binding')==binding(plan) and record.get('phase')=='upload-requested','Only an unresolved upload may be abandoned.')
        require(not any((folder/(role+'.json')).exists() for role in ('edge','dns','nginx','chat','files','partner')),
                'Guest progress exists; do not abandon referenced media.')
        archive=folder/('abandoned-'+kind+'-'+uuid.uuid4().hex+'.json')
        path.rename(archive)
        return {'state':'upload-abandoned','remote_files':'retained','notice':'Old remote files/tasks were retained. A new upload uses a new name; inspect orphaned media separately.'}

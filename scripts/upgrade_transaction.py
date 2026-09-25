"""Durable application upgrade ordering; runtime owns only fixed reviewed paths."""
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import stat
import uuid
from application_catalogue import for_owner,transition
from backup_scope import include,network_owner,package
from backup_contracts import binary_paths
from restore_transaction import atomic_json,read_journal,sync_directory

PENDING=Path('etc/rdc-upgrade-pending.json')
JOURNALS=Path('var/lib/rdc-upgrades/transactions')
RESULT=Path('var/lib/rdc-upgrades/result.json')
PLAN_FIELDS={'source_owner','target_owner','source_hashes'}
FIELDS=PLAN_FIELDS|{'schema_version','id','phase','started_at','snapshot'}


class UpgradeError(ValueError):
    def __init__(self,recovered,*,committed=False):
        self.recovered=recovered;self.committed=committed
        super().__init__('Upgrade needs attention. '+('The new version is committed; use upgrade recover to finish it, never automatically revert user data.' if committed else
            ('Previous version and data recovery verified.' if recovered else 'Keep the node isolated and use upgrade recover; no successful recovery is claimed.')))


def timestamp(value):
    if not isinstance(value,str):raise ValueError('Invalid upgrade time')
    result=datetime.fromisoformat(value)
    if result.tzinfo is None:raise ValueError('Upgrade times require a timezone')
    return result


def validate_plan(data):
    if not isinstance(data,dict) or set(data)!=PLAN_FIELDS:raise ValueError('Unknown upgrade plan')
    source=data['source_owner'];target=data['target_owner']
    if not isinstance(source,dict) or 'applications' not in source or not isinstance(target,dict) or 'applications' not in target:raise ValueError('Upgrade requires complete application ownership')
    if include(network_owner(source),source['applications'])!=source or include(network_owner(target),target['applications'])!=target:raise ValueError('Unknown application scope')
    reviewed=transition(package(source['applications']),for_owner(source['applications']))
    if reviewed is None:raise ValueError('Already current; no upgrade transaction is needed')
    expected=dict(source,applications=dict(source['applications'],images={key:pin['image'] for key,pin in reviewed['target'].items()}))
    if target!=expected:raise ValueError('Upgrade cannot change network, node, domain or application identity')
    hashes=data['source_hashes']
    if not isinstance(hashes,dict) or set(hashes)!=set(binary_paths(source)) or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in hashes.values()):raise ValueError('Upgrade requires complete source component identity')


def validate_snapshot(value,*,started_at):
    if not isinstance(value,dict) or set(value)!={'id','captured_at'} or not isinstance(value['id'],str) or not re.fullmatch('[a-f0-9]{64}',value['id']):raise ValueError('Upgrade requires a complete verified snapshot identity')
    captured=timestamp(value['captured_at']);now=datetime.now(timezone.utc)
    if captured<timestamp(started_at) or captured>now or (now-captured).total_seconds()>3600:raise ValueError('Upgrade snapshot must be captured during this stopped-service maintenance window and no more than one hour old')


def validate(data,*,fresh_snapshot=False):
    if not isinstance(data,dict) or set(data)!=FIELDS or type(data['schema_version']) is not int or data['schema_version']!=1 or not isinstance(data['id'],str) or not re.fullmatch('[a-f0-9]{32}',data['id']):raise ValueError('Unknown upgrade journal')
    validate_plan({key:data[key] for key in PLAN_FIELDS});timestamp(data['started_at'])
    if data['phase'] not in ('preparing','migrating','committed','rolled-back'):raise ValueError('Unknown upgrade phase')
    snapshot=data['snapshot']
    if snapshot is not None:
        if fresh_snapshot:validate_snapshot(snapshot,started_at=data['started_at'])
        elif not isinstance(snapshot,dict) or set(snapshot)!={'id','captured_at'} or not isinstance(snapshot['id'],str) or not re.fullmatch('[a-f0-9]{64}',snapshot['id']) or timestamp(snapshot['captured_at'])<timestamp(data['started_at']):raise ValueError('Invalid retained upgrade snapshot')
    elif data['phase'] in ('migrating','committed'):raise ValueError('Migration has no verified recovery snapshot')
    return data


def present(path):return path.exists() or path.is_symlink()


def directory(path):
    if not present(path):path.mkdir(mode=0o700,parents=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe upgrade journal directory')
    for parent in path.parents:
        if parent.is_symlink():raise ValueError('Linked upgrade journal parent')


def save(root,journal):
    validate(journal)
    atomic_json(root/JOURNALS/(journal['id']+'.json'),journal)


def pending(root):
    marker=read_journal(root/PENDING)
    if not isinstance(marker,dict) or set(marker)!={'schema_version','transaction_id'} or marker['schema_version']!=1 or not isinstance(marker['transaction_id'],str) or not re.fullmatch('[a-f0-9]{32}',marker['transaction_id']):raise ValueError('Unknown upgrade marker')
    data=validate(read_journal(root/JOURNALS/(marker['transaction_id']+'.json')))
    if data['id']!=marker['transaction_id']:raise ValueError('Upgrade journal and marker differ')
    return data


def finish(root,journal,backend):
    if journal['phase'] not in ('committed','rolled-back'):raise ValueError('Cannot publish an unverified version')
    backend.publish(journal)
    backend.clean(journal)
    state='upgraded-service-verified' if journal['phase']=='committed' else 'previous-version-restored'
    result={'schema_version':1,'transaction_id':journal['id'],'state':state,'snapshot':journal['snapshot'],
            'completed_at':datetime.now(timezone.utc).isoformat(),'user_operation':'not-recorded'}
    if present(root/RESULT):last_result(root)
    atomic_json(root/RESULT,result)
    (root/PENDING).unlink();sync_directory((root/PENDING).parent)
    return result


def last_result(root=Path('/')):
    value=read_journal(Path(root)/RESULT)
    if not isinstance(value,dict) or set(value)!={'schema_version','transaction_id','state','snapshot','completed_at','user_operation'} or value['schema_version']!=1 or value['state'] not in ('upgraded-service-verified','previous-version-restored') or value['user_operation']!='not-recorded':raise ValueError('Unknown upgrade result')
    timestamp(value['completed_at'])
    return value


def rollback(root,journal,backend):
    backend.restore_original(journal)
    backend.verify(journal,original=True)
    journal['phase']='rolled-back';save(root,journal)
    return finish(root,journal,backend)


def apply(plan,backend,*,root=Path('/')):
    validate_plan(plan);root=Path(root)
    if present(root/PENDING) or present(root/'etc/rdc-restore-pending.json'):raise ValueError('Complete the pending maintenance transaction first')
    directory(root/JOURNALS.parent);directory(root/JOURNALS)
    (root/PENDING).parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    if (root/PENDING).parent.is_symlink():raise ValueError('Linked maintenance marker parent')
    journal={'schema_version':1,'id':uuid.uuid4().hex,'phase':'preparing','started_at':datetime.now(timezone.utc).isoformat(),'snapshot':None,**json.loads(json.dumps(plan))}
    save(root,journal);atomic_json(root/PENDING,{'schema_version':1,'transaction_id':journal['id']})
    try:
        backend.prepare(journal);backend.quiesce(journal)
        journal['snapshot']=backend.snapshot(journal);validate_snapshot(journal['snapshot'],started_at=journal['started_at'])
        journal['phase']='migrating';save(root,journal)
        backend.stage(journal);backend.isolate(journal);backend.migrate(journal);backend.verify(journal)
        journal['phase']='committed';save(root,journal)
        return finish(root,journal,backend)
    except Exception:
        if journal['phase']=='committed':
            backend.freeze(journal);raise UpgradeError(None,committed=True) from None
        recovered=False
        try:rollback(root,journal,backend);recovered=True
        except Exception:backend.freeze(journal)
        raise UpgradeError(recovered) from None
    except BaseException:
        backend.freeze(journal);raise


def recover(backend,*,root=Path('/')):
    root=Path(root);journal=pending(root)
    if present(root/'etc/rdc-restore-pending.json'):raise ValueError('An unrelated restore must be reviewed before upgrade recovery')
    try:
        backend.prepare(journal)
        if journal['phase'] in ('committed','rolled-back'):
            backend.isolate(journal);backend.verify(journal,original=journal['phase']=='rolled-back')
            return finish(root,journal,backend)
        return rollback(root,journal,backend)
    except BaseException:
        backend.freeze(journal);raise

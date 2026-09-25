"""Local service-restore evidence, separate from user-operation and offsite proof."""
from datetime import datetime,timezone
from pathlib import Path
import re
from backup_contracts import binary_paths
from backup_scope import validate as validate_scope
from backup_snapshot import component_hashes
from regional_workspace import private_read
from gateway_store import decode

PATH=Path('var/lib/rdc-backup/restore-result.json')
FIELDS={'schema_version','transaction_id','ownership','snapshot_id','captured_at','completed_at','binary_sha256','service_verification','user_operation'}


def timestamp(value):
    if not isinstance(value,str):raise ValueError('Invalid restore evidence time')
    result=datetime.fromisoformat(value)
    if result.tzinfo is None:raise ValueError('Restore evidence requires UTC-aware times')
    return result


def validate_source(source):
    if not isinstance(source,dict) or set(source)!={'captured_at','snapshot_id'} or (source['snapshot_id'] is not None and (not isinstance(source['snapshot_id'],str) or not re.fullmatch('[a-f0-9]{64}',source['snapshot_id']))):
        raise ValueError('Invalid restore source evidence')
    timestamp(source['captured_at'])


def validate(data):
    if not isinstance(data,dict) or set(data)!=FIELDS or type(data['schema_version']) is not int or data['schema_version']!=1:
        raise ValueError('Unknown restore evidence record')
    if not isinstance(data['transaction_id'],str) or not re.fullmatch('[a-f0-9]{32}',data['transaction_id']) or data['service_verification']!='verified' or data['user_operation']!='not-recorded':
        raise ValueError('Unsupported restore evidence claim')
    validate_scope(data['ownership'])
    validate_source({key:data[key] for key in ('captured_at','snapshot_id')})
    if timestamp(data['completed_at'])<timestamp(data['captured_at']):raise ValueError('Restore evidence clock order is invalid')
    hashes=data['binary_sha256']
    if not isinstance(hashes,dict) or set(hashes)!=set(binary_paths(data['ownership'])) or any(not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) for value in hashes.values()):
        raise ValueError('Restore evidence has no compatible component identity')
    return data


def record(root,journal):
    """Called after release/cleanup and immediately before clearing pending.

    The remaining pending marker takes precedence until this write succeeds.
    Legacy journals lack source capture evidence and never manufacture it.
    """
    if journal['phase']!='committed' or 'source' not in journal:return
    validate_source(journal['source']);path=Path(root)/PATH
    data={'schema_version':1,'transaction_id':journal['id'],'ownership':journal['ownership'],**journal['source'],
          'completed_at':datetime.now(timezone.utc).isoformat(),'binary_sha256':journal['binary_sha256'],
          'service_verification':'verified','user_operation':'not-recorded'}
    validate(data)
    if path.exists() or path.is_symlink():validate(decode(private_read(path)))
    from restore_transaction import atomic_json
    atomic_json(path,data)


def latest(root,owner,*,now=None):
    root=Path(root);pending=root/'etc/rdc-restore-pending.json'
    if pending.exists() or pending.is_symlink():return {'state':'restore-pending','user_operation':'not-recorded','next_step':'Complete backup restore-recover before relying on historical evidence.'}
    path=root/PATH
    if not (path.exists() or path.is_symlink()):return {'state':'untested','user_operation':'not-recorded','next_step':'Perform a fenced restore and test a real user operation.'}
    data=validate(decode(private_read(path)))
    if data['ownership']!=owner:return {'state':'different-scope','user_operation':'not-recorded','next_step':'Test recovery of the currently installed package and identity.'}
    current=now or datetime.now(timezone.utc)
    if current.tzinfo is None or timestamp(data['completed_at'])>current:raise ValueError('Cannot establish restore evidence age; inspect the clock')
    same=component_hashes(root,owner)==data['binary_sha256']
    return {'state':'service-verified' if same else 'verified-on-prior-components',
            'completed_at':data['completed_at'],'captured_at':data['captured_at'],'snapshot_id':data['snapshot_id'],
            'user_operation':'not-recorded','next_step':'Test application login and a real chat/file operation; service verification does not prove user data usability.'}

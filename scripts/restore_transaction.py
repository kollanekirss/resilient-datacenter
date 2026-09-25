"""Journalled same-component restoration. Caller supplies explicit fencing approval."""
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid
from backup_contracts import resources
from backup_snapshot import component_hashes,copy_resource
from backup_operations import validate_restore

PENDING='etc/rdc-restore-pending.json'
TRANSACTIONS='var/lib/rdc-backup/transactions'

class RestoreError(ValueError):
    def __init__(self,recovered,*,committed=False):
        self.recovered=recovered;self.committed=committed
        super().__init__('Restoration needs attention. '+('The restored state was committed; do not roll it back after clients may have written data.' if committed else
                         'Previous data and service recovery '+('verified.' if recovered else 'NOT verified. Keep the replacement independently isolated and use restore-recover.')))


def atomic_json(path,data):
    fd,name=tempfile.mkstemp(prefix='.rdc-journal-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(data,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def sync_tree(path):
    entries=[path,*path.rglob('*')]
    for entry in entries:
        if entry.is_file() and not entry.is_symlink():
            fd=os.open(entry,os.O_RDONLY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
    for entry in reversed(entries):
        if entry.is_dir() and not entry.is_symlink(): sync_directory(entry)


def durable_rename(source,destination):
    os.replace(source,destination)
    sync_directory(source.parent)
    if destination.parent!=source.parent: sync_directory(destination.parent)


def restoration_paths(owner):
    # Keep this replacement's verified certificate/account and current network
    # configuration; recover persistent identities, data and authorization policy.
    return [p for p in resources(owner).paths if p not in ('etc/server-connectivity-profile.json','etc/rdc-tls','etc/letsencrypt')]


def plan(stage,owner,*,root=Path('/')):
    root=Path(root);metadata=validate_restore(stage,owner)
    if json.loads((root/'etc/server-connectivity-profile.json').read_text())!=owner: raise ValueError('Replacement ownership differs from snapshot')
    if component_hashes(root,owner)!=metadata['binary_sha256']: raise ValueError('Restoration requires the exact snapshot component binaries')
    pending=root/PENDING
    if pending.exists() or pending.is_symlink(): raise ValueError('Recover the pending restore transaction before starting another')
    if (root/'etc/rdc-restore-isolation.json').exists(): raise ValueError('Previous restore isolation requires recovery before another transaction')
    paths=restoration_paths(owner)
    needed={}
    for name in paths:
        path=root/name
        if not path.exists() or path.is_symlink() or path.is_mount(): raise ValueError('Restore supports existing owned directories, not missing, linked or mounted resource roots')
        device=path.parent.stat().st_dev
        size=sum(p.stat().st_size for p in (Path(stage)/'data'/name).rglob('*') if p.is_file() and not p.is_symlink())
        previous=needed.get(device,(path.parent,0));needed[device]=(previous[0],previous[1]+size)
        for parent in path.parents:
            if parent==root: break
            if parent.is_symlink(): raise ValueError('Linked restore parents are unsupported')
    for parent,size in needed.values():
        if shutil.disk_usage(parent).free<size*1.1+64*1024*1024: raise ValueError('Insufficient space for the restore candidate and retained previous data')
    return {'ownership':owner,'captured_at':metadata['captured_at'],'binary_sha256':metadata['binary_sha256'],'paths':paths,
            'preserve':'Current HTTPS certificates, ACME account, service configuration and relay routing are retained.',
            'fencing':'Operator must independently fence the previous instance before promotion.'}


def retain_current_settings(root,name,candidate,owner):
    if name=='etc/headscale':
        keep=['config.yaml','derp-map.yml']
        if owner.get('tls_mode')!='managed-acme': keep+=['tls.crt','tls.key']
    elif name=='etc/sc-derp' and owner.get('tls_mode')!='managed-acme':
        keep=[p.name for p in (root/name).iterdir() if p.suffix in ('.crt','.key')]
        if not keep: raise ValueError('The replacement relay has no supplied TLS material')
    else: keep=[]
    for item in keep:
        source=root/name/item
        if source.is_symlink() or not source.is_file(): raise ValueError('Current service settings cannot be safely retained')
        destination=candidate/item
        if destination.is_symlink(): destination.unlink()
        shutil.copy2(source,destination)


def set_permissions(path,name,owner):
    import pwd,grp
    group={'controller':'headscale','relay':'sc-derp','peer':'root'}[owner['role']]
    persistent=name.startswith('var/lib/')
    user=group if persistent else 'root'
    uid=pwd.getpwnam(user).pw_uid;gid=grp.getgrnam(group).gr_gid
    for entry in [path,*path.rglob('*')]:
        os.chown(entry,uid,gid,follow_symlinks=False)
        if not entry.is_symlink(): entry.chmod((0o700 if persistent else 0o750) if entry.is_dir() else (0o600 if persistent else 0o640))


def workspace(root,name,identifier,index):
    return (root/name).parent/('.rdc-restore-'+identifier+'-'+str(index))


def remove(path):
    if path.is_symlink() or path.is_file(): path.unlink()
    elif path.exists(): shutil.rmtree(path)


def read_journal(path):
    import stat
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>65536:
        raise ValueError('Unsafe restore journal')
    return json.loads(path.read_text())


def save(root,journal):
    atomic_json(root/TRANSACTIONS/(journal['id']+'.json'),journal)


def clean_workspaces(root,journal):
    for index,name in enumerate(journal['paths']):
        temporary=workspace(root,name,journal['id'],index)
        if temporary.is_symlink(): raise ValueError('Unsafe restore workspace')
        if temporary.exists(): shutil.rmtree(temporary)


def finish(root,journal,runtime):
    # Once committed, no automatic rollback is permitted: clients may gain
    # access during this boundary and write data before an interruption.
    runtime.finish_validation()
    runtime.release()
    clean_workspaces(root,journal)
    (root/PENDING).unlink(missing_ok=True)


def rollback(root,journal,runtime):
    for service in resources(journal['ownership']).services: runtime.stop(service)
    for index,name in reversed(list(enumerate(journal['paths']))):
        temporary=workspace(root,name,journal['id'],index)
        if temporary.is_symlink(): raise ValueError('Unsafe restore workspace')
        old=temporary/'old';target=root/name
        if old.exists():
            remove(target);durable_rename(old,target)
    if component_hashes(root,journal['ownership'])!=journal['binary_sha256']:
        raise ValueError('Components changed during restoration; previous data is retained but service restart is blocked')
    runtime.allow_validation()
    for service,active in journal['original_active'].items():
        if active: runtime.start(service)
    if any(journal['original_active'].values()): runtime.verify(journal['ownership'])
    journal['phase']='rolled-back';save(root,journal)
    finish(root,journal,runtime)


def apply(stage,owner,*,root=Path('/'),runtime=None,permissions=set_permissions):
    if runtime is None:
        from restore_runtime import Runtime
        runtime=Runtime(owner)
    root=Path(root);stage=Path(stage);review=plan(stage,owner,root=root)
    services=resources(owner).services
    original={name:runtime.is_active(name) for name in services}
    directory=root/TRANSACTIONS;directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077: raise ValueError('Unsafe restore journal directory')
    runtime_state=runtime.prepare(owner) if hasattr(runtime,'prepare') else {}
    journal={'schema_version':1,'id':uuid.uuid4().hex,'ownership':owner,'paths':review['paths'],
             'binary_sha256':review['binary_sha256'],'original_active':original,'phase':'preparing','runtime_state':runtime_state}
    try:
        save(root,journal);atomic_json(root/PENDING,{'schema_version':1,'transaction_id':journal['id']})
    except BaseException:
        runtime.release()
        raise
    isolated=False
    try:
        runtime.isolate(owner);isolated=True
        for index,name in enumerate(journal['paths']):
            temporary=workspace(root,name,journal['id'],index);temporary.mkdir(mode=0o700)
            copy_resource(stage/'data'/name,temporary/'new')
            retain_current_settings(root,name,temporary/'new',owner)
            permissions(temporary/'new',name,owner)
            sync_tree(temporary)
        for service in services:
            runtime.stop(service)
            if runtime.is_active(service): raise ValueError('Service did not stop before restoration')
        for index,name in enumerate(journal['paths']):
            temporary=workspace(root,name,journal['id'],index)
            durable_rename(root/name,temporary/'old');durable_rename(temporary/'new',root/name)
        journal['phase']='validating';save(root,journal)
        if component_hashes(root,owner)!=journal['binary_sha256']: raise ValueError('Components changed during restoration')
        runtime.allow_validation()
        for service in services: runtime.start(service)
        runtime.verify(owner)
        journal['phase']='committed';save(root,journal)
        finish(root,journal,runtime)
        return {'state':'restored-service-verified','captured_at':review['captured_at'],'user_operation_test':'not-run'}
    except Exception:
        if journal['phase']=='committed': raise RestoreError(None,committed=True) from None
        recovered=False
        try:
            if isolated: rollback(root,journal,runtime);recovered=True
        except Exception: runtime.finish_validation()
        raise RestoreError(recovered) from None
    except BaseException:
        runtime.finish_validation()
        raise


def recover(owner,*,root=Path('/'),runtime=None):
    if runtime is None:
        from restore_runtime import Runtime
        runtime=Runtime(owner)
    root=Path(root)
    marker=read_journal(root/PENDING)
    if not isinstance(marker,dict) or set(marker)!={'schema_version','transaction_id'} or marker['schema_version']!=1 or not re.fullmatch('[a-f0-9]{32}',str(marker['transaction_id'])):
        raise ValueError('Invalid restore recovery marker')
    journal=read_journal(root/TRANSACTIONS/(marker['transaction_id']+'.json'))
    if (not isinstance(journal,dict) or set(journal)!={'schema_version','id','ownership','paths','binary_sha256','original_active','phase','runtime_state'} or
        journal['schema_version']!=1 or journal['id']!=marker['transaction_id'] or journal['ownership']!=owner or journal['paths']!=restoration_paths(owner) or
        journal['phase'] not in ('preparing','validating','committed','rolled-back') or
        not isinstance(journal['original_active'],dict) or set(journal['original_active'])!=set(resources(owner).services) or
        any(type(v) is not bool for v in journal['original_active'].values()) or component_hashes(root,owner)!=journal['binary_sha256']):
        raise ValueError('Recovery journal does not match this owned installation')
    if hasattr(runtime,'prepare'): runtime.prepare(owner,state=journal['runtime_state'])
    runtime.isolate(owner)
    runtime.finish_validation()
    if journal['phase']=='rolled-back':
        runtime.allow_validation()
        for name,active in journal['original_active'].items():
            if active: runtime.start(name)
        if any(journal['original_active'].values()): runtime.verify(owner)
        finish(root,journal,runtime)
        return {'state':'previous-data-restored'}
    if journal['phase']=='committed':
        runtime.allow_validation()
        for name in resources(owner).services: runtime.start(name)
        runtime.verify(owner);finish(root,journal,runtime)
        return {'state':'restored-service-verified','user_operation_test':'not-run'}
    rollback(root,journal,runtime)
    return {'state':'previous-data-restored'}

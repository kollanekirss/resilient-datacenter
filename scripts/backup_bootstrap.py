"""Derive a strictly network-only recovery stage from an owned application snapshot."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from backup_contracts import resources,binary_paths
from backup_scope import network_owner,package,verify_installed
from backup_snapshot import copy_resource,component_hashes,inspect_resources
from backup_operations import validate_restore
from gateway_store import decode
from regional_workspace import private_read,private_write


APPLICATION_DIRECTORIES=('etc/rdc-services','etc/rdc-nextcloud','etc/rdc-gateway',
                         'var/lib/rdc-services','var/lib/rdc-nextcloud','var/lib/rdc-gateway-recovery')


def fresh_peer(root,owner):
    if not isinstance(owner,dict) or owner.get('role')!='peer' or 'applications' in owner:
        raise ValueError('Network bootstrap requires a fresh peer with network-only backup scope')
    root=Path(root);verify_installed(root,owner)
    if any((root/name).exists() or (root/name).is_symlink() for name in APPLICATION_DIRECTORIES):
        raise ValueError('Restore the network identity before installing any application or gateway')
    pending=root/'etc/rdc-restore-pending.json'
    if pending.exists() or pending.is_symlink():raise ValueError('Recover the pending transaction before preparing a replacement identity')


def source_metadata(source,owner,expected_package,root):
    fresh_peer(root,owner)
    if expected_package not in ('matrix','nextcloud','gateway'):raise ValueError('Choose a supported recovery package')
    data=decode(private_read(Path(source)/'snapshot.json'))
    full=data.get('ownership') if isinstance(data,dict) else None
    if not isinstance(full,dict) or 'applications' not in full or network_owner(full)!=owner or package(full['applications'])!=expected_package:
        raise ValueError('Application snapshot differs from this replacement identity or selected package')
    metadata=validate_restore(source,full)
    hashes={name:metadata['binary_sha256'][name] for name in binary_paths(owner)}
    if hashes!=component_hashes(root,owner):raise ValueError('Install the exact recorded network components before recovering their identity')
    inspect_resources(Path(source)/'data',resources(owner).paths)
    return metadata


def narrow_metadata(metadata,owner):
    catalogue=resources(owner)
    return {'schema_version':1,'ownership':owner,'captured_at':metadata['captured_at'],
            'binary_sha256':{name:metadata['binary_sha256'][name] for name in binary_paths(owner)},
            'paths':list(catalogue.paths),'services_originally_active':{name:metadata['services_originally_active'][name] for name in catalogue.services}}


def tree_digest(root,owner):
    """Bind every derived byte/link to the already validated full source."""
    digest=hashlib.sha256();root=Path(root)
    for name in resources(owner).paths:
        base=root/name
        entries=[base,*sorted(base.rglob('*'))] if base.is_dir() else [base]
        for entry in entries:
            info=entry.lstat();relative=str(entry.relative_to(root))
            if stat.S_ISLNK(info.st_mode):kind='link';value=str(entry.readlink()).encode()
            elif stat.S_ISDIR(info.st_mode):kind='directory';value=b''
            else:
                kind='file'
                with entry.open('rb') as stream:value=hashlib.file_digest(stream,'sha256').digest()
            digest.update(json.dumps([relative,kind,len(value)],separators=(',',':')).encode());digest.update(value)
    return digest.hexdigest()


def derive(source,destination,owner,expected_package,*,root=Path('/')):
    source=Path(source);destination=Path(destination)
    metadata=source_metadata(source,owner,expected_package,root)
    if destination.exists() or destination.is_symlink():raise ValueError('Network recovery stage already exists; it will not be replaced')
    destination.mkdir(mode=0o700)
    try:
        for name in resources(owner).paths:copy_resource(source/'data'/name,destination/'data'/name)
        private_write(destination/'snapshot.json',json.dumps(narrow_metadata(metadata,owner)).encode())
        verify(source,destination,owner,expected_package,root=root)
    except BaseException:
        shutil.rmtree(destination);raise
    return {'state':'network-recovery-staged','package':expected_package,'captured_at':metadata['captured_at'],
            'network_identity':'not-promoted','application_data':'retained in the full source; not installed'}


def verify(source,destination,owner,expected_package,*,root=Path('/')):
    metadata=source_metadata(source,owner,expected_package,root)
    derived=validate_restore(destination,owner)
    if derived!=narrow_metadata(metadata,owner) or tree_digest(Path(source)/'data',owner)!=tree_digest(Path(destination)/'data',owner):
        raise ValueError('Derived network stage differs from the selected full snapshot')
    return metadata


def private_directory(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Use an owned private recovery staging directory')


def workspace(identifier,*,create=False):
    from backup_transport import SNAPSHOT
    from backup_operations import WORK
    if not isinstance(identifier,str) or not SNAPSHOT.fullmatch(identifier):raise ValueError('Select one complete snapshot ID')
    for path in (WORK,WORK/'bootstrap'):
        if create:path.mkdir(mode=0o700,exist_ok=True)
        private_directory(path)
    result=WORK/'bootstrap'/identifier
    if create:
        if result.exists() or result.is_symlink():raise ValueError('Bootstrap stage already exists; review it instead of replacing it')
        result.mkdir(mode=0o700)
    private_directory(result)
    return result


def stage(identifier,expected_package):
    from backup_operations import configured
    data,transport=configured();owner=data['ownership'];fresh_peer(Path('/'),owner)
    folder=workspace(identifier,create=True)
    try:
        transport.restore(identifier,folder/'source')
        result=derive(folder/'source',folder/'network',owner,expected_package)
        private_write(folder/'bootstrap.json',json.dumps({'schema_version':1,'snapshot_id':identifier,'package':expected_package,'ownership':owner,
                      'source_metadata_sha256':hashlib.sha256((folder/'source/snapshot.json').read_bytes()).hexdigest()}).encode())
    except BaseException:
        shutil.rmtree(folder);raise
    return dict(result,snapshot_id=identifier,next_step='Review bootstrap-plan, independently fence the old node, then explicitly bootstrap-apply using console access.')


def review(identifier,owner):
    from restore_transaction import plan
    folder=workspace(identifier);record=decode(private_read(folder/'bootstrap.json'))
    if not isinstance(record,dict) or set(record)!={'schema_version','snapshot_id','package','ownership','source_metadata_sha256'} or type(record['schema_version']) is not int or record['schema_version']!=1 or record['snapshot_id']!=identifier or record['ownership']!=owner or record['source_metadata_sha256']!=hashlib.sha256(private_read(folder/'source/snapshot.json')).hexdigest():
        raise ValueError('Bootstrap record differs from the selected owned source')
    verify(folder/'source',folder/'network',owner,record['package'])
    result=plan(folder/'network',owner)
    return folder,dict(result,state='network-bootstrap-plan',snapshot_id=identifier,package=record['package'],
                       warning='This replaces the temporary VPN identity. Use independent console access and fence the old instance first.',
                       next_step='After identity verification, install the same application version with its original service identity and fresh TLS, include-services, then stage and restore the original full snapshot.')


def action(args,data,*,input_fn=input):
    if args.action=='bootstrap-stage':return stage(args.snapshot,args.package)
    folder,result=review(args.snapshot,data['ownership'])
    if args.action=='bootstrap-plan':return result
    if args.action!='bootstrap-apply':raise ValueError('Unsupported network recovery bootstrap action')
    import sys
    print(json.dumps(result,indent=2))
    phrase='FENCED AND RESTORE NETWORK '+data['ownership']['node_name']
    if not sys.stdin.isatty() or input_fn('Type '+phrase+' to replace this temporary identity: ').strip()!=phrase:return {'state':'cancelled'}
    from restore_transaction import apply
    restored=apply(folder/'network',data['ownership'])
    return dict(restored,network_bootstrap='completed',application_restore='not-performed',next_step=result['next_step'])

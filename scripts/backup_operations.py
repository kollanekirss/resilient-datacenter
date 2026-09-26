"""Ownership checks and backup/restore preparation. Promotion is a separate guarded operation."""
import bz2
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
from backup_contracts import validate,resources,binary_paths,RESTIC_VERSION,RESTIC_SHA256
from backup_snapshot import capture,inspect_resources
from backup_transport import Restic
from profile_config import _identifier,_safe_values
from setup_contracts import validate_local_manifest,local_ownership
from validate_inventory import hostname

BASE=Path('/etc/rdc-backup')
BINARY=Path('/usr/local/bin/rdc-restic')
WORK=Path('/var/lib/rdc-backup')


def match_owner(profile,owner,*,expected=None):
    from backup_scope import network_owner,validate as validate_scope
    validate_scope(owner)
    owner=network_owner(owner)
    if expected is not None: expected=network_owner(expected)
    if validate(profile) or not isinstance(owner,dict) or not _safe_values(owner): raise ValueError('Invalid backup ownership')
    if owner.get('role')!=profile['role'] or owner.get('institution_id')!=profile['institution_id']:
        raise ValueError('Backup profile does not match this installed institution and role')
    if owner['role']=='portable':
        from application_access import validate_portable_owner
        validate_portable_owner(owner)
        if owner['node_name']!=profile['node_name']:raise ValueError('Portable backup node differs')
    elif owner['role']=='peer':
        manifest={'kind':'local-node','schema_version':1,'institution_id':owner.get('institution_id'),'node_name':owner.get('node_name'),
                  'headscale_hostname':owner.get('controller_hostname'),'node_tag':owner.get('node_tag')}
        if validate_local_manifest(manifest) or local_ownership(manifest)!=owner or owner['node_name']!=profile['node_name']:
            raise ValueError('Only the current local-node ownership contract is supported')
    else:
        fields={'schema_version','deployment_mode','institution_id','role','controller_hostname'}
        managed=owner.get('schema_version')==3
        if managed: fields|={'tls_mode','certificate_hostname'}
        if (set(owner)!=fields or type(owner.get('schema_version')) is not int or owner['schema_version'] not in (2,3) or
            owner['deployment_mode']!='independent' or not hostname(owner['controller_hostname']) or
            (managed and (owner['tls_mode']!='managed-acme' or not hostname(owner['certificate_hostname'])))):
            raise ValueError('Only current independent infrastructure ownership is supported')
    if expected is not None and owner!=expected: raise ValueError('Installed identity changed since backup configuration')


def validate_restore(stage,owner):
    stage=Path(stage)
    metadata=stage/'snapshot.json'
    if metadata.is_symlink() or not metadata.is_file() or metadata.stat().st_size>65536: raise ValueError('Missing or unsafe snapshot metadata')
    data=json.loads(metadata.read_text());catalogue=resources(owner)
    if (not isinstance(data,dict) or set(data)!={'schema_version','ownership','paths','captured_at','services_originally_active','binary_sha256'} or
        type(data['schema_version']) is not int or data['schema_version']!=1 or data['ownership']!=owner or data['paths']!=list(catalogue.paths) or
        not isinstance(data['services_originally_active'],dict) or set(data['services_originally_active'])!=set(catalogue.services) or
        any(type(v) is not bool for v in data['services_originally_active'].values())):
        raise ValueError('Snapshot does not match the expected identity, schema or resource catalogue')
    if not isinstance(data['binary_sha256'],dict) or set(data['binary_sha256'])!=set(binary_paths(owner)) or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in data['binary_sha256'].values()):
        raise ValueError('Snapshot has no supported component identity')
    if not isinstance(data['captured_at'],str) or datetime.fromisoformat(data['captured_at']).tzinfo is None: raise ValueError('Snapshot timestamp is invalid')
    if (stage/'data').is_symlink() or set(p.name for p in stage.iterdir())!={'data','snapshot.json'}:
        raise ValueError('Unexpected snapshot contents')
    paths=catalogue.paths
    for path in (stage/'data').rglob('*'):
        relative=path.relative_to(stage/'data').as_posix()
        if not any(relative==p or relative.startswith(p+'/') or p.startswith(relative+'/') for p in paths):
            raise ValueError('Snapshot contains data outside the managed resource catalogue')
    inspect_resources(stage/'data',paths)
    from backup_scope import verify_installed
    verify_installed(stage/'data',owner)
    if 'applications' in owner:
        from backup_scope import application_backup
        application_backup(owner['applications']).validate_data(stage/'data',owner['applications'])
    return data


def status_summary(snapshots,*,now=None):
    result={'state':'no-backup','restore_test':'not-run','offsite_location':'operator-verification-required'}
    if not snapshots: return result
    current=datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
    dated=[(datetime.fromisoformat(s['time'].replace('Z','+00:00')),s) for s in snapshots]
    if current.tzinfo is None or any(t.tzinfo is None or t>current for t,_ in dated): raise ValueError('Cannot establish backup age from the supplied timestamps')
    when,snapshot=max(dated,key=lambda pair:pair[0])
    return dict(result,state='snapshot-present',snapshot_id=snapshot['id'],captured_at=when.isoformat(),backup_age_seconds=int((current-when).total_seconds()))


def root_json(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022: raise ValueError('Unsafe administration file ownership or permissions')
    if info.st_size>65536: raise ValueError('Administration file is oversized')
    return json.loads(path.read_text())


def require_platform():
    if os.geteuid()!=0: raise ValueError('Run this action through sudo on the managed server')
    if platform.system()!='Linux' or platform.machine()!='x86_64': raise ValueError('Backup administration supports Ubuntu 24.04 amd64 only')
    os_release=Path('/etc/os-release').read_text()
    if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release or not Path('/run/systemd/system').is_dir():
        raise ValueError('Backup administration supports Ubuntu 24.04 with systemd only')


def private_write(path,content):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream: stream.write(content)


def restic_bytes(artifact=None):
    if artifact is None:
        url=f'https://github.com/restic/restic/releases/download/v{RESTIC_VERSION}/restic_{RESTIC_VERSION}_linux_amd64.bz2'
        with urllib.request.urlopen(url,timeout=60) as source:compressed=source.read(64*1024*1024+1)
    else:
        path=Path(artifact)
        if not path.is_absolute():raise ValueError('Use an absolute local Restic artifact path')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):raise ValueError('Restic artifact must be a regular file')
            compressed=source.read(64*1024*1024+1)
    if len(compressed)>64*1024*1024 or hashlib.sha256(compressed).hexdigest()!=RESTIC_SHA256:
        raise ValueError('Restic artifact failed pinned checksum verification')
    binary=bz2.decompress(compressed)
    if len(binary)>256*1024*1024 or binary[:4]!=b'\x7fELF' or binary[18:20]!=b'\x3e\x00': raise ValueError('Unexpected Restic target executable')
    return binary


def install_binary(path,*,artifact=None):
    binary=restic_bytes(artifact)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
    try:
        with os.fdopen(fd,'wb') as stream: stream.write(binary)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return hashlib.sha256(binary).hexdigest()


def recovery_material(password_file,ssh_key_file):
    if (password_file is None)!=(ssh_key_file is None): raise ValueError('Recovery requires both the saved repository password and SSH private key')
    if password_file is None: return None
    paths=[Path(password_file),Path(ssh_key_file)]
    for path in paths:
        info=path.lstat()
        if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077 or info.st_size>16384:
            raise ValueError('Recovery access files must be small, private, root-owned regular files')
    password=paths[0].read_text()
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}\n?',password): raise ValueError('Use the saved project-generated repository password')
    public=subprocess.run(['/usr/bin/ssh-keygen','-y','-P','','-f',str(paths[1])],check=True,capture_output=True,text=True,timeout=15).stdout.strip()
    from backup_contracts import valid_host_key
    if not valid_host_key(' '.join(public.split()[:2])): raise ValueError('Recovery requires the saved unencrypted Ed25519 access key')
    return password,paths[1].read_text(),public+'\n'


def configure(profile,*,password_file=None,ssh_key_file=None,restic_artifact=None):
    require_platform()
    owner=root_json(Path('/etc/server-connectivity-profile.json'));match_owner(profile,owner)
    if BASE.exists() or BASE.is_symlink() or BINARY.exists() or BINARY.is_symlink():
        raise ValueError('Existing backup installation requires review; configuration does not replace identities or secrets')
    recovered=recovery_material(password_file,ssh_key_file)
    if restic_artifact is not None:restic_bytes(restic_artifact)
    BASE.mkdir(mode=0o700)
    installed=False
    try:
        if recovered:
            for name,content in zip(('password','ssh_key','ssh_key.pub'),recovered): private_write(BASE/name,content)
        else:
            private_write(BASE/'password',secrets.token_urlsafe(32)+'\n')
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','rdc-backup-writer','-f',str(BASE/'ssh_key')],check=True,timeout=30)
            (BASE/'ssh_key').chmod(0o600)
        transport=Restic(profile)
        private_write(BASE/'known_hosts',transport.known_hosts())
        digest=install_binary(BINARY,artifact=restic_artifact) if restic_artifact is not None else install_binary(BINARY)
        installed=True
        from restore_runtime import install_guards
        install_guards(owner)
        private_write(BASE/'configuration.json',json.dumps({'schema_version':1,'profile':profile,'ownership':owner,'restic_version':RESTIC_VERSION,'binary_sha256':digest},indent=2)+'\n')
    except BaseException:
        shutil.rmtree(BASE)
        if installed: BINARY.unlink()
        raise
    print('Backup credentials prepared on this server. No repository was initialized and no backup was taken.')
    print('Authorize the public key in /etc/rdc-backup/ssh_key.pub on the backup destination.')
    print('Keep the repository password in /etc/rdc-backup/password and an emergency access method in an independent recovery store before initialization.')
    if recovered: print('Recovery access imported. Inspect backup status; do not initialize an existing repository.')
    return {'state':'configured-recovery-access' if recovered else 'configured-not-initialized'}


def configured(*,recovery=False):
    require_platform()
    data=root_json(BASE/'configuration.json')
    if set(data)!={'schema_version','profile','ownership','restic_version','binary_sha256'} or data['schema_version']!=1 or data['restic_version']!=RESTIC_VERSION:
        raise ValueError('Unknown backup installation contract')
    owner=root_json(Path('/etc/server-connectivity-profile.json'))
    match_owner(data['profile'],owner,expected=data['ownership'])
    from backup_scope import verify_installed,tag
    # A journalled interruption may leave an application directory between its
    # two renames. Recovery validates the complete journal and component hashes
    # before restoring that directory; ordinary operations still require it.
    if not recovery:verify_installed(Path('/'),data['ownership'])
    with BINARY.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=data['binary_sha256']: raise ValueError('Installed backup tool differs from the verified version')
    transport=Restic(data['profile'],scope=tag(data['ownership']));transport.check_credentials()
    return data,transport


def backup_now():
    data,transport=configured()
    from backup_scope import installed_application
    if installed_application() is not None and 'applications' not in data['ownership']:
        raise ValueError('An application is installed but backup scope covers only networking. Review backup include-services before taking another snapshot.')
    WORK.mkdir(mode=0o700,exist_ok=True)
    if WORK.is_symlink() or WORK.stat().st_uid!=0 or WORK.stat().st_mode & 0o077: raise ValueError('Unsafe local backup workspace')
    with tempfile.TemporaryDirectory(prefix='snapshot-',dir=WORK) as temporary:
        stage=Path(temporary)/'snapshot'
        capture(Path('/'),stage,data['ownership'])
        transport.wait_ready()
        identifier=transport.backup(stage)
    return {'state':'snapshot-created','snapshot_id':identifier,'restore_test':'not-run'}


def stage_restore(identifier):
    from backup_snapshot import component_hashes
    from backup_transport import SNAPSHOT
    data,transport=configured()
    if not isinstance(identifier,str) or not SNAPSHOT.fullmatch(identifier): raise ValueError('Supply a complete snapshot ID')
    WORK.mkdir(mode=0o700,exist_ok=True)
    if WORK.is_symlink() or WORK.stat().st_uid!=0 or WORK.stat().st_mode & 0o077: raise ValueError('Unsafe restore workspace')
    parent=WORK/'restores';parent.mkdir(mode=0o700,exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid!=0 or parent.stat().st_mode & 0o077: raise ValueError('Unsafe restore workspace')
    stage=parent/identifier
    transport.restore(identifier,stage)
    try:
        metadata=validate_restore(stage,data['ownership'])
        if metadata['binary_sha256']!=component_hashes(Path('/'),data['ownership']):
            raise ValueError('Installed component bytes differ from the snapshot; restore compatibility has not been established')
    except BaseException:
        shutil.rmtree(stage)
        raise
    return {'state':'restore-staged','snapshot_id':identifier,'captured_at':metadata['captured_at'],
            'directory':str(stage),'restore_test':'not-run','promotion':'not-performed'}


def action(args):
    import fcntl
    import sys
    from profile_config import load_profile
    if args.action=='setup':
        from backup_setup import wizard
        return wizard(args.output_file)
    if args.action=='target':
        from backup_target import prepare,authorize
        return prepare(load_profile(str(args.manifest))) if args.target_action=='prepare' else authorize(args.public_key)
    upgrade=Path('/etc/rdc-upgrade-pending.json')
    if upgrade.exists() or upgrade.is_symlink():raise ValueError('Run upgrade recover before ordinary backup operations')
    if args.action=='configure':
        options={'restic_artifact':args.restic_artifact} if getattr(args,'restic_artifact',None) is not None else {}
        return configure(load_profile(str(args.profile)),password_file=args.recovery_password_file,ssh_key_file=args.recovery_ssh_key_file,**options)
    data,transport=configured(recovery=True) if args.action=='restore-recover' else configured()
    if args.action=='status' or (args.action=='schedule' and args.schedule_action=='status'):
        from backup_schedule import status as schedule_status
        try: summary=status_summary(transport.snapshots())
        except (ValueError,OSError,subprocess.SubprocessError):
            summary={'state':'backup-unreachable','restore_test':'not-run','next_step':'Check backup storage reachability, credentials and pinned host key.'}
        summary['schedule']=schedule_status(summary.get('backup_age_seconds'))
        if summary['state']=='snapshot-present' and summary['schedule'].get('overdue'): summary['state']='backup-overdue'
        from backup_scope import tag,installed_application
        summary['scope']=tag(data['ownership'])+'-and-network' if 'applications' in data['ownership'] else 'network-only'
        if installed_application() is not None and 'applications' not in data['ownership']:
            summary['state']='application-backup-missing';summary['next_step']='Review backup include-services, then take and test an application backup.'
        return summary
    if args.action=='schedule' and args.schedule_action=='disable':
        from backup_schedule import disable
        return disable()
    fd=os.open(BASE/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action in ('bootstrap-stage','bootstrap-plan','bootstrap-apply'):
            from backup_bootstrap import action as bootstrap_action
            return bootstrap_action(args,data,input_fn=input)
        if args.action=='include-services':
            from backup_scope import installed_application,application_backup,package
            application=installed_application()
            if application is None:raise ValueError('Install and verify the application before extending backup scope')
            include_services=application_backup(application).include_services
            print('Include '+package(application)+' accounts, application data, identity and database secrets in future encrypted backups. Preserve repository credentials and history; update the protected backup runtime if scheduled.')
            phrase='INCLUDE SERVICES '+data['profile']['node_name']
            if not sys.stdin.isatty() or input('Type '+phrase+' to proceed: ').strip()!=phrase:return {'state':'cancelled'}
            return include_services()
        if args.action=='schedule' and args.schedule_action=='enable':
            from backup_schedule import enable
            return enable(args.frequency)
        if args.action=='initialize':
            if not sys.stdin.isatty(): raise ValueError('Repository initialization requires interactive confirmation of independent recovery access')
            print('Keep the repository password and emergency storage access independently of this server. Confirm the destination is in a separate failure domain.')
            if input('Type RECOVERY ACCESS SAVED to initialize the encrypted repository: ').strip()!='RECOVERY ACCESS SAVED':
                raise ValueError('Initialization cancelled; no completed backup is claimed')
            transport.initialize();return {'state':'repository-initialized-no-backup'}
        if args.action=='run':
            print('Taking a consistent snapshot briefly pauses the owned service. It is restarted before encrypted upload.')
            return backup_now()
        if args.action=='restore-stage': return stage_restore(args.snapshot)
        if args.action=='restore-recover':
            from restore_transaction import recover
            return recover(data['ownership'])
        if args.action in ('restore-plan','restore-apply'):
            from backup_transport import SNAPSHOT
            from restore_transaction import plan,apply
            if not SNAPSHOT.fullmatch(args.snapshot): raise ValueError('Supply a complete snapshot ID')
            stage=WORK/'restores'/args.snapshot
            for path in (WORK,WORK/'restores',stage):
                info=path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077: raise ValueError('Unsafe restore staging directory')
            review=plan(stage,data['ownership'])
            if args.action=='restore-plan': return dict(review,state='restore-plan-no-changes')
            print(json.dumps(review,indent=2))
            print('This replaces local service data with the selected snapshot. Later changes will be lost. Shut down or independently isolate the OLD instance first; failed reachability is not proof of fencing.')
            phrase='FENCED AND REPLACE '+data['profile']['node_name']
            if not sys.stdin.isatty() or input('Type '+phrase+' to proceed: ').strip()!=phrase: return {'state':'cancelled'}
            try: return apply(stage,data['ownership'])
            except KeyboardInterrupt:
                raise ValueError('Restore interrupted. Inspect the pending transaction and run backup restore-recover; automatic service startup remains guarded.') from None
    raise ValueError('Unsupported backup action')

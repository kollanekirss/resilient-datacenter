"""Fixed owned gateway snapshot package; archived issuer data is never executed."""
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
from contextlib import contextmanager
from regional_workspace import private_read,private_write
from gateway_store import Store,decode
import gateway_contracts
from service_contracts import network_manifest

ARCHIVE=Path('/var/lib/rdc-gateway-recovery')
REQUIRED={'initialization.json','initialized.json','profile.json','identity.json','state.json','ownership.json','clock.json','tls'}
OPTIONAL={'operation.lock','clock.lock','envoy.json','candidate.json','certificate-status.json','recovery-required.json'}


def ownership(profile,identity,network):
    network_manifest(network)
    if gateway_contracts.validate(profile,identity):raise ValueError('Invalid gateway backup identity/profile')
    if any(profile[key]!=network[key] for key in ('institution_id','node_name')) or profile['regional_controller']!=network['controller_hostname']:
        raise ValueError('Gateway backup network differs from its signed installation')
    return {'schema_version':1,'role':'gateway','packages':['gateway'],'profile':profile,'identity':identity,'network':network}


def validate_owner(application):
    if not isinstance(application,dict) or set(application)!={'schema_version','role','packages','profile','identity','network'}:
        raise ValueError('Unknown gateway backup ownership')
    if type(application['schema_version']) is not int or application!=ownership(application['profile'],application['identity'],application['network']):raise ValueError('Gateway backup ownership differs')
    return application


def private_directory(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Use an owned private gateway recovery directory')


def initialize_archive(path,application):
    validate_owner(application);path=Path(path)
    if not (path.exists() or path.is_symlink()):path.mkdir(mode=0o700)
    private_directory(path)
    if (path/'manifest.json').exists():
        current=decode(private_read(path/'manifest.json'))
        if not isinstance(current,dict) or set(current)!={'schema_version','ownership','issuer_snapshot'} or type(current['schema_version']) is not int or current['schema_version']!=1 or type(current['issuer_snapshot']) is not bool or current['ownership']!=application:raise ValueError('Recovery archive belongs to another gateway')
    else:
        if list(path.iterdir()):raise ValueError('Unowned files exist in the recovery archive')
        private_write(path/'manifest.json',json.dumps({'schema_version':1,'ownership':application,'issuer_snapshot':False}).encode())


def validate_archive(path,application):
    from service_issuer_contracts import validate,credential_text,validate_renewal,name_fields
    from regional_agreements import fingerprint
    private_directory(path);metadata=decode(private_read(path/'manifest.json'))
    if not isinstance(metadata,dict) or set(metadata)!={'schema_version','ownership','issuer_snapshot'} or type(metadata['schema_version']) is not int or metadata['schema_version']!=1 or metadata['ownership']!=application or type(metadata['issuer_snapshot']) is not bool:
        raise ValueError('Invalid gateway recovery archive')
    expected={'manifest.json','issuer'} if metadata['issuer_snapshot'] else {'manifest.json'}
    if set(p.name for p in path.iterdir())!=expected:raise ValueError('Incomplete or unknown gateway recovery archive files')
    if not metadata['issuer_snapshot']:return metadata
    issuer=path/'issuer';private_directory(issuer)
    if set(p.name for p in issuer.iterdir())!={'configuration.json','cloudflare.ini','cli.ini','certbot'}:raise ValueError('Unknown archived issuer resources')
    data=decode(private_read(issuer/'configuration.json'))
    if not isinstance(data,dict) or set(data)!={'schema_version','profile','network'} or data['schema_version']!=1 or data['network']!=application['network'] or validate(data['profile']):raise ValueError('Archived issuer ownership differs')
    profile=data['profile'];own=application['identity']['payload']
    if profile['kind']!='gateway-certificates' or profile['gateway_fingerprint']!=fingerprint(application['identity']) or profile['institution_id']!=own['institution_id'] or profile['node_name']!=own['gateway_node'] or {k:profile[k] for k in name_fields(profile)}!={name+'_hostname':domain for name,domain in own['services'].items()}:
        raise ValueError('Archived issuer differs from the pinned gateway')
    text=private_read(issuer/'cloudflare.ini').decode();prefix='dns_cloudflare_api_token = '
    if not text.startswith(prefix) or credential_text(text[len(prefix):].rstrip('\n'))!=text:raise ValueError('Invalid archived provider credential format')
    if private_read(issuer/'cli.ini')!=b'':raise ValueError('Archived issuer contains unreviewed configuration')
    # Standard Certbot live links may point only within this archived account.
    from backup_snapshot import inspect_resources
    inspect_resources(path,('issuer',))
    for entry in issuer.rglob('*'):
        if entry.is_symlink() and entry.readlink().is_absolute():raise ValueError('Absolute archived issuer link')
    validate_renewal((issuer/'certbot/renewal/rdc-services.conf').read_text())
    entries=list(issuer.rglob('*'))
    if len(entries)>512 or sum(p.stat().st_size for p in entries if p.is_file() and not p.is_symlink())>8*1024*1024:raise ValueError('Oversized archived issuer account')
    return metadata


def refresh_archive(path,application,source=Path('/etc/rdc-service-acme')):
    """Refresh a derived private cache only after validating a separate candidate.

    The caller holds the backup and gateway locks. No archived configuration is
    installed into an executable issuer location or into the proxy's mount.
    """
    path=Path(path);source=Path(source)
    initialize_archive(path,application)
    if not (source.exists() or source.is_symlink()):
        return validate_archive(path,application)
    if not {p.name for p in path.iterdir()}<={'manifest.json','issuer'}:
        raise ValueError('Unknown gateway recovery cache resources')
    if (path/'issuer').exists() or (path/'issuer').is_symlink():private_directory(path/'issuer')
    private_directory(source)
    from backup_snapshot import inspect_resources
    size=inspect_resources(source,('certbot',))
    entries=list((source/'certbot').rglob('*'))
    if len(entries)>508 or size>8*1024*1024:raise ValueError('Oversized issuer account')
    # Absolute links would retain their live target after copying; Certbot's
    # normal live/archive links are relative and remain within this account.
    for entry in entries:
        if entry.is_symlink() and entry.readlink().is_absolute():raise ValueError('Absolute issuer links cannot be archived')
    inputs={name:private_read(source/name) for name in ('configuration.json','cloudflare.ini','cli.ini')}
    with tempfile.TemporaryDirectory(prefix='.gateway-recovery-',dir=path.parent) as temporary:
        candidate=Path(temporary);initialize_archive(candidate,application)
        issuer=candidate/'issuer';issuer.mkdir(mode=0o700)
        for name,raw in inputs.items():private_write(issuer/name,raw)
        shutil.copytree(source/'certbot',issuer/'certbot',symlinks=True)
        metadata={'schema_version':1,'ownership':application,'issuer_snapshot':True}
        private_write(candidate/'manifest.json',json.dumps(metadata).encode(),replace=True)
        validate_archive(candidate,application)
        # This directory is only a derived cache. An interruption cannot make a
        # valid snapshot; a later refresh can rebuild it from the live issuer.
        if (path/'issuer').exists():shutil.rmtree(path/'issuer')
        issuer.rename(path/'issuer')
        private_write(path/'manifest.json',json.dumps(metadata).encode(),replace=True)
    return validate_archive(path,application)


@contextmanager
def capture_context(root,application):
    """The outer caller already owns the global backup operation lock."""
    root=Path(root);store=Store(root/'etc/rdc-gateway')
    with store.lock(wait_seconds=10):
        from gateway_certificates import pending
        if store.pending() or pending(store) or store.recovery_pending():
            raise ValueError('Complete pending gateway policy, certificates and recovery review before backup')
        refresh_archive(root/'var/lib/rdc-gateway-recovery',application,root/'etc/rdc-service-acme')
        validate_data(root,application)
        yield


def include_services():
    """Extend the existing encrypted scope while its outer lock is held."""
    from backup_operations import configured,BASE
    from backup_scope import include,network_owner
    from backup_schedule import owned_schedule,refresh_runtime,private_json
    from restore_runtime import install_guards
    import gateway_backup_runtime as runtime
    data,_=configured();settings=runtime.read_settings();application=settings['ownership']
    owner=include(network_owner(data['ownership']),application)
    if 'applications' in data['ownership'] and data['ownership']!=owner:raise ValueError('Gateway backup migration requires review')
    pending=Path('/etc/rdc-restore-pending.json')
    if pending.exists() or pending.is_symlink():raise ValueError('Complete pending restore before changing backup scope')
    with capture_context(Path('/'),application):
        runtime.ready('gateway',settings)
        install_guards(owner)
        if (BASE/'schedule.json').exists():
            owned_schedule(check_runtime=False);refresh_runtime(Path(__file__).resolve().parent)
        private_json(BASE/'configuration.json',dict(data,ownership=owner))
    return {'state':'application-backup-scope-configured','packages':['gateway'],'credentials':'preserved','snapshot_history':'preserved',
            'restore_test':'not-run','next_step':'Run a new backup and a fenced recovery exercise; older network-only snapshots do not protect partner policy.'}


def begin_restore(root,stage,transaction_id):
    from gateway_recovery import suspend,reference
    import time
    root=Path(root);current=Store(root/'etc/rdc-gateway');saved=Store(Path(stage)/'data/etc/rdc-gateway')
    history=reference(saved)
    checkpoint=decode(private_read(saved.base/'clock.json'))['latest_utc']
    return suspend(current,transaction_id,now=max(int(time.time()),checkpoint,history['approval_floor'] if history else 0))


def prepare_candidate(root,candidate,application):
    from gateway_recovery import write_reference
    current=Store(Path(root)/'etc/rdc-gateway');saved=Store(candidate)
    if current.profile()!=application['profile'] or current.identity()!=application['identity']:raise ValueError('Replacement gateway ownership differs')
    record=current.recovery()
    if not record or not record['review_pending']:raise ValueError('Gateway restore requires persistent closed review')
    old=current.state();restored=saved.state()
    merged=dict(restored,generation=max(old['generation'],restored['generation'])+1,
                revoked_ids=sorted(set(old['revoked_ids'])|set(restored['revoked_ids'])))
    saved.validate_state(merged);saved._write('state.json',merged)
    checkpoints=[decode(private_read(store.base/'clock.json'))['latest_utc'] for store in (current,saved)]
    saved._write('clock.json',{'schema_version':1,'latest_utc':max(*checkpoints,record['approval_floor'])})
    from gateway_certificates import managed_material
    managed_material(current)
    shutil.rmtree(saved.base/'tls')
    shutil.copytree(current.base/'tls',saved.base/'tls',symlinks=True)
    for name in ('envoy.json','candidate.json','certificate-status.json'):(saved.base/name).unlink(missing_ok=True)
    write_reference(saved,record)


def restore_permissions(path,name):
    path=Path(path)
    if name not in ('etc/rdc-gateway','var/lib/rdc-gateway-recovery'):raise ValueError('Unknown gateway restore resource')
    for entry in [path,*path.rglob('*')]:
        if not (entry.is_symlink() or entry.is_file() or entry.is_dir()):raise ValueError('Unsupported gateway restore entry')
        os.chown(entry,0,0,follow_symlinks=False)
        if not entry.is_symlink():entry.chmod(0o700 if entry.is_dir() else 0o600)


def export_token(archive,application,destination):
    destination=Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():raise ValueError('Choose a new absolute token file in a private directory')
    private_directory(destination.parent)
    if not validate_archive(Path(archive),application)['issuer_snapshot']:raise ValueError('This gateway archive has no provider credential')
    raw=private_read(Path(archive)/'issuer/cloudflare.ini').decode()
    token=raw.removeprefix('dns_cloudflare_api_token = ').strip()+'\n'
    private_write(destination,token.encode())
    return {'state':'gateway-issuer-token-exported','output_file':str(destination),
            'next_step':'Review or rotate this DNS token and explicitly issue certificates on the replacement. No issuer configuration was activated.'}


def validate_data(root,application):
    validate_owner(application);root=Path(root);store=Store(root/'etc/rdc-gateway')
    entries={p.name for p in store.base.iterdir()}
    if not REQUIRED<=entries or not entries<=REQUIRED|OPTIONAL:raise ValueError('Incomplete or unreviewed gateway snapshot resources')
    if decode(private_read(store.base/'ownership.json'))!=application or store.profile()!=application['profile'] or store.identity()!=application['identity']:
        raise ValueError('Gateway snapshot identity differs')
    state=store.state()
    if decode(private_read(store.base/'initialized.json'))!={'schema_version':1} or decode(private_read(store.base/'initialization.json'))!={'profile':application['profile'],'identity':application['identity']}:raise ValueError('Gateway initialization history differs')
    clock=decode(private_read(store.base/'clock.json'))
    if not isinstance(clock,dict) or set(clock)!={'schema_version','latest_utc'} or clock['schema_version']!=1 or type(clock['latest_utc']) is not int or not 0<=clock['latest_utc']<2**53:raise ValueError('Gateway clock history is invalid')
    for name in entries-{'tls'}:
        private_read(store.base/name)
    from gateway_certificates import managed_material
    managed_material(store)
    tls=store.base/'tls'
    for entry in tls.rglob('*'):
        if entry.is_symlink() and (entry.parent!=tls or entry.name not in ('active','previous')):raise ValueError('Unsupported gateway TLS link')
        if not entry.is_symlink() and not (entry.is_file() or entry.is_dir()):raise ValueError('Unsupported gateway TLS resource')
    from certificate_lifecycle import generation
    for name in ('active','previous'):generation(tls,name)
    validate_archive(root/'var/lib/rdc-gateway-recovery',application)

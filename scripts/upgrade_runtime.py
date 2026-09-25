"""Local fixed-package upgrade runtime. Privileged methods require a managed server."""
from contextlib import ExitStack,contextmanager
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from application_catalogue import for_owner,transition
from backup_scope import application_runtime,package,network_owner
from backup_contracts import resources
from backup_operations import require_platform,root_json,configured,validate_restore,status_summary
from backup_snapshot import component_hashes,capture
from restore_transaction import atomic_json,durable_rename
from restore_runtime import Runtime as Isolation,UPGRADE_PENDING,install_guards
import upgrade_files
import upgrade_transaction as transaction

SOURCE=Path(__file__).resolve().parent
ROOT=Path('/')


def command(argv,*,input=None,timeout=60):
    result=subprocess.run(argv,input=input,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise ValueError('Application upgrade operation failed; private diagnostics were withheld')
    if len(result.stdout)>2*1024*1024:raise ValueError('Oversized upgrade response')
    return result.stdout


def source_files(selected):
    if selected=='matrix':return ('service_runtime.py','service_images.json','service_regional.py')
    if selected=='nextcloud':return ('nextcloud_runtime.py','nextcloud_cron.py','nextcloud_images.json','service_runtime.py','nextcloud_regional.py','service_regional.py','regional_http.py')
    raise ValueError('Unsupported package runtime')


def verify_helpers(runtime,owner):
    selected=package(owner['applications']);manifest=root_json(runtime.INSTALLED/'manifest.json')
    expected=source_files(selected)
    if not isinstance(manifest,dict) or set(manifest)!={'schema_version','files'} or manifest['schema_version']!=1 or set(manifest['files'])!=set(expected):raise ValueError('Unknown installed runtime manifest')
    if {p.name for p in runtime.INSTALLED.iterdir()}!=set(expected)|{'manifest.json'}:raise ValueError('Unreviewed installed helper files')
    for name in expected:
        path=runtime.INSTALLED/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe installed upgrade source')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=manifest['files'][name]:raise ValueError('Installed helper differs from its owned manifest')
        if name in ('service_images.json','nextcloud_images.json'):
            if json.loads(raw)!={'schema_version':1,'components':for_owner(owner['applications'])}:raise ValueError('Installed catalogue differs from the reviewed predecessor')
        elif raw!=(SOURCE/name).read_bytes():raise ValueError('This predecessor helper revision has no reviewed upgrade path')


def check():
    require_platform()
    if transaction.present(UPGRADE_PENDING):return {'state':'upgrade-pending','next_step':'Run upgrade recover from the same reviewed source.'}
    if transaction.present(Path('/etc/rdc-restore-pending.json')):raise ValueError('Complete restore-recover before upgrading')
    from status_probe import discover
    found=discover()
    if found is None or found['package'] not in ('matrix','nextcloud'):raise ValueError('Upgrade requires an owned chat or file-service node')
    owner=found['owner'];runtime=application_runtime(owner['applications']);settings=runtime.read_settings()
    if settings['ownership']!=owner['applications'] or settings['components']!=for_owner(owner['applications']):raise ValueError('Upgrade source identity differs')
    reviewed=transition(found['package'],settings['components'])
    for name in runtime.UNITS:
        runtime.verify_image(name,settings);runtime.ready(name,settings,attempts=1)
    if reviewed is None:return {'state':'already-current','package':found['package'],'next_step':'No reviewed newer package is available in this source. Continue backups and recovery exercises.'}
    verify_helpers(runtime,owner)
    data,transport=configured()
    if data['ownership']!=owner:raise ValueError('Configure full application backup scope before upgrading')
    summary=status_summary(transport.snapshots(timeout=15))
    if summary['state']!='snapshot-present' or summary['backup_age_seconds']>86400:raise ValueError('Verify a full application backup no more than one day old before starting maintenance')
    if transaction.present(Path('/etc/rdc-backup/runtime-update.json')):raise ValueError('Finish the pending backup runtime update before upgrading')
    target=dict(owner,applications=dict(owner['applications'],images={key:pin['image'] for key,pin in reviewed['target'].items()}))
    plan={'source_owner':owner,'target_owner':target,'source_hashes':component_hashes(ROOT,owner)}
    transaction.validate_plan(plan)
    upgrade_files.preflight(ROOT,owner,'0'*32)
    return {'state':'upgrade-ready','package':found['package'],'source_versions':{k:v['version'] for k,v in reviewed['source'].items()},
            'target_versions':{k:v['version'] for k,v in reviewed['target'].items()},'backup_age_seconds':summary['backup_age_seconds'],'plan':plan,
            'next_step':'Choose a maintenance window. Apply takes and verifies a fresh encrypted snapshot while application writers are stopped.'}


@contextmanager
def locks(selected):
    if selected not in ('matrix','nextcloud'):raise ValueError('Unsupported upgrade lock scope')
    with ExitStack() as stack:
        for path in (Path('/etc/rdc-backup/operation.lock'),Path('/run/rdc-services-operation.lock' if selected=='matrix' else '/run/rdc-nextcloud-operation.lock')):
            fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            stream=stack.enter_context(os.fdopen(fd,'a'));fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def write(path,content,*,mode=0o600,uid=0,gid=0):
    path=Path(path);raw=content.encode() if isinstance(content,str) else content
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('Linked upgrade output')
    fd,temporary=tempfile.mkstemp(prefix='.rdc-upgrade-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),uid,gid);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        from restore_transaction import sync_directory
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def action(args,*,input_fn=input):
    require_platform()
    if args.upgrade_action=='recover':
        journal=transaction.pending(ROOT);selected=package(journal['source_owner']['applications'])
        with locks(selected):return transaction.recover(Backend(journal['source_owner']))
    review=check()
    if args.upgrade_action=='check' or review['state']!='upgrade-ready':return {k:v for k,v in review.items() if k!='plan'}
    if args.upgrade_action!='apply':raise ValueError('Unknown upgrade action')
    print(json.dumps({k:v for k,v in review.items() if k!='plan'},indent=2))
    print('This node will pause chat or files, verify a fresh encrypted backup, migrate only the listed version and suspend partner links for review. A committed upgrade will never automatically revert newer user data.')
    phrase='UPGRADE '+review['plan']['source_owner']['node_name']
    if not sys.stdin.isatty() or input_fn('Type '+phrase+' to begin maintenance: ').strip()!=phrase:return {'state':'cancelled'}
    with locks(review['package']):
        current=check()
        if current.get('plan')!=review['plan']:raise ValueError('Upgrade plan changed; check again')
        from service_operations import pull_images
        target=review['plan']['target_owner']['applications'];pins=for_owner(target)
        pull_images(pins)
        runtime=application_runtime(target)
        for component in pins:runtime.verify_image(component,{'components':pins})
        # Upgrade-compatible guards must be durable before the first pending
        # marker: a reboot at any later point cannot publish a partial version.
        install_guards(review['plan']['source_owner'],upgrade_compat=True)
        return transaction.apply(review['plan'],Backend(review['plan']['source_owner']))


class Backend:
    def __init__(self,source_owner):
        require_platform();self.owner=source_owner;self.selected=package(source_owner['applications'])
        self.runtime=application_runtime(source_owner['applications'])
        self.isolation=Isolation(source_owner,pending=UPGRADE_PENDING)

    def prepare(self,journal):
        if journal['source_owner']!=self.owner:raise ValueError('Upgrade runtime belongs to another source')
        # Peer application roles have no infrastructure certificate timer. The
        # outer application lock also excludes the private-service issuer.
        self.isolation.prepare(self.owner,state={'certificate_timer_active':False})

    def quiesce(self,journal):
        for name in resources(self.owner).services:
            if name=='tailscaled':continue
            self.isolation.stop(name)
            if self.isolation.is_active(name):raise ValueError('Application writer did not stop')
        if self.selected=='nextcloud':
            self.isolation.stop('rdc-nextcloud-cron')
            if self.isolation.is_active('rdc-nextcloud-cron'):raise ValueError('File background job did not stop')

    def snapshot(self,journal):
        return self.consistent_snapshot(journal,self.owner)

    def consistent_snapshot(self,journal,owner):
        data,transport=configured()
        if data['ownership']!=owner:raise ValueError('Upgrade backup scope changed')
        if journal['phase']=='preparing' and component_hashes(ROOT,owner)!=journal['source_hashes']:raise ValueError('Upgrade source changed before snapshot')
        parent=ROOT/transaction.JOURNALS.parent
        # Only tailscaled was active at capture and may restart. All application
        # writers stay explicitly stopped; no candidate has been installed yet.
        self.isolation.allow_validation()
        try:
            with tempfile.TemporaryDirectory(prefix='snapshot-',dir=parent) as temporary:
                folder=Path(temporary);metadata=capture(ROOT,folder/'snapshot',owner,upgrade_id=journal['id'])
                transport.wait_ready();identifier=transport.backup(folder/'snapshot')
                transport.restore(identifier,folder/'download')
                downloaded=validate_restore(folder/'download',owner)
                if downloaded!=metadata:raise ValueError('Downloaded upgrade backup differs from its capture')
                if journal['phase']=='preparing':
                    for name in resources(owner).services:
                        if name!='tailscaled' and self.isolation.is_active(name):raise ValueError('A writer restarted during the upgrade backup')
                return {'id':identifier,'captured_at':metadata['captured_at']}
        finally:self.isolation.finish_validation()

    def stage(self,journal):
        if component_hashes(ROOT,self.owner)!=journal['source_hashes']:raise ValueError('Upgrade source changed during backup')
        upgrade_files.stage(ROOT,self.owner,journal['id'])

    def isolate(self,journal):self.isolation.isolate(self.owner)

    def install_runtime(self,journal):
        runtime=self.runtime;target=journal['target_owner']['applications']
        settings=root_json(runtime.BASE/'runtime.json');settings.update(ownership=target,components=for_owner(target))
        atomic_json(runtime.BASE/'ownership.json',target);atomic_json(runtime.BASE/'runtime.json',settings)
        hashes={}
        for name in source_files(self.selected):
            raw=(SOURCE/name).read_bytes();write(runtime.INSTALLED/name,raw,mode=0o644);hashes[name]=hashlib.sha256(raw).hexdigest()
        atomic_json(runtime.INSTALLED/'manifest.json',{'schema_version':1,'files':hashes})
        return settings

    def migrate(self,journal):
        settings=self.install_runtime(journal)
        self.isolation.allow_validation()
        self.isolation.start(self.runtime.UNITS['postgres'])
        if self.selected=='nextcloud':
            from upgrade_nextcloud import migrate
            migrate(settings)
        # Synapse migrates its database at startup. All ingress remains under
        # the owned isolation table; pending maintenance suspends federation.
        for name in reversed(resources(journal['target_owner']).services):
            if name!='tailscaled':self.isolation.start(name)

    def verify(self,journal,*,original=False):
        owner=journal['source_owner' if original else 'target_owner']
        if original and component_hashes(ROOT,owner)!=journal['source_hashes']:raise ValueError('Original component recovery differs')
        network_hashes=component_hashes(ROOT,network_owner(owner))
        if any(journal['source_hashes'].get(name)!=digest for name,digest in network_hashes.items()):raise ValueError('Network components changed during the application upgrade')
        verify_helpers(self.runtime,owner)
        self.isolation.allow_validation()
        for name in reversed(resources(owner).services):self.isolation.start(name)
        settings=self.runtime.read_settings()
        if settings['ownership']!=owner['applications']:raise ValueError('Verified application identity differs')
        for name in self.runtime.UNITS:
            self.runtime.verify_image(name,settings);self.runtime.ready(name,settings,attempts=1)

    def restore_original(self,journal):
        self.quiesce(journal);self.isolate(journal)
        upgrade_files.restore(ROOT,self.owner,journal['id'])
        if component_hashes(ROOT,self.owner)!=journal['source_hashes']:raise ValueError('Retained original helpers changed')
        self.isolation.allow_validation()
        for name in reversed(resources(self.owner).services):
            if name!='tailscaled':self.isolation.start(name)

    def publish(self,journal):
        if journal['phase']=='committed':
            from backup_schedule import BASE,RUNTIME,verify_runtime,refresh_runtime
            data=root_json(BASE/'configuration.json')
            if data['ownership'] not in (journal['source_owner'],journal['target_owner']):raise ValueError('Backup scope changed during upgrade')
            atomic_json(BASE/'configuration.json',dict(data,ownership=journal['target_owner']))
            if RUNTIME.exists() or (BASE/'runtime-update.json').exists():
                from backup_schedule import FILES
                desired={'schema_version':1,'files':{name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in FILES}}
                if not (BASE/'runtime-update.json').exists() and verify_runtime()!=desired:
                    previous=RUNTIME.parent/'.rdc-backup-runtime-previous'
                    if previous.exists() or previous.is_symlink():
                        verify_runtime(previous)
                        retained=ROOT/transaction.JOURNALS.parent/('retained-backup-runtime-'+journal['id'])
                        if retained.exists() or retained.is_symlink():raise ValueError('Unexpected retained backup runtime')
                        durable_rename(previous,retained)
                refresh_runtime(SOURCE)
        self.isolation.finish_validation();self.isolation.release()
        if journal['phase']=='committed':
            # Do not report completion while only old-version backups exist.
            # Publication was committed already: a failure here resumes backup
            # at the new version and can never discard newly accepted writes.
            self.consistent_snapshot(journal,journal['target_owner'])

    def clean(self,journal):upgrade_files.clean(ROOT,self.owner,journal['id'])

    def freeze(self,journal):self.isolation.finish_validation()

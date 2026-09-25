"""Local dedicated gateway installation and explicit partner transitions."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import fcntl
from contextlib import contextmanager
from functools import wraps
from backup_operations import require_platform
from certificate_lifecycle import validate_material
from regional_workspace import private_read,private_write
from regional_operations import imported
from gateway_store import Store
import gateway_runtime as runtime
import gateway_transition
import gateway_contracts as contracts
import gateway_certificates as certificates

SOURCE=Path(__file__).resolve().parent
UNIT=Path('/etc/systemd/system')/(runtime.UNIT+'.service')
GUARD=Path('/etc/systemd/system/rdc-regional-guard.service')
TIMER=Path('/etc/systemd/system/rdc-regional-guard.timer')
SYSCTL=Path('/etc/sysctl.d/80-rdc-regional-gateway.conf')
SYSCTL_TEXT='net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\n'


@contextmanager
def backup_operation(base=Path('/etc/rdc-backup')):
    if not (base.exists() or base.is_symlink()):
        yield;return
    from gateway_backup import private_directory
    private_directory(base)
    descriptor=os.open(base/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe gateway backup lock')
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def serialized(function):
    @wraps(function)
    def call(*args,**kwargs):
        with backup_operation():return function(*args,**kwargs)
    return call


def tls_inputs(profile,identity):
    result=[]
    for name in ('tls_certificate','tls_private_key'):
        path=Path(profile[name]);info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>262144 or (name=='tls_private_key' and info.st_mode&0o077):raise ValueError('Use root-owned PEM inputs and a private certificate key')
        result.append(path.read_bytes())
    for hostname in identity['payload']['services'].values():validate_material(*result,hostname)
    return result


def preflight(profile,identity):
    require_platform()
    errors=contracts.validate(profile,identity)
    if errors:raise ValueError('; '.join(errors))
    for path in ('/etc/rdc-services','/etc/rdc-nextcloud','/etc/headscale','/etc/sc-derp'):
        if Path(path).exists() or Path(path).is_symlink():raise ValueError('Use a dedicated regional gateway VM, separate from controllers and application nodes')
    if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Resolve the pending network restore before configuring regional access')
    runtime.validate_network(profile,identity,runtime.root_json(Path('/etc/server-connectivity-profile.json')),
        json.loads(runtime.command('/usr/local/bin/tailscale','status','--json')),json.loads(runtime.command('/usr/local/bin/tailscale','debug','prefs')))
    runtime.lan_interface(profile)
    existing=runtime.BASE.exists() or runtime.BASE.is_symlink()
    if existing:
        store=Store(runtime.BASE)
        if store.profile()!=profile or store.identity()!=identity:raise ValueError('This gateway has a different pinned identity or network configuration')
        store.state()
        if certificates.pending(store):raise ValueError('Resume the pending gateway certificate replacement before installation')
        if store.recovery_pending():raise ValueError('Review gateway recovery and apply current fresh agreements before repeating installation')
        if not (runtime.BASE/'tls/active').exists() and not (runtime.BASE/'tls/active').is_symlink() and store.state()['generation']==0:
            cert,key=tls_inputs(profile,identity)  # Resume interrupted first installation.
        else:cert,key=certificates.managed_material(store)
        for hostname in identity['payload']['services'].values():validate_material(cert,key,hostname)
    else:
        tls_inputs(profile,identity)
        reserved=[runtime.INSTALLED,UNIT,Path(str(UNIT)+'.d'),SYSCTL,GUARD,TIMER,Path(str(GUARD)+'.d'),Path(str(TIMER)+'.d')]
        if any(path.exists() or path.is_symlink() for path in reserved):raise ValueError('Unowned gateway resources already exist')
        if Path('/usr/sbin/nft').exists():
            tables=json.loads(runtime.command('/usr/sbin/nft','-j','list','tables'))
            if any(item.get('table',{}).get('name')=='rdc_gateway' for item in tables['nftables']):raise ValueError('A firewall already owns the gateway table name')
        if Path('/usr/bin/podman').exists() and json.loads(runtime.command('/usr/bin/podman','ps','--all','--format','json')):raise ValueError('Use a dedicated gateway without other root-managed containers')
        if re.search(r':(?:443|3128|9443)\s',runtime.command('/usr/bin/ss','-H','-lntup')):raise ValueError('A gateway listener port is already in use')
        if shutil.disk_usage('/var/lib').free<3*1024**3:raise ValueError('Provide at least 3 GiB free disk for the gateway')
    from nextcloud_operations import check_overrides
    from restore_runtime import guard_files
    from backup_scope import include
    from gateway_backup import ownership
    owner=ownership(profile,identity,runtime.root_json(Path('/etc/server-connectivity-profile.json')))
    check_overrides([Path(str(path)+'.d') for path in (UNIT,GUARD,TIMER)],guard_files(include(owner['network'],owner)))
    if not existing and Path('/etc/rdc-backup/schedule.json').exists():
        from backup_schedule import owned_schedule
        owned_schedule()
        if subprocess.run(['/bin/systemctl','is-active','rdc-backup.timer'],capture_output=True,timeout=15).returncode!=3:
            raise ValueError('Disable the backup timer before adding a gateway; include-services and create a new snapshot afterward')
    return {'state':'gateway-preflight-passed','existing':existing,'partner_transport':'not-verified'}


def owned_file(path,content,*,mode=0o600):
    raw=content.encode() if isinstance(content,str) else content
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=mode or path.read_bytes()!=raw:raise ValueError('Existing gateway resource differs; no unreviewed overwrite')
    else:
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        path.chmod(mode)


@serialized
def install(profile,identity):
    preflight(profile,identity)
    store=Store(runtime.BASE);store.initialize(profile,identity)
    with store.lock(wait_seconds=10):
        from gateway_backup import ownership,initialize_archive,ARCHIVE
        owner=ownership(profile,identity,runtime.root_json(Path('/etc/server-connectivity-profile.json')))
        private_write(runtime.BASE/'ownership.json',json.dumps(owner).encode())
        initialize_archive(ARCHIVE,owner)
        # Read the complete frozen catalogue before any package/systemd changes.
        if runtime.INSTALLED.exists():
            info=runtime.INSTALLED.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Unsafe installed gateway runtime directory')
        else:runtime.INSTALLED.mkdir(mode=0o700)
        hashes={}
        for name in runtime.RUNTIME_FILES:
            raw=(SOURCE/name).read_bytes();owned_file(runtime.INSTALLED/name,raw,mode=0o644);hashes[name]=hashlib.sha256(raw).hexdigest()
        owned_file(runtime.INSTALLED/'manifest.json',json.dumps({'schema_version':1,'files':hashes},sort_keys=True))
        if not (runtime.BASE/'tls/active').exists():
            cert,key=tls_inputs(profile,identity)
            certificates.activate_certificate(store,cert,key,initial=True)
        owned_file(UNIT,runtime.unit(),mode=0o644);owned_file(SYSCTL,SYSCTL_TEXT,mode=0o644)
        owned_file(GUARD,runtime.guard_unit(),mode=0o644);owned_file(TIMER,runtime.guard_timer(),mode=0o644)
        runtime.command('/usr/bin/apt-get','update','-qq',timeout=300)
        runtime.command('/usr/bin/apt-get','install','-y','podman','runc','nftables','python3-cryptography','python3-yaml',timeout=600)
        runtime.command('/usr/sbin/sysctl','-p',str(SYSCTL))
        pin=contracts.image_pins()['gateway']
        runtime.command('/usr/bin/podman','pull',pin['image'],timeout=600)
        runtime.verify_image();runtime.verify_runtime()
        runtime.command('/bin/systemctl','daemon-reload')
        controller=runtime.Runtime(store)
        if store.pending():candidate=store.pending()
        else:
            previous=store.state();candidate=store.candidate(previous['agreements'],[],now=int(time.time()))
        gateway_transition.apply(store,controller,candidate)
        runtime.command('/bin/systemctl','enable',runtime.UNIT+'.service')
        runtime.command('/bin/systemctl','enable','--now','rdc-regional-guard.timer')
    return {'state':'gateway-listeners-installed','partners':len(store.peers()),'application_federation':'not-verified',
            'next_step':'Apply independently approved agreements and test application exchange; listener readiness alone proves no federation.'}


@serialized
def change(documents=None,revoked_ids=None,*,resume=False):
    require_platform();runtime.verify_runtime();store=Store(runtime.BASE)
    with store.lock(wait_seconds=10):
        restore=Path('/etc/rdc-restore-pending.json')
        if restore.exists() or restore.is_symlink():raise ValueError('Complete fenced recovery before changing gateway policy')
        if certificates.pending(store):raise ValueError('Complete the pending gateway certificate replacement before changing policy')
        if resume:
            candidate=store.pending()
            if candidate is None:raise ValueError('No gateway transition is pending')
        else:
            state=store.state()
            selected=state['agreements'] if documents is None else documents
            if documents is None and revoked_ids and store.recovery_pending():
                from gateway_recovery import fresh_documents
                selected=[document for document in selected if fresh_documents(store.recovery(),[document])]
            candidate=store.candidate(selected,revoked_ids or [],now=int(time.time()))
        gateway_transition.apply(store,runtime.Runtime(store),candidate)
    return {'state':'gateway-policy-applied','generation':candidate['generation'],'partners':len(store.peers()),
            'application_federation':'not-verified','revocations_recorded':len(candidate['revoked_ids'])}


def status():
    require_platform();runtime.verify_runtime();store=Store(runtime.BASE);network=True
    try:runtime.network_check(store)
    except (OSError,ValueError,subprocess.SubprocessError):network=False
    item=runtime.inspect(store.identity());pending=store.pending()
    checkpoint=json.loads(private_read(runtime.BASE/'clock.json'));now=int(time.time())
    time_verified=type(checkpoint.get('latest_utc')) is int and 0<=now-checkpoint['latest_utc']<=30
    timer=subprocess.run(['/bin/systemctl','is-active','rdc-regional-guard.timer'],capture_output=True,timeout=15).returncode==0
    review=store.recovery()
    return {'recovery_review':review,'state':'gateway-recovery-review-required' if store.recovery_pending() else ('gateway-change-pending' if pending else ('gateway-configured' if time_verified and timer else 'gateway-enforcement-unverified')),'time_checkpoint_recent':time_verified,'guard_timer_active':timer,'network_identity_verified':network,
            'proxy_running':bool(item and item.get('State',{}).get('Running')),'approved_peers':store.peers(),
            'application_federation':'not-verified','supported_transport':['matrix','nextcloud']}


def action(args):
    from profile_config import load_profile
    from regional_operations import interactive
    import sys
    command=args.gateway_action
    if command=='recovery':
        require_platform();runtime.verify_runtime()
        from gateway_backup import export_token,ARCHIVE
        from gateway_store import decode
        with backup_operation():
            store=Store(runtime.BASE)
            with store.lock(wait_seconds=10):
                return export_token(ARCHIVE,decode(private_read(store.base/'ownership.json')),args.output_file)
    if command=='issuer':
        from service_issuer import action as issuer_action
        return issuer_action(args)
    if command=='certificate':
        require_platform();runtime.verify_runtime()
        if args.certificate_action=='status':return certificates.status(Store(runtime.BASE))
        return certificates.replace(args.certificate,args.private_key)
    if command=='setup':
        from gateway_setup import wizard
        return wizard(imported(args.identity),args.identity,args.output_file)
    if command in ('check','apply'):
        profile=load_profile(str(args.profile))
        if not isinstance(profile,dict) or not isinstance(profile.get('identity_file'),str) or not Path(profile['identity_file']).is_absolute():raise ValueError('Select a gateway profile with an absolute public identity file path')
        identity=imported(profile['identity_file'])
        preview=preflight(profile,identity)
        if command=='check':return preview
        interactive()
        print(json.dumps({'scope':'this dedicated Ubuntu gateway','profile':profile,
                          'changes':['pinned Envoy container','private LAN proxy','scoped firewall','disable general forwarding','owned systemd runtime'],
                          'application_federation':'not-verified'},indent=2))
        if input('Type INSTALL to install or resume this gateway: ').strip()!='INSTALL':return {'state':'cancelled'}
        return install(profile,identity)
    if command=='status':return status()
    if command=='service-link':
        from service_link import export_gateway
        from regional_operations import export
        require_platform();runtime.verify_runtime();store=Store(runtime.BASE)
        with store.lock(wait_seconds=10):return export(args.output_file,export_gateway(store,args.package))
    require_platform();interactive();runtime.verify_runtime();store=Store(runtime.BASE)
    documents=None;revoked=None
    if command=='policy':
        documents=[imported(path) for path in args.agreement]
        candidate=store.candidate(documents,[],now=int(time.time()))
        print(json.dumps({'recovery_review':store.recovery(),'proposed_peers':store.peers(candidate),'note':'This replaces the active agreement selection; recorded revocations remain permanent.'},indent=2))
    elif command=='revoke':
        revoked=[args.agreement_id]
        selected=store.state()['agreements']
        if store.recovery_pending():
            from gateway_recovery import fresh_documents
            selected=[document for document in selected if fresh_documents(store.recovery(),[document])]
        store.candidate(selected,revoked,now=int(time.time()))
        print('Record this agreement as revoked on THIS gateway and close its future traffic: '+args.agreement_id)
    elif command=='resume':
        if store.pending() is None:raise ValueError('No gateway change is pending')
        print('Retry the exact pending gateway change. Access stays closed on failure.')
    else:raise ValueError('Unsupported gateway operation')
    if input('Type APPLY to change this gateway: ').strip()!='APPLY':return {'state':'cancelled'}
    return change(documents,revoked,resume=command=='resume')

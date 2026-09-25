"""Guided local file-service installation on an independently owned enrolled node."""
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
from backup_operations import require_platform,root_json
from certificate_lifecycle import activate,validate_material
from nextcloud_contracts import validate,ownership,image_pins,from_owner
from nextcloud_rendering import application_config,configuration_values,apache_ports,apache_site,proxy,IDENTITY_FIELDS
from service_operations import directory,write,installed_address,pull_images
import nextcloud_runtime as runtime

SOURCE=Path(__file__).resolve().parent
TLSBASE=Path('/etc/rdc-nextcloud-tls')
TARGET=Path('/etc/systemd/system/rdc-nextcloud.target')
CRON=Path('/etc/systemd/system/rdc-nextcloud-cron.service')
TIMER=Path('/etc/systemd/system/rdc-nextcloud-cron.timer')


def inputs(profile):
    if validate(profile):raise ValueError('Invalid file-service profile')
    content=[]
    for key in ('tls_certificate','tls_private_key'):
        path=Path(profile[key]);info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>262144:raise ValueError('Use small regular root-owned certificate files')
        if key=='tls_private_key' and info.st_mode&0o077:raise ValueError('The private key must be readable only by root')
        content.append(path.read_bytes())
    validate_material(*content,profile['nextcloud_hostname'])
    return tuple(content)


def reserved_paths():
    return [runtime.BASE,runtime.STATE,runtime.APP,runtime.INSTALLED,runtime.regional.BASE,TLSBASE,TARGET,CRON,TIMER,
            *[Path('/etc/systemd/system',name+'.service') for name in runtime.UNITS.values()]]


def check_overrides(folders,known):
    from restore_runtime import check_guard
    for folder in folders:
        if not (folder.exists() or folder.is_symlink()):continue
        if folder.is_symlink() or not folder.is_dir():raise ValueError('Unsafe file-service unit overrides')
        for path in folder.iterdir():
            if path not in known:raise ValueError('Unreviewed file-service unit overrides require administration review')
            check_guard(path,known[path][0])
        info=folder.stat()
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe file-service unit overrides')


def preflight(profile):
    require_platform()
    if validate(profile):raise ValueError('Invalid file-service profile')
    network=root_json(Path('/etc/server-connectivity-profile.json'));owner=ownership(profile,network)
    address=installed_address(network);inputs(profile)
    if {item[4][0] for item in socket.getaddrinfo(profile['nextcloud_hostname'],443,type=socket.SOCK_STREAM)}!={address}:
        raise ValueError('The file-service DNS name must resolve only to this enrolled overlay IPv4')
    if Path('/etc/rdc-services').exists():raise ValueError('Use a separate enrolled VM for Nextcloud; this node already has the chat package')
    marker=runtime.BASE/'ownership.json'
    if marker.exists() or marker.is_symlink():
        if root_json(marker)!=owner:raise ValueError('Existing file-service identity or component versions differ')
        from restore_runtime import guard_files
        from backup_scope import include
        units=[TARGET,CRON,TIMER,*[Path('/etc/systemd/system',name+'.service') for name in runtime.UNITS.values()]]
        check_overrides([Path(str(path)+'.d') for path in units],guard_files(include(network,owner)))
        if (runtime.BASE/'runtime.json').exists() and root_json(runtime.BASE/'runtime.json')['bind_address']!=address:
            raise ValueError('File-service address changed; use a reviewed endpoint migration')
        return {'ownership':owner,'address':address,'existing':True}
    if any(p.exists() or p.is_symlink() for p in reserved_paths()):raise ValueError('Unowned file-service resources exist; this installer will not adopt them')
    for path in [TARGET,CRON,TIMER,*[Path('/etc/systemd/system',name+'.service') for name in runtime.UNITS.values()]]:
        if Path(str(path)+'.d').exists() or Path(str(path)+'.d').is_symlink():raise ValueError('Unreviewed file-service unit overrides exist')
    if shutil.disk_usage('/var/lib').free<12*1024**3:raise ValueError('Provide at least 12 GiB free storage, plus capacity for files and recovery copies')
    memory={k:int(v.split()[0]) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
    if memory.get('MemTotal',0)<int(3.5*1024**2):raise ValueError('Provide approximately 4 GiB RAM or more')
    listeners=subprocess.run(['/usr/bin/ss','-H','-lntup'],check=True,capture_output=True,text=True,timeout=15).stdout
    if re.search(r':(?:443|5434|8083)\s',listeners):raise ValueError('A required file-service port is already occupied')
    if Path('/usr/bin/podman').exists() and json.loads(runtime.podman('ps','--all','--format','json')):
        raise ValueError('Use a dedicated node without existing root-managed containers')
    if Path('/etc/rdc-backup/schedule.json').exists():
        from backup_schedule import owned_schedule
        owned_schedule()
        if subprocess.run(['/bin/systemctl','is-active','rdc-backup.timer'],capture_output=True,timeout=15).returncode!=3:
            raise ValueError('Disable the backup timer before adding files; extend backup scope and take a new snapshot afterward')
    return {'ownership':owner,'address':address,'existing':False}


from nextcloud_certificates import activate_certificate


def maintenance(settings,action,data):
    result=subprocess.run(runtime.maintenance_command(settings,action),input=json.dumps(data),text=True,capture_output=True,timeout=300)
    if result.returncode:raise ValueError('Private file-service '+action+' failed; inspect application state without publishing secrets')


def code_entries(root):
    root=Path(root);entries=[root,*root.rglob('*')]
    for entry in entries:
        if entry.is_symlink():
            try:target=entry.resolve(strict=True)
            except (OSError,RuntimeError):raise ValueError('Broken or cyclic link in pinned application code') from None
            if not target.is_relative_to(root.resolve()) or not (target.is_file() or target.is_dir()):
                raise ValueError('Pinned application code link escapes its read-only tree')
        elif not (entry.is_file() or entry.is_dir()):raise ValueError('Special file in pinned application code')
    return entries


def bootstrap(settings,profile,admin_user,admin_password,database_password):
    completed=runtime.BASE/'identity.json'
    if completed.exists():
        identity=root_json(completed);configuration_values(profile,identity)
    else:
        if not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}',admin_user) or not isinstance(admin_password,str) or len(admin_password)<12:
            raise ValueError('Use a lowercase administrator name and a password of at least 12 characters')
        seeded=runtime.BASE/'code-seeded.json'
        if not seeded.exists():
            directory(runtime.APP,uid=33,gid=33)
            command=runtime.common(settings)+['--rm','--user=33:33','--entrypoint=rsync','--volume',str(runtime.APP)+':/var/www/html:rw',
                     settings['components']['nextcloud']['image'],'-rlt','/usr/src/nextcloud/','/var/www/html/']
            subprocess.run(command,check=True,capture_output=True,timeout=120)
            # Keep only the upstream sample/CAN_INSTALL until local initialization.
            for file in (runtime.APP/'config').glob('*.config.php'):file.unlink()
            write(seeded,json.dumps({'image':settings['components']['nextcloud']['image']}))
        elif root_json(seeded)!={'image':settings['components']['nextcloud']['image']}:raise ValueError('Existing file-service code identity differs')
        generated=runtime.APP/'config/config.php'
        if not generated.exists():maintenance(settings,'install',{'admin_user':admin_user,'admin_password':admin_password,'database_password':database_password})
        export='$CONFIG=[];require "/var/www/html/config/config.php";echo json_encode(array_intersect_key($CONFIG,array_flip('+json.dumps(sorted(IDENTITY_FIELDS-{'data_fingerprint'}))+')));'
        command=runtime.common(settings)+['--rm','--user=33:33','--entrypoint=php','--volume',str(runtime.APP)+':/var/www/html:ro',settings['components']['nextcloud']['image'],'-r',export]
        result=subprocess.run(command,check=True,capture_output=True,text=True,timeout=30)
        identity=json.loads(result.stdout);identity['data_fingerprint']=secrets.token_hex(16);configuration_values(profile,identity)
        write(completed,json.dumps(identity))
    directory(runtime.BASE/'config',mode=0o700,uid=33,gid=33)
    write(runtime.BASE/'config/config.php',application_config(profile,identity),mode=0o400,uid=33,gid=33)
    # Code is recreated from the pinned image on a replacement, not a writable
    # application volume. Config and uploaded files have separate mounts.
    freeze_code(runtime.APP)


def freeze_code(root):
    root=Path(root)
    code_entries(root)  # Reject escaping links before touching the owned tree.
    # The private identity/config copy is durable before this call. Remove the
    # bootstrap copy before making any application code world-readable.
    (root/'config/config.php').unlink(missing_ok=True)
    for entry in code_entries(root):
        os.chown(entry,0,0,follow_symlinks=False)
        if not entry.is_symlink():entry.chmod(0o755 if entry.is_dir() else 0o644)


def cron_unit():
    return '[Unit]\nDescription=RDC Nextcloud background jobs\nAfter=rdc-nextcloud.service\nPartOf=rdc-nextcloud.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I -B /usr/local/lib/rdc-nextcloud/nextcloud_cron.py\nTimeoutStartSec=300\nUMask=0077\n'


def cron_timer():return '[Unit]\nDescription=RDC Nextcloud background-job schedule\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=5m\n[Install]\nWantedBy=timers.target\n'


def install_or_resume(profile,network,address,admin_user,admin_password):
    require_platform();owner=ownership(profile,network);cert,key=inputs(profile)
    marker=runtime.BASE/'ownership.json'
    if marker.exists() or marker.is_symlink():
        if root_json(marker)!=owner:raise ValueError('Cannot resume another file-service installation')
    elif any(p.exists() or p.is_symlink() for p in reserved_paths()):raise ValueError('File-service paths must be fresh or exactly owned')
    if not Path('/usr/bin/podman').exists() or not Path('/usr/bin/runc').exists():
        subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,capture_output=True,timeout=300)
        subprocess.run(['/usr/bin/apt-get','install','-y','podman','runc'],check=True,capture_output=True,timeout=600)
    pins=pull_images(image_pins());settings={'schema_version':1,'ownership':owner,'bind_address':address,'components':pins}
    for name in pins:runtime.verify_image(name,settings)
    directory(runtime.BASE);write(marker,json.dumps(owner))
    for path in (runtime.STATE,runtime.INSTALLED,TLSBASE):directory(path)
    write(runtime.BASE/'runtime.json',json.dumps(settings))
    password_file=runtime.BASE/'database-password'
    if password_file.exists():
        info=password_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=999 or stat.S_IMODE(info.st_mode)!=0o400:raise ValueError('Unsafe saved database credential')
        password=password_file.read_text().strip()
        if not re.fullmatch('[a-f0-9]{64}',password):raise ValueError('Invalid saved database credential')
    else:
        if (runtime.STATE/'postgres').exists() and any((runtime.STATE/'postgres').iterdir()):raise ValueError('Database exists without saved credentials; use recovery')
        password=secrets.token_hex(32);write(password_file,password+'\n',uid=999,gid=999,mode=0o400)
    directory(runtime.STATE/'postgres',uid=999,gid=999);directory(runtime.STATE/'files',uid=33,gid=33)
    write(runtime.BASE/'ports.conf',apache_ports(),mode=0o644);write(runtime.BASE/'site.conf',apache_site(),mode=0o644)
    write(runtime.BASE/'Caddyfile',proxy(profile,address),mode=0o644)
    hashes={}
    for name in ('nextcloud_runtime.py','nextcloud_cron.py','nextcloud_images.json','service_runtime.py','nextcloud_regional.py','service_regional.py','regional_http.py'):
        content=(SOURCE/name).read_bytes();write(runtime.INSTALLED/name,content,mode=0o644);hashes[name]=hashlib.sha256(content).hexdigest()
    write(runtime.INSTALLED/'manifest.json',json.dumps({'schema_version':1,'files':hashes}))
    for name,unitname in runtime.UNITS.items():write(Path('/etc/systemd/system',unitname+'.service'),runtime.unit(name),mode=0o644)
    write(TARGET,'[Unit]\nDescription=RDC Nextcloud services\nAfter=tailscaled.service\nWants=rdc-nextcloud-proxy.service\n[Install]\nWantedBy=multi-user.target\n',mode=0o644)
    write(CRON,cron_unit(),mode=0o644);write(TIMER,cron_timer(),mode=0o644)
    subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)
    subprocess.run(['/bin/systemctl','start','rdc-nextcloud-postgres.service'],check=True,timeout=180)
    bootstrap(settings,profile,admin_user,admin_password,password)
    runtime.podman('exec','--user','999:999',runtime.UNITS['postgres'],'psql','-p','5434','-U','nextcloud','-d','nextcloud','-c','ALTER ROLE oc_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',timeout=30)
    if runtime.TLS.exists() and ((runtime.TLS/'tls.crt').read_bytes()!=cert or (runtime.TLS/'tls.key').read_bytes()!=key):raise ValueError('Use the explicit certificate replacement command')
    activate_certificate(settings,cert,key,initial=True)
    runtime.synchronize_regional(settings)
    subprocess.run(['/bin/systemctl','start','rdc-nextcloud.service'],check=True,timeout=180)
    # Preserve only the currently reviewed connector's narrowly selected shares.
    for app in ('updatenotification','sharebymail'):
        runtime.podman('exec','--user','33:33',runtime.UNITS['nextcloud'],'php','occ','app:disable',app,timeout=60)
    expected='approved-gateway-configured' if runtime.regional.active(settings) else 'disabled'
    if federation_status()!=expected or public_links_status()!='disabled':raise ValueError('External sharing controls did not take effect')
    runtime.podman('exec','--user','33:33',runtime.UNITS['nextcloud'],'php','occ','background:cron',timeout=60)
    subprocess.run(['/bin/systemctl','enable','--now','rdc-nextcloud.target','rdc-nextcloud-cron.timer'],check=True,timeout=180)
    subprocess.run(['/bin/systemctl','start','rdc-nextcloud-proxy.service'],check=True,timeout=180)
    return status()


FEDERATION_CONTROLS=('outgoing_server2server_share_enabled','incoming_server2server_share_enabled',
                     'outgoing_server2server_group_share_enabled','incoming_server2server_group_share_enabled',
                     'lookupServerEnabled','lookupServerUploadEnabled','federatedTrustedShareAutoAccept')


def federation_status():
    config=runtime.regional.active(runtime.read_settings());expected=runtime.regional.controls(config)
    values={name:runtime.podman('exec','--user','33:33',runtime.UNITS['nextcloud'],'php','occ','config:app:get','files_sharing',name,timeout=30).strip() for name in FEDERATION_CONTROLS}
    if values!=expected:return 'configuration-changed'
    return 'approved-gateway-configured' if config else 'disabled'


def public_links_status():
    value=runtime.podman('exec','--user','33:33',runtime.UNITS['nextcloud'],'php','occ','config:app:get','core','shareapi_allow_links',timeout=30).strip()
    return 'disabled' if value=='no' else 'configuration-changed'


def status():
    settings=runtime.read_settings()
    for name in runtime.UNITS:runtime.verify_image(name,settings);runtime.ready(name,settings,attempts=1)
    return {'state':'file-service-listeners-verified','nextcloud_url':'https://'+settings['ownership']['nextcloud_hostname'],
            'application_login_test':'not-run','application_backup':backup_status(),'federation':federation_status(),'public_links':public_links_status()}


def action(args):
    import getpass
    import sys
    from profile_config import load_profile
    if args.action=='regional':
        from nextcloud_link import action as regional_action
        return regional_action(args)
    if args.action=='issuer':
        from service_issuer import action as issuer_action
        return issuer_action(args)
    if args.action=='setup':
        from nextcloud_setup import wizard
        return wizard(args.output_file)
    require_platform()
    if args.action=='status':return status()
    if args.action=='check':return dict(preflight(load_profile(str(args.profile))),state='checks-passed')
    profile=None;username=password=None
    if args.action=='apply':
        profile=load_profile(str(args.profile));preflight(profile)
        phrase='INSTALL NEXTCLOUD ON '+profile['node_name']
        print('Install the pinned file service on THIS node: '+profile['node_name']+'. Local accounts, private HTTPS and background jobs will be configured.')
        if not sys.stdin.isatty() or input('Type '+phrase+' to continue: ').strip()!=phrase:return {'state':'cancelled'}
        if not (runtime.BASE/'identity.json').exists():
            username=input('Initial administrator name (lowercase, 3–32 characters): ').strip()
            password=getpass.getpass('Initial administrator password (at least 12 characters): ')
            if password!=getpass.getpass('Repeat administrator password: '):raise ValueError('Passwords did not match')
        else:username=password='unused'
    elif args.action=='account':
        if not sys.stdin.isatty():raise ValueError('Create application accounts through an interactive local terminal')
        username=input('New ordinary account name (lowercase, 3–32 characters): ').strip()
        password=getpass.getpass('Account password (at least 12 characters): ')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}',username) or len(password)<12:raise ValueError('Use a valid account name and a password of at least 12 characters')
        if password!=getpass.getpass('Repeat account password: '):raise ValueError('Passwords did not match')
    elif args.action!='certificate':raise ValueError('Unsupported file-service operation')
    with ExitStack() as stack:
        locks=[Path('/run/rdc-nextcloud-operation.lock')]
        if Path('/etc/rdc-backup').exists():locks.insert(0,Path('/etc/rdc-backup/operation.lock'))
        for path in locks:
            descriptor=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            lock=stack.enter_context(os.fdopen(descriptor,'a'));fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Complete pending recovery before administering the file service')
        if args.action=='apply':
            review=preflight(profile)
            return install_or_resume(profile,review['ownership']['network'],review['address'],username,password)
        settings=runtime.read_settings()
        if args.action=='account':
            maintenance(settings,'account',{'username':username,'password':password})
            return {'state':'account-created','username':username,'administrator':False}
        profile=from_owner(settings['ownership']);profile.update(tls_certificate=str(args.certificate),tls_private_key=str(args.private_key))
        cert,key=inputs(profile)
        return activate_certificate(settings,cert,key)


def backup_status():
    result={'state':'not-configured','restore_test':'not-run'}
    if Path('/etc/rdc-backup/configuration.json').exists():
        from backup_operations import configured,status_summary
        data,transport=configured()
        if 'applications' not in data['ownership']:return dict(result,state='network-only-applications-unprotected')
        try:return status_summary(transport.snapshots())
        except (OSError,ValueError,subprocess.SubprocessError):return dict(result,state='backup-unreachable')
    return result

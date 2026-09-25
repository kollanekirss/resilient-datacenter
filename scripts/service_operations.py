"""Local installation of the owned Matrix package on an enrolled Ubuntu service node."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
from backup_operations import require_platform,root_json,private_write
from certificate_lifecycle import validate_material
from service_contracts import validate,ownership,network_manifest,image_pins,same_installation
from service_rendering import synapse,logging_config,element,element_nginx,proxy
import service_runtime as runtime

TLSBASE=Path('/etc/rdc-service-tls')
TARGET=Path('/etc/systemd/system/rdc-services.target')
SOURCE=Path(__file__).resolve().parent


def tls_inputs(profile):
    contents=[]
    for name in ('tls_certificate','tls_private_key'):
        path=Path(profile[name]);info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>262144:
            raise ValueError('TLS inputs must be small, regular, root-owned files that other users cannot modify')
        if name=='tls_private_key' and info.st_mode&0o077: raise ValueError('Service TLS private key must be readable only by root')
        contents.append(path.read_bytes())
    for hostname in (profile['matrix_hostname'],profile['element_hostname']):validate_material(*contents,hostname)
    return tuple(contents)


def installed_address(network):
    from local_checks import inspect_local_checks
    checks=inspect_local_checks(network_manifest(network),require_owned=True,check_tls=False)
    if any(c.outcome!='pass' for c in checks) or not any(c.code=='client.verified' for c in checks): raise ValueError('Enroll and verify this owned local node before installing applications')
    result=subprocess.run(['/usr/local/bin/tailscale','status','--json'],check=True,capture_output=True,text=True,timeout=15)
    data=json.loads(result.stdout)
    addresses=[ipaddress.ip_address(v) for v in data.get('Self',{}).get('TailscaleIPs',[])]
    ipv4=[str(v) for v in addresses if v.version==4 and v in ipaddress.ip_network('100.64.0.0/10')]
    if len(ipv4)!=1:raise ValueError('Cannot establish the enrolled node overlay IPv4')
    return ipv4[0]


def reserved_paths():
    return [runtime.BASE,runtime.STATE,runtime.INSTALLED,TLSBASE,TARGET,
            *[Path('/etc/systemd/system')/(name+'.service') for name in runtime.UNITS.values()],
            *[Path('/etc/systemd/system')/(name+'.service.d') for name in runtime.UNITS.values()],Path(str(TARGET)+'.d')]


def preflight(profile):
    require_platform()
    if validate(profile):raise ValueError('Invalid Matrix service profile')
    if Path('/etc/rdc-nextcloud').exists() or Path('/etc/rdc-nextcloud').is_symlink():raise ValueError('Use a separate enrolled VM for Matrix; this node has file-service state')
    network=root_json(Path('/etc/server-connectivity-profile.json'));owner=ownership(profile,network)
    address=installed_address(network);tls_inputs(profile)
    backup_base=Path('/etc/rdc-backup')
    if (backup_base/'schedule.json').exists() and not (runtime.BASE/'ownership.json').exists():
        from backup_schedule import owned_schedule
        owned_schedule()
        active=subprocess.run(['/bin/systemctl','is-active','rdc-backup.timer'],capture_output=True,text=True,timeout=15)
        if active.returncode!=3:raise ValueError('Disable the backup schedule before adding applications; include-services and a new verified snapshot are required before re-enabling it')
    for hostname in (profile['matrix_hostname'],profile['element_hostname']):
        answers={r[4][0] for r in socket.getaddrinfo(hostname,443,type=socket.SOCK_STREAM)}
        if answers!={address}:raise ValueError('Both service DNS names must resolve only to this node overlay IPv4; review local DNS and disable public proxying')
    existing=runtime.BASE/'ownership.json'
    if existing.exists() or existing.is_symlink():
        if not same_installation(profile,network,root_json(existing)):raise ValueError('Application identity/version differs; migration requires a reviewed path')
        from restore_runtime import guard_files,check_guard
        from backup_scope import include
        known=guard_files(include(network,owner))
        for unit_name in runtime.UNITS.values():
            folder=Path('/etc/systemd/system',unit_name+'.service.d')
            if folder.exists() or folder.is_symlink():
                if folder.is_symlink() or folder.stat().st_uid!=0 or folder.stat().st_mode&0o022:raise ValueError('Unsafe application unit overrides')
                for path in folder.iterdir():
                    if path not in known:raise ValueError('Unreviewed application unit overrides require administration review')
                    check_guard(path,known[path][0])
        if Path(str(TARGET)+'.d').exists():raise ValueError('Unreviewed application target overrides require administration review')
        if (runtime.BASE/'runtime.json').exists():
            current=root_json(runtime.BASE/'runtime.json')
            if current['bind_address']!=address:raise ValueError('Service endpoint changed; address migration requires review')
        for name,content in zip(('tls.crt','tls.key'),tls_inputs(profile)):
            if (runtime.TLS/name).exists() and (runtime.TLS/name).read_bytes()!=content:raise ValueError('Use a reviewed certificate replacement operation; apply does not overwrite TLS identities')
        return {'ownership':owner,'address':address,'existing':True}
    if any(p.exists() or p.is_symlink() for p in reserved_paths()):raise ValueError('Unowned application resources exist; this installer does not adopt them')
    if shutil.disk_usage('/var/lib').free<12*1024**3:raise ValueError('Provide at least 12 GiB free local space before installing this initial Matrix package')
    memory={k:int(v.split()[0]) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
    if memory.get('MemTotal',0)<int(3.5*1024**2):raise ValueError('This initial package requires a server with approximately 4 GiB RAM or more')
    listeners=subprocess.run(['/usr/bin/ss','-H','-lntup'],check=True,capture_output=True,text=True,timeout=15).stdout
    import re
    if re.search(r':(?:443|5433|8008|8082)\s',listeners):raise ValueError('A reserved application port is already in use; no listener was replaced')
    if Path('/usr/bin/podman').exists():
        containers=json.loads(runtime.podman('ps','--all','--format','json'))
        if containers:raise ValueError('Use a dedicated node without existing root-managed containers for this initial package')
    return {'ownership':owner,'address':address,'existing':False}


def pull_images(pins=None):
    pins=image_pins() if pins is None else pins
    with tempfile.TemporaryDirectory(prefix='rdc-image-auth-') as directory:
        auth=Path(directory)/'auth.json';auth.write_text('{"auths":{}}');auth.chmod(0o600)
        for item in pins.values():
            cached=subprocess.run(['/usr/bin/podman','image','exists',item['image']],capture_output=True,timeout=15)
            if cached.returncode==0: continue
            if cached.returncode!=1: raise ValueError('Cannot inspect local service image cache')
            subprocess.run(['/usr/bin/podman','pull','--authfile',str(auth),'--arch','amd64','--os','linux',item['image']],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
    return pins


def directory(path,*,mode=0o700,uid=0,gid=0):
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=mode:
            raise ValueError('Existing service directory differs from its owned permissions')
        return
    path.mkdir(mode=mode);os.chown(path,uid,gid);path.chmod(mode)


def write(path,content,*,mode=0o600,uid=0,gid=0):
    data=content.encode() if isinstance(content,str) else content
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=mode or path.read_bytes()!=data:
            raise ValueError('Existing service configuration differs; resume will not overwrite it')
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.chown(path,uid,gid);path.chmod(mode)


def install_or_resume(profile,network,address):
    # The public apply path runs preflight first. Disposable CI may call this
    # lower-level helper with its synthetic owned node and local test network.
    require_platform();owner=ownership(profile,network);cert,key=tls_inputs(profile)
    marker=runtime.BASE/'ownership.json'
    if marker.exists() or marker.is_symlink():
        if not same_installation(profile,network,root_json(marker)):raise ValueError('Cannot resume another application identity')
    elif any(p.exists() or p.is_symlink() for p in reserved_paths()):raise ValueError('Application target must be fresh or owned by this exact installation')
    if not Path('/usr/bin/podman').exists() or not Path('/usr/bin/runc').exists():
        subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300)
        subprocess.run(['/usr/bin/apt-get','install','-y','podman','runc'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
    pins=pull_images()
    settings={'schema_version':1,'ownership':owner,'bind_address':address,'components':pins}
    for name in pins:runtime.verify_image(name,settings)
    directory(runtime.BASE)
    write(runtime.BASE/'ownership.json',json.dumps(owner,indent=2)+'\n')
    for path in (runtime.STATE,runtime.INSTALLED,TLSBASE):directory(path)
    write(runtime.BASE/'runtime.json',json.dumps(settings,indent=2)+'\n')
    if (runtime.BASE/'secrets.json').exists():generated=root_json(runtime.BASE/'secrets.json')
    else:
        if any((runtime.STATE/name).exists() and any((runtime.STATE/name).iterdir()) for name in ('postgres','synapse')): raise ValueError('Persistent application data exists without its saved secrets; recovery requires review')
        generated={name:secrets.token_hex(32) for name in ('database_password','registration_secret','macaroon_secret','form_secret')}
        write(runtime.BASE/'secrets.json',json.dumps(generated))
    for name,uid in (('postgres',999),('synapse',991)):
        directory(runtime.STATE/name,uid=uid,gid=uid)
    configuration=runtime.BASE/'synapse';directory(configuration,mode=0o750,gid=991)
    write(configuration/'homeserver.yaml',synapse(profile,generated),mode=0o640,gid=991)
    write(configuration/'log.config',logging_config(),mode=0o640,gid=991)
    write(runtime.BASE/'database-password',generated['database_password']+'\n',mode=0o400,uid=999,gid=999)
    write(runtime.BASE/'element.json',element(profile),mode=0o644)
    write(runtime.BASE/'element-nginx.conf',element_nginx(),mode=0o644)
    write(runtime.BASE/'Caddyfile',proxy(profile,address),mode=0o644)
    from service_certificates import activate_pair
    if runtime.TLS.exists() or runtime.TLS.is_symlink():
        from certificate_lifecycle import generation
        generation(TLSBASE,'active')
        if (runtime.TLS/'tls.crt').read_bytes()!=cert or (runtime.TLS/'tls.key').read_bytes()!=key:
            raise ValueError('Use services certificate to replace an existing TLS identity')
    activate_pair(TLSBASE,settings,cert,key,initial=True)
    hashes={}
    for name in ('service_runtime.py','service_images.json','service_regional.py'):
        content=(SOURCE/name).read_bytes();write(runtime.INSTALLED/name,content,mode=0o644);hashes[name]=hashlib.sha256(content).hexdigest()
    write(runtime.INSTALLED/'manifest.json',json.dumps({'schema_version':1,'files':hashes}))
    for name,unit_name in runtime.UNITS.items():write(Path('/etc/systemd/system')/(unit_name+'.service'),runtime.unit(name),mode=0o644)
    write(TARGET,'[Unit]\nDescription=RDC Matrix services\nAfter=tailscaled.service\nWants=rdc-service-proxy.service\n[Install]\nWantedBy=multi-user.target\n',mode=0o644)
    subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)
    subprocess.run(['/bin/systemctl','enable','rdc-services.target'],check=True,timeout=30)
    subprocess.run(['/bin/systemctl','start','rdc-services.target'],check=True,timeout=180)
    subprocess.run(['/bin/systemctl','start','rdc-service-proxy.service'],check=True,timeout=180)
    return status()


def status():
    settings=runtime.read_settings()
    for name in runtime.UNITS:
        runtime.verify_image(name,settings);runtime.ready(name,settings,attempts=1)
    backup={'state':'not-configured','restore_test':'not-run'}
    if Path('/etc/rdc-backup/configuration.json').exists():
        from backup_operations import configured,status_summary
        data,transport=configured()
        if 'applications' not in data['ownership']:backup['state']='network-only-applications-unprotected'
        else:
            try:backup=status_summary(transport.snapshots())
            except (OSError,ValueError,subprocess.SubprocessError):backup={'state':'backup-unreachable','restore_test':'not-run'}
    return {'state':'service-listeners-verified','matrix_url':'https://'+settings['ownership']['matrix_hostname'],
            'element_url':'https://'+settings['ownership']['element_hostname'],'application_login_test':'not-run',
            'application_backup':backup,'federation':regional_status(settings)}


def regional_status(settings):
    import service_regional
    configured=service_regional.configured(settings)
    if configured is None:return 'disabled'
    return 'connector-configured-exchange-unverified' if service_regional.active(settings) else 'suspended-pending-review'


def apply(profile):
    review=preflight(profile)
    return install_or_resume(profile,review['ownership']['network'],review['address'])


def action(args):
    import fcntl
    import sys
    from profile_config import load_profile
    if args.action=='regional':
        from service_link import action as regional_action
        return regional_action(args)
    if args.action=='issuer':
        from service_issuer import action as issuer_action
        return issuer_action(args)
    if args.action=='setup':
        from service_setup import wizard
        return wizard(args.output_file)
    require_platform()
    if args.action=='certificate':
        from service_certificates import replace
        return replace(args.certificate,args.private_key)
    if args.action=='status':return status()
    if args.action=='check':return dict(preflight(load_profile(str(args.profile))),state='checks-passed')
    if args.action=='account':
        from service_accounts import interactive
        return interactive(admin=args.admin)
    if args.action!='apply':raise ValueError('Unsupported application action')
    profile=load_profile(str(args.profile));review=preflight(profile)
    print('Install Matrix, PostgreSQL, Element and a private HTTPS proxy on THIS node: '+profile['node_name']+'. No public registration or federation will be enabled.')
    print('The application uses pinned containers. User login and application recovery remain unverified until exercised.')
    phrase='INSTALL MATRIX ON '+profile['node_name']
    if not sys.stdin.isatty() or input('Type '+phrase+' to proceed: ').strip()!=phrase:return {'state':'cancelled'}
    from service_certificates import operation_lock
    try:
        with operation_lock():return apply(profile)
    except KeyboardInterrupt:
        raise ValueError('Installation interrupted. Existing application state was retained; rerun the same reviewed profile to resume and verify it.') from None

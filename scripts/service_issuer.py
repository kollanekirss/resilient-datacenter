"""Explicit private-service DNS issuer and frozen renewal administration."""
from contextlib import contextmanager,ExitStack
from datetime import datetime,timezone,timedelta
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from service_issuer_contracts import validate,credential_text,issue_command,renew_command,validate_renewal,name_fields
from service_runtime import root_json,read_settings,verify_https
from service_contracts import network_manifest
from certificate_lifecycle import validate_material,validity
from service_certificates import activate_pair

BASE=Path('/etc/rdc-service-acme')
RUNTIME=Path('/opt/rdc-service-certificate-runtime')
UNIT=Path('/etc/systemd/system/rdc-service-certificate.service')
TIMER=Path('/etc/systemd/system/rdc-service-certificate.timer')
LEGACY_FILES=('service_issuer_runner.py','service_issuer.py','service_issuer_contracts.py','service_certificates.py',
       'service_runtime.py','service_contracts.py','certificate_lifecycle.py','profile_config.py','setup_contracts.py',
       'validate_inventory.py','validate_tls.py')
FILES=LEGACY_FILES+('nextcloud_runtime.py','nextcloud_certificates.py')


def directory(path,*,create=True):
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Unsafe certificate issuer directory')
    elif create:path.mkdir(mode=0o700)
    else:raise ValueError('Certificate issuer directory is missing')


def private_file(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>262144:
        raise ValueError('Certificate issuer files must be regular and private to root')
    return path.read_bytes()


def write(path,content,*,replace=False):
    content=content.encode() if isinstance(content,str) else content
    if path.exists() or path.is_symlink():
        previous=private_file(path)
        if not replace:
            if previous!=content:raise ValueError('Existing certificate issuer configuration differs')
            return
    fd,temporary=tempfile.mkstemp(prefix='.rdc-issuer-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def configuration():
    if os.geteuid()!=0 or not Path('/run/systemd/system').is_dir():raise ValueError('Run certificate administration on the owned Ubuntu server')
    directory(BASE,create=False);data=json.loads(private_file(BASE/'configuration.json'))
    if set(data)!={'schema_version','profile','network'} or data['schema_version']!=1 or validate(data['profile']):raise ValueError('Unknown certificate issuer configuration')
    network_manifest(data['network'])
    if root_json(Path('/etc/server-connectivity-profile.json'))!=data['network']:raise ValueError('Certificate issuer network identity changed')
    if any(data['profile'][k]!=data['network'][k] for k in ('institution_id','node_name')):raise ValueError('Certificate issuer node mismatch')
    return data


def check_ambient():
    # Dedicated settings must not inherit global pre/post/deploy hooks.
    for path in (Path('/etc/letsencrypt/cli.ini'),Path('/root/.config/letsencrypt/cli.ini')):
        if path.exists() or path.is_symlink():raise ValueError('An existing global Certbot configuration requires administration review before using this isolated issuer')


@contextmanager
def operation_lock(profile=None):
    if profile is None and (BASE/'configuration.json').exists():profile=configuration()['profile']
    file_service=profile is not None and profile.get('kind')=='nextcloud-certificates'
    with ExitStack() as stack:
        paths=[Path('/run/rdc-nextcloud-operation.lock' if file_service else '/run/rdc-services-operation.lock')]
        if Path('/etc/rdc-backup').exists():paths.insert(0,Path('/etc/rdc-backup/operation.lock'))
        for path in paths:
            fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            stream=stack.enter_context(os.fdopen(fd,'a'));fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('A pending restore blocks certificate issuance and activation')
        yield


def execute(command):
    check_ambient()
    subprocess.run(command,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','TZ':'UTC'},timeout=600)


def material(profile):
    lineage=BASE/'certbot/live/rdc-services'
    # Certbot owns its standard live -> archive links. Require their resolved
    # targets to stay in this private certificate lineage.
    contents=[]
    for name in ('fullchain.pem','privkey.pem'):
        target=(lineage/name).resolve(strict=True)
        if not target.is_relative_to(BASE/'certbot/archive/rdc-services'):raise ValueError('Certificate lineage points outside the owned archive')
        info=target.lstat()
        if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or info.st_mode&0o022 or info.st_size>262144:raise ValueError('Unsafe issued certificate material')
        if name=='privkey.pem' and info.st_mode&0o077:raise ValueError('Issued key is not private to root')
        contents.append(target.read_bytes())
    for name in name_fields(profile):validate_material(*contents,profile[name])
    return tuple(contents)


def check_renewal():
    path=BASE/'certbot/renewal/rdc-services.conf'
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>65536:raise ValueError('Unsafe certificate renewal configuration')
    validate_renewal(path.read_text())
    saved=private_file(BASE/'cloudflare.ini').decode()
    prefix='dns_cloudflare_api_token = '
    if not saved.startswith(prefix) or saved!=credential_text(saved[len(prefix):].rstrip('\n')):raise ValueError('Certificate provider credentials file changed format')


def publish(profile,cert,key):
    directory(BASE/'issued')
    write(BASE/'issued/tls.crt',cert,replace=True);write(BASE/'issued/tls.key',key,replace=True)
    return {'certificate':str(BASE/'issued/tls.crt'),'private_key':str(BASE/'issued/tls.key')}


def application_runtime(profile):
    if profile['kind']=='nextcloud-certificates':
        import nextcloud_runtime
        return nextcloud_runtime
    import service_runtime
    return service_runtime


def active_directory(profile):
    return Path('/etc/rdc-nextcloud-tls' if profile['kind']=='nextcloud-certificates' else '/etc/rdc-service-tls')


def activate_application(profile,settings,cert,key):
    if profile['kind']=='nextcloud-certificates':
        from nextcloud_certificates import activate_certificate
        return activate_certificate(settings,cert,key)
    return activate_pair(active_directory(profile),settings,cert,key)


def matching_application(profile):
    settings=application_runtime(profile).read_settings()
    if any(settings['ownership'][k]!=profile[k] for k in ('institution_id','node_name',*name_fields(profile))):
        raise ValueError('Certificate issuer and application identities differ')
    return settings


def issue(profile,token):
    from backup_operations import require_platform
    require_platform()
    if validate(profile):raise ValueError('Invalid service certificate request')
    network=root_json(Path('/etc/server-connectivity-profile.json'));network_manifest(network)
    if any(profile[k]!=network[k] for k in ('institution_id','node_name')):raise ValueError('Certificate request differs from the local node')
    data={'schema_version':1,'profile':profile,'network':network}
    with operation_lock(profile):
        check_ambient()
        marker=BASE/'configuration.json'
        if BASE.exists() or BASE.is_symlink():
            if configuration()!=data:raise ValueError('Another certificate issuer identity exists')
        else:
            directory(BASE);write(marker,json.dumps(data))
        for name in ('certbot','work','logs','issued'):directory(BASE/name)
        write(BASE/'cli.ini','')
        if (BASE/'cloudflare.ini').exists():
            saved=private_file(BASE/'cloudflare.ini').decode()
            if token is not None and saved!=credential_text(token):raise ValueError('Changing provider credentials requires explicit administration review')
        else:
            if token is None:raise ValueError('Enter the restricted provider token to initialize certificate issuance')
            write(BASE/'cloudflare.ini',credential_text(token))
        if not Path('/usr/bin/certbot').exists() or not Path('/usr/lib/python3/dist-packages/certbot_dns_cloudflare').is_dir():
            subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,capture_output=True,timeout=300)
            subprocess.run(['/usr/bin/apt-get','install','-y','certbot','python3-certbot-dns-cloudflare','python3-cryptography','python3-yaml'],check=True,capture_output=True,timeout=600)
        try:
            execute(issue_command(profile));check_renewal();cert,key=material(profile);paths=publish(profile,cert,key)
            write(BASE/'status.json',json.dumps({'state':'issued','checked_at':datetime.now(timezone.utc).isoformat()}),replace=True)
        except (OSError,ValueError,subprocess.SubprocessError):
            write(BASE/'status.json',json.dumps({'state':'issuance-failed','checked_at':datetime.now(timezone.utc).isoformat()}),replace=True)
            raise ValueError('Certificate issuance failed. Review DNS zone access, provider token, propagation and issuer availability; existing active TLS was retained.') from None
    return dict(paths,state='issued-not-activated',next_step='Use these certificate paths in '+('files' if profile['kind']=='nextcloud-certificates' else 'services')+' setup, install applications, then enable certificate renewal.')


def unit_text():
    return '[Unit]\nDescription=RDC private service certificate renewal\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I -B /opt/rdc-service-certificate-runtime/service_issuer_runner.py\nUMask=0077\nTimeoutStartSec=900\n'


def timer_text():
    return '[Unit]\nDescription=RDC private service certificate renewal schedule\n[Timer]\nOnCalendar=*-*-* 00,12:00:00 UTC\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n'


def verify_runtime():
    directory(RUNTIME,create=False);manifest=json.loads(private_file(RUNTIME/'manifest.json'))
    if set(manifest)!={'schema_version','files'} or manifest['schema_version']!=1 or set(manifest['files']) not in (set(FILES),set(LEGACY_FILES)):raise ValueError('Unknown issuer runtime')
    if set(p.name for p in RUNTIME.iterdir())!=set(manifest['files'])|{'manifest.json'}:raise ValueError('Unexpected issuer runtime files')
    for name,digest in manifest['files'].items():
        if hashlib.sha256(private_file(RUNTIME/name)).hexdigest()!=digest:raise ValueError('Certificate renewal runtime changed')
    for path,content in ((UNIT,unit_text()),(TIMER,timer_text())):
        if private_file(path).decode()!=content or Path(str(path)+'.d').exists() or Path(str(path)+'.d').is_symlink():raise ValueError('Unreviewed certificate renewal unit or override')


def enable():
    with operation_lock():
        data=configuration();settings=matching_application(data['profile'])
        check_renewal();cert,key=material(data['profile'])
        source=Path(__file__).resolve().parent
        hashes={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in FILES}
        intent=BASE/'runtime-install.json'
        if (RUNTIME.exists() or RUNTIME.is_symlink()) and not intent.exists():
            verify_runtime()
            if json.loads(private_file(RUNTIME/'manifest.json'))['files']!=hashes:raise ValueError('Installed certificate runtime differs; use its reviewed source or an explicit supported upgrade')
        else:
            if intent.exists():
                if json.loads(private_file(intent))!=hashes:raise ValueError('Resume issuer installation from its original reviewed source')
            else:
                if any(p.exists() or p.is_symlink() for p in (UNIT,TIMER,Path(str(UNIT)+'.d'),Path(str(TIMER)+'.d'))):raise ValueError('Unknown certificate scheduler resources exist')
                write(intent,json.dumps(hashes))
            directory(RUNTIME)
            for name in FILES:
                path=source/name
                if path.is_symlink():raise ValueError('Linked issuer source is unsupported')
                content=path.read_bytes();write(RUNTIME/name,content);hashes[name]=hashlib.sha256(content).hexdigest()
            write(RUNTIME/'manifest.json',json.dumps({'schema_version':1,'files':hashes}))
            write(UNIT,unit_text());write(TIMER,timer_text())
        verify_runtime()
        intent.unlink(missing_ok=True)
        probe=subprocess.run(['/usr/bin/python3','-I','-c','import yaml; import cryptography'],capture_output=True,timeout=15)
        if probe.returncode:
            subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,capture_output=True,timeout=300)
            subprocess.run(['/usr/bin/apt-get','install','-y','python3-yaml','python3-cryptography'],check=True,capture_output=True,timeout=300)
        activate_application(data['profile'],settings,cert,key)
        subprocess.run(['/bin/systemctl','daemon-reload'],check=True,capture_output=True,timeout=30)
        subprocess.run(['/bin/systemctl','enable','--now','rdc-service-certificate.timer'],check=True,capture_output=True,timeout=30)
        return {'state':'certificate-renewal-enabled','provider':'cloudflare','real_provider_acceptance':'operator-verification-required'}


def renew():
    verify_runtime()
    with operation_lock():
        data=configuration();settings=matching_application(data['profile'])
        try:
            check_renewal();execute(renew_command());cert,key=material(data['profile'])
            result=activate_application(data['profile'],settings,cert,key);publish(data['profile'],cert,key)
            write(BASE/'status.json',json.dumps(dict(result,checked_at=datetime.now(timezone.utc).isoformat())),replace=True)
        except (OSError,ValueError,subprocess.SubprocessError):
            write(BASE/'status.json',json.dumps({'state':'renewal-failed','checked_at':datetime.now(timezone.utc).isoformat()}),replace=True)
            raise ValueError('Certificate renewal failed. Check provider access and the active certificate; no successful renewal is claimed.') from None


def status():
    data=configuration();result={'state':'configured','provider':'cloudflare','automatic_renewal':False}
    if (BASE/'status.json').exists():result.update(json.loads(private_file(BASE/'status.json')))
    from cryptography import x509
    active=active_directory(data['profile'])/'active/tls.crt'
    if active.exists():
        cert=x509.load_pem_x509_certificate(active.read_bytes());expiry=validity(cert,'after')
        result.update(expires_at=expiry.isoformat(),expires_within_14_days=expiry<=datetime.now(timezone.utc)+timedelta(days=14))
        try:application_runtime(data['profile']).verify_https(matching_application(data['profile']));result['serving_verified']=True
        except (OSError,ValueError,subprocess.SubprocessError):result['serving_verified']=False
    if RUNTIME.exists():
        verify_runtime()
        probe=subprocess.run(['/bin/systemctl','is-active','rdc-service-certificate.timer'],capture_output=True,timeout=15)
        if probe.returncode not in (0,3):raise ValueError('Cannot establish certificate timer state')
        result['automatic_renewal']=probe.returncode==0
    return result


def action(args):
    if args.issuer_action=='setup':
        from service_issuer_setup import wizard
        return wizard(args.output_file,package=getattr(args,'certificate_package','matrix'))
    from backup_operations import require_platform
    require_platform()
    if args.issuer_action=='enable':return enable()
    if args.issuer_action=='status':return status()
    if args.issuer_action=='issue':
        import getpass,sys
        from profile_config import load_profile
        profile=load_profile(str(args.profile))
        if validate(profile):raise ValueError('Invalid certificate request profile')
        token=None
        if args.token_file is not None:
            if not args.token_file.is_absolute():raise ValueError('Use an absolute private credential-file path')
            token=private_file(args.token_file).decode().strip()
        elif not (BASE/'cloudflare.ini').exists():
            if not sys.stdin.isatty():raise ValueError('Initial issuance needs an interactive token prompt or a private root-owned token file')
            print('Use a restricted Cloudflare API token with Zone:DNS:Edit for only the selected certificate zones. It remains private on this node; keep independent emergency provider access.')
            token=getpass.getpass('Restricted DNS API token: ').strip()
        return issue(profile,token)
    raise ValueError('Unknown certificate issuer action')

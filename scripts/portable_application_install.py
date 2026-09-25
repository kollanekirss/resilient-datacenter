"""Explicit local VM installation. Invoked only after an interactive role review."""
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import stat
import subprocess
from portable_applications import profiles
from portable_frontend import configuration,nginx,TLS
from application_access import portable_owner,verify_local_address,verify_assigned
from backup_operations import require_platform,root_json
from service_operations import directory,write
from certificate_lifecycle import validate_material

SOURCE=Path(__file__).resolve().parent
BASE=Path('/etc/rdc-frontend')
INSTALLED=Path('/usr/local/lib/rdc-frontend')
UNIT=Path('/etc/systemd/system/rdc-frontend.service')


def material(path,*,private=False):
    path=Path(path);info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&(0o077 if private else 0o022) or info.st_size>262144:
        raise ValueError('Use small root-owned regular TLS files; private keys must be readable only by root')
    return path.read_bytes()


def coverage(cert,key,hostname,days):
    result=validate_material(cert,key,hostname)
    if datetime.fromisoformat(result['expires_at'])<datetime.now(timezone.utc)+timedelta(days=days):
        raise ValueError('Certificate does not cover the planned offline duration plus margin')
    return result


def frontend_unit():
    return '''[Unit]
Description=RDC portable local HTTPS frontend
After=network.target
[Service]
Type=simple
RuntimeDirectory=rdc-frontend
ExecStartPre=/usr/bin/python3 -I -B /usr/local/lib/rdc-frontend/portable_frontend_runtime.py prepare
ExecStartPre=/usr/sbin/nginx -t -c /etc/rdc-frontend/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/rdc-frontend/nginx.conf -g "daemon off;"
ExecStartPost=/usr/bin/python3 -I -B /usr/local/lib/rdc-frontend/portable_frontend_runtime.py ready
Restart=on-failure
RestartSec=10
TimeoutStartSec=90
TimeoutStopSec=30
KillSignal=SIGQUIT
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def frontend_material(c,folder):
    folder=Path(folder);values={}
    for role,item in c['services'].items():
        cert=material(folder/(role+'.crt'));key=material(folder/(role+'.key'),private=True)
        coverage(cert,key,item['hostname'],c['certificate_days'])
        values[role+'.crt']=cert;values[role+'.key']=key
    trust=material(folder/'backend-ca.crt')
    context=__import__('ssl').create_default_context(cadata=trust.decode('ascii'))
    if not context.get_ca_certs():raise ValueError('Backend trust file must contain CA certificates')
    values['backend-ca.crt']=trust
    return values


def activate_frontend_tls(c,values,*,replace=False):
    """Durable, private generations; an interrupted renewal is resumable."""
    base=BASE/'tls';directory(base)
    digest=hashlib.sha256(b''.join(name.encode()+values[name] for name in sorted(values))).hexdigest()
    generation=base/digest;directory(generation)
    for name,raw in values.items():write(generation/name,raw)
    fd=os.open(generation,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    active=base/'active'
    old=None
    if active.is_symlink():
        old=os.readlink(active)
        if not __import__('re').fullmatch('[a-f0-9]{64}',old):raise ValueError('Unexpected frontend TLS generation')
        if old==digest:
            if replace:subprocess.run(['/bin/systemctl','restart','rdc-frontend.service'],check=True,timeout=120)
            return
        if not replace:raise ValueError('Use frontend-renew for certificate changes')
    elif active.exists():raise ValueError('Unsafe frontend TLS active path')
    temporary=base/('switch-'+secrets.token_hex(8))
    os.symlink(digest,temporary);os.replace(temporary,active)
    fd=os.open(base,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    if replace:
        try:
            subprocess.run(['/bin/systemctl','restart','rdc-frontend.service'],check=True,timeout=120)
        except BaseException:
            if old is not None:
                temporary=base/('rollback-'+secrets.token_hex(8));os.symlink(old,temporary);os.replace(temporary,active)
                fd=os.open(base,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
                subprocess.run(['/bin/systemctl','restart','rdc-frontend.service'],check=False,timeout=120)
            raise


def frontend(plan,settings,tls_dir,*,renew=False):
    require_platform();c=configuration(plan,settings)
    # Verify actual frontend placement without changing networking.
    verify_assigned(c['address'])
    for path in ('/usr/sbin/nginx','/usr/sbin/nft'):
        if not Path(path).is_file():raise ValueError('Prepare the nginx and nftables Ubuntu packages first')
    for item in c['services'].values():
        if {r[4][0] for r in socket.getaddrinfo(item['hostname'],443,type=socket.SOCK_STREAM)}!={c['address']}:raise ValueError('Local service DNS must point only to this frontend')
    values=frontend_material(c,tls_dir)
    import fcntl
    fd=os.open('/run/rdc-frontend-operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        marker=BASE/'configuration.json'
        if marker.exists() or marker.is_symlink():
            if root_json(marker)!=c:raise ValueError('Existing frontend belongs to another plan/settings; no migration was attempted')
        elif renew:raise ValueError('Install the owned frontend before renewal')
        elif any(p.exists() or p.is_symlink() for p in (BASE,INSTALLED,UNIT,Path('/var/lib/rdc-frontend'))):raise ValueError('Unowned frontend resources exist')
        if Path(str(UNIT)+'.d').exists() or Path(str(UNIT)+'.d').is_symlink():raise ValueError('Unreviewed frontend unit overrides exist')
        state=subprocess.run(['/bin/systemctl','is-active','nginx.service'],capture_output=True,timeout=15)
        if state.returncode not in (3,4):raise ValueError('Stop the stock nginx service on this dedicated VM before proceeding')
        enabled=subprocess.run(['/bin/systemctl','is-enabled','nginx.service'],capture_output=True,text=True,timeout=15)
        if enabled.stdout.strip() not in ('disabled','masked','not-found'):raise ValueError('Disable the stock nginx service so it cannot conflict at boot')
        if not marker.exists():
            listeners=subprocess.run(['/usr/bin/ss','-H','-lnt'],check=True,capture_output=True,text=True,timeout=15).stdout
            if __import__('re').search(r':443\s',listeners):raise ValueError('HTTPS port is already occupied')
        directory(BASE);write(marker,json.dumps(c,sort_keys=True)+'\n')
        directory(INSTALLED)
        hashes={}
        for name in ('portable_frontend.py','portable_frontend_runtime.py','application_access.py'):
            raw=(SOURCE/name).read_bytes();write(INSTALLED/name,raw,mode=0o644);hashes[name]=hashlib.sha256(raw).hexdigest()
        write(INSTALLED/'manifest.json',json.dumps({'schema_version':1,'files':hashes}))
        write(BASE/'nginx.conf',nginx(c));write(UNIT,frontend_unit(),mode=0o644)
        account=pwd.getpwnam('www-data')
        state=Path('/var/lib/rdc-frontend');directory(state,mode=0o750,uid=account.pw_uid,gid=account.pw_gid)
        for name in ('body','proxy'):directory(state/name,mode=0o700,uid=account.pw_uid,gid=account.pw_gid)
        activate_frontend_tls(c,values,replace=renew)
        subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)
        subprocess.run(['/bin/systemctl','enable','--now','rdc-frontend.service'],check=True,timeout=120)
        import portable_frontend_runtime as runtime
        runtime.main('ready')
    return {'state':'local-frontend-tls-verified','login_test':'not-run','offline_recovery':'not-run'}


def backend(plan,role):
    require_platform()
    if role not in ('chat','files'):raise ValueError('Choose chat or files')
    profile=profiles(plan)[role];network=portable_owner(profile)
    verify_local_address(network)
    cert=material(profile['tls_certificate']);key=material(profile['tls_private_key'],private=True)
    names=[profile[k] for k in ('matrix_hostname','element_hostname','nextcloud_hostname') if k in profile]
    for host in names:coverage(cert,key,host,plan['offline_days']+plan['certificate_margin_days'])
    if role=='chat':
        import service_operations as ops
        username=password=None
    else:
        import nextcloud_operations as ops
        import getpass
        if not (ops.runtime.BASE/'identity.json').exists():
            username=input('Initial Nextcloud administrator name: ').strip()
            password=getpass.getpass('Initial administrator password (at least 12 characters): ')
            if not __import__('re').fullmatch('[a-z][a-z0-9_-]{2,31}',username) or len(password)<12:raise ValueError('Use a valid administrator name and password')
            if password!=getpass.getpass('Repeat password: '):raise ValueError('Passwords did not match')
        else:username=password='unused'
    from service_certificates import operation_lock
    with operation_lock(lock_path=Path('/run/rdc-services-operation.lock' if role=='chat' else '/run/rdc-nextcloud-operation.lock')):
        marker=Path('/etc/server-connectivity-profile.json')
        if marker.exists() or marker.is_symlink():
            if root_json(marker)!=network:raise ValueError('This VM has another network identity; no migration was attempted')
        else:write(marker,json.dumps(network,sort_keys=True)+'\n')
        review=ops.preflight(profile)
        if role=='chat':return ops.install_or_resume(profile,network,review['address'])
        return ops.install_or_resume(profile,network,review['address'],username,password)

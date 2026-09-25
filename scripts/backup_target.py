"""Dedicated single-writer SFTP storage bound to an enrolled node's overlay address."""
import ipaddress
import json
import os
from pathlib import Path
import pwd
import subprocess
from backup_contracts import valid_host_key
from backup_operations import require_platform,root_json,private_write
from setup_contracts import validate_local_manifest,local_ownership
from local_checks import inspect_local_checks

BASE=Path('/etc/rdc-backup-target')
STORAGE=Path('/srv/rdc-backup-target')
USER='rdc-backup'
SERVICE='rdc-backup-sshd'
PORT=2222


def public_key(text):
    lines=text.strip().splitlines()
    if len(lines)!=1: raise ValueError('Provide exactly one Ed25519 public key')
    key=' '.join(lines[0].split()[:2])
    if not valid_host_key(key): raise ValueError('Invalid Ed25519 public key')
    return key


def sshd_configuration(address):
    ip=ipaddress.ip_address(address)
    if ip.version!=4 or ip not in ipaddress.ip_network('100.64.0.0/10'): raise ValueError('Storage must bind to this node overlay IPv4')
    return f'''Port {PORT}
ListenAddress {ip}
HostKey {BASE}/ssh_host_ed25519_key
PidFile /run/{SERVICE}/sshd.pid
AuthorizedKeysFile {BASE}/authorized_keys
AllowUsers {USER}
AuthenticationMethods publickey
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms ssh-ed25519
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
StrictModes yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
GatewayPorts no
ChrootDirectory {STORAGE}
ForceCommand internal-sftp -d /data
Subsystem sftp internal-sftp
LogLevel ERROR
'''


def prepare(manifest):
    require_platform()
    if validate_local_manifest(manifest): raise ValueError('Provide a local-node manifest')
    owner=root_json(Path('/etc/server-connectivity-profile.json'))
    if owner!=local_ownership(manifest): raise ValueError('Storage node ownership differs from the local manifest')
    checks=inspect_local_checks(manifest,require_owned=True,check_tls=False)
    if any(c.outcome in ('fail','unknown') for c in checks) or not any(c.code=='client.verified' and c.outcome=='pass' for c in checks):
        raise ValueError('Storage requires a verified, enrolled local node')
    status=json.loads(subprocess.run(['/usr/local/bin/tailscale','status','--json'],check=True,capture_output=True,text=True,timeout=10).stdout)
    addresses=[ip for ip in status.get('Self',{}).get('TailscaleIPs',[]) if ipaddress.ip_address(ip).version==4]
    if len(addresses)!=1: raise ValueError('Cannot establish one overlay IPv4 address')
    return provision_storage(owner,addresses[0])


def provision_storage(owner,address):
    # Caller must already validate platform, ownership and active enrollment.
    config=sshd_configuration(address)
    if BASE.exists() or BASE.is_symlink() or STORAGE.exists() or STORAGE.is_symlink() or Path('/etc/systemd/system/'+SERVICE+'.service').exists():
        raise ValueError('Existing backup storage requires review; prepare never replaces it')
    try: pwd.getpwnam(USER)
    except KeyError: pass
    else: raise ValueError('Reserved backup account already exists; migration must be reviewed')
    if not Path('/usr/sbin/sshd').exists():
        policy=Path('/usr/sbin/policy-rc.d')
        if policy.exists() or policy.is_symlink(): raise ValueError('An existing service-start policy requires operator package preparation')
        private_write(policy,'#!/bin/sh\nexit 101\n');policy.chmod(0o755)
        try:
            subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,timeout=300,stdout=subprocess.DEVNULL)
            subprocess.run(['/usr/bin/apt-get','install','-y','-qq','openssh-server'],check=True,timeout=300,stdout=subprocess.DEVNULL)
        finally: policy.unlink()
    BASE.mkdir(mode=0o755);STORAGE.mkdir(mode=0o755)
    subprocess.run(['/usr/sbin/useradd','--system','--no-create-home','--home-dir','/data','--shell','/usr/sbin/nologin','--password','*',USER],check=True,timeout=30)
    account=pwd.getpwnam(USER);data=STORAGE/'data';data.mkdir(mode=0o700);os.chown(data,account.pw_uid,account.pw_gid)
    subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','rdc-backup-target','-f',str(BASE/'ssh_host_ed25519_key')],check=True,timeout=30)
    private_write(BASE/'authorized_keys','')
    (BASE/'authorized_keys').chmod(0o644)
    private_write(BASE/'sshd_config',config)
    private_write(BASE/'ownership.json',json.dumps({'schema_version':1,'ownership':owner,'address':address}))
    subprocess.run(['/usr/sbin/sshd','-t','-f',str(BASE/'sshd_config')],check=True,timeout=15)
    unit='''[Unit]
Description=Dedicated encrypted-backup SFTP storage over the private overlay
After=tailscaled.service
Requires=tailscaled.service
PartOf=tailscaled.service
StartLimitIntervalSec=0
[Service]
ExecStart=/usr/sbin/sshd -D -f /etc/rdc-backup-target/sshd_config
RuntimeDirectory=rdc-backup-sshd
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/rdc-backup-target/data /run/rdc-backup-sshd
[Install]
WantedBy=multi-user.target tailscaled.service
'''
    private_write(Path('/etc/systemd/system/'+SERVICE+'.service'),unit)
    subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)
    subprocess.run(['/bin/systemctl','enable','--now',SERVICE],check=True,timeout=30)
    key=public_key((BASE/'ssh_host_ed25519_key.pub').read_text())
    return {'state':'storage-prepared-no-writer-authorized','backup_host':address,'backup_port':PORT,'backup_host_key':key,
            'network_access':'controller administrator must separately permit the intended writer to this node TCP 2222'}


def authorize(key_path):
    require_platform();owner=root_json(Path('/etc/server-connectivity-profile.json'));state=root_json(BASE/'ownership.json')
    if state.get('schema_version')!=1 or state.get('ownership')!=owner: raise ValueError('Backup storage ownership mismatch')
    key=public_key(Path(key_path).read_text())
    existing=BASE/'authorized_keys';info=existing.lstat()
    if info.st_uid!=0 or info.st_mode & 0o022 or existing.is_symlink(): raise ValueError('Unsafe backup authorization file')
    if existing.read_text(): raise ValueError('One writer is already authorized; replacement or additional access needs explicit review')
    new=BASE/'authorized_keys.new';private_write(new,'restrict '+key+'\n');new.chmod(0o644);os.replace(new,existing)
    return {'state':'writer-authorized','scope':'SFTP files in the dedicated encrypted-backup storage only'}

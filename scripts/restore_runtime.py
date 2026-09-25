"""Linux service isolation for explicitly fenced recovery; never alters other firewall tables."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from backup_contracts import resources
from backup_snapshot import Services
from backup_operations import root_json

PENDING=Path('/etc/rdc-restore-pending.json')
UPGRADE_PENDING=Path('/etc/rdc-upgrade-pending.json')
ISOLATION=Path('/etc/rdc-restore-isolation.json')
PERMIT=Path('/run/rdc-restore-validation')
GUARD=Path('/usr/local/sbin/rdc-restore-guard')
TIMER='rdc-certificate-renew.timer'


def guard_script(pending=PENDING,permit=PERMIT,*,upgrade=UPGRADE_PENDING):
    original='#!/bin/sh\nset -eu\nif [ -e '+shlex.quote(str(pending))+' ] && [ ! -f '+shlex.quote(str(permit))+' ]; then\n  echo "A pending RDC restore blocks automatic startup; use restore-recover." >&2\n  exit 1\nfi\n'
    if upgrade is None:return original
    return original+'if [ -e '+shlex.quote(str(upgrade))+' ] && [ ! -f '+shlex.quote(str(permit))+' ]; then\n  echo "A pending RDC upgrade blocks automatic startup; use upgrade recover." >&2\n  exit 1\nfi\n'


def guard_files(owner):
    names=[n for n in resources(owner).services if not n.endswith('.timer')]
    if 'rdc-nextcloud-cron.timer' in resources(owner).services:names.append('rdc-nextcloud-cron')
    if owner.get('tls_mode')=='managed-acme': names.append('rdc-certificate-renew')
    return {GUARD:(guard_script(),0o755),**{Path('/etc/systemd/system')/(n+'.service.d')/'20-rdc-restore-guard.conf':
            ('[Service]\nExecStartPre='+str(GUARD)+'\n',0o644) for n in names}}


def check_guard(path,content):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or path.read_text()!=content:
        raise ValueError('Restore startup guard differs from the owned installation')


def install_guards(owner,*,upgrade_compat=False):
    entries=guard_files(owner)
    replace_guard=False
    for path,(content,mode) in entries.items():
        if path.exists() or path.is_symlink():
            if path==GUARD and upgrade_compat and path.read_text()==guard_script(upgrade=None):
                check_guard(path,guard_script(upgrade=None));replace_guard=True
            else:check_guard(path,content)
        if path.parent.is_symlink(): raise ValueError('Linked service drop-in directory is unsupported')
    for path,(content,mode) in entries.items():
        if path==GUARD and replace_guard:
            import tempfile
            fd,temporary=tempfile.mkstemp(prefix='.rdc-guard-',dir=path.parent)
            try:
                with os.fdopen(fd,'w') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
                os.chmod(temporary,mode);os.replace(temporary,path)
            finally:
                if os.path.exists(temporary):os.unlink(temporary)
            continue
        if path.exists(): continue
        path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'w') as stream: stream.write(content)
    subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)


def isolation_rules(role,identifier):
    if role not in ('controller','relay','peer','portable') or not re.fullmatch('[a-f0-9]{32}',identifier): raise ValueError('Invalid restore isolation identity')
    rules=['iifname "lo" accept']
    if role in ('peer','portable'):
        if role=='peer':rules.append('iifname "tailscale0" drop')
        rules.append('tcp dport { 443, 8443, 3128 } drop')
    else:
        rules.append('tcp dport 443 drop')
        if role=='relay': rules.append('udp dport 3478 drop')
    # Explicit commands in one atomic nft batch. On Ubuntu's nft version,
    # `create table` with nested chains creates only the table itself.
    commands=['create table inet rdc_restore { comment "rdc-restore:'+identifier+'"; }',
              'add chain inet rdc_restore input { type filter hook input priority -200; policy accept; }',
              'add chain inet rdc_restore forward { type filter hook forward priority -200; policy accept; }']
    commands+=['add rule inet rdc_restore input '+rule for rule in rules]
    if role=='peer': commands.append('add rule inet rdc_restore forward iifname "tailscale0" drop')
    return '\n'.join(commands)+'\n'


def rules_digest(data,identifier):
    entries=data.get('nftables',[])
    tables=[e['table'] for e in entries if 'table' in e]
    if len(tables)!=1 or tables[0].get('comment')!='rdc-restore:'+identifier or tables[0].get('name')!='rdc_restore' or tables[0].get('family')!='inet':
        raise ValueError('Reserved restore firewall table is not owned by this transaction')
    def normalize(value):
        if isinstance(value,dict): return {k:normalize(v) for k,v in value.items() if k!='handle'}
        if isinstance(value,list): return [normalize(v) for v in value]
        return value
    contents=[normalize(e) for e in entries if 'metainfo' not in e]
    return hashlib.sha256(json.dumps(contents,sort_keys=True).encode()).hexdigest()


def verify_peer(manifest,*,attempts=30,pause=time.sleep):
    from local_checks import inspect_local_checks
    deadline=time.monotonic()+45
    transient={'client.stopped','client.inspect_denied','client.awaiting_enrollment','client.unavailable'}
    for attempt in range(attempts):
        checks=inspect_local_checks(manifest,require_owned=True,check_tls=False)
        if checks and all(c.outcome=='pass' for c in checks) and any(c.code=='client.verified' for c in checks):return
        failures={c.code for c in checks if c.outcome!='pass'}
        if not failures or not failures<=transient or time.monotonic()>=deadline or attempt==attempts-1:break
        # A systemd start does not mean the daemon has loaded its restored
        # identity and preferences. Keep ingress isolated while it becomes ready.
        pause(1)
    raise ValueError('Restored networking identity could not be verified')


class Runtime(Services):
    def prepare_restored_application(self,owner):
        from backup_scope import package
        if owner!=self.owner or 'applications' not in owner or package(owner['applications'])!='matrix':
            raise ValueError('Unexpected restored application identity')
        if self.is_active('rdc-synapse'):raise ValueError('Restored one-time keys must be cleared before Synapse starts')
        import service_runtime
        settings=service_runtime.read_settings()
        if settings['ownership']!=owner['applications']:raise ValueError('Restored Matrix ownership changed')
        service_runtime.ready('postgres',settings,attempts=1)
        # A physical database backup also contains keys used after its capture.
        # Never issue those keys again. Device keys and encrypted key backups
        # remain intact; clients upload fresh one-time keys after recovery.
        service_runtime.podman('exec','--user','999:999',service_runtime.UNITS['postgres'],
            'psql','-X','-v','ON_ERROR_STOP=1','-U','synapse','-d','synapse','-p','5433',
            '-c','TRUNCATE TABLE e2e_one_time_keys_json;',timeout=30)

    def close_gateway(self):
        import gateway_runtime
        from gateway_store import Store
        gateway_runtime.Runtime(Store(gateway_runtime.BASE)).close()

    def __init__(self,owner,*,pending=PENDING):
        if pending not in (PENDING,UPGRADE_PENDING):raise ValueError('Unknown maintenance marker')
        self.pending=pending
        self.owner=owner;self.lock=None;self.timer_active=False;self.prepared=False;self.identifier=None
    def nft(self,*args,input=None):
        result=subprocess.run(['/usr/sbin/nft',*args],input=input,capture_output=True,text=True,timeout=15)
        if result.returncode: raise ValueError('Restore firewall operation failed; inspect local administration logs')
        return json.loads(result.stdout) if '-j' in args else None
    def table(self):
        data=self.nft('-j','list','tables')
        if any(e.get('table',{}).get('family')=='inet' and e['table'].get('name')=='rdc_restore' for e in data['nftables']):
            return self.nft('-j','list','table','inet','rdc_restore')
        return None
    def prepare(self,owner,*,state=None):
        if owner!=self.owner: raise ValueError('Restore runtime ownership differs')
        if not Path('/usr/sbin/nft').is_file(): raise ValueError('Install the Ubuntu nftables package before recovery; do not enable or replace a firewall configuration')
        for path,(content,mode) in guard_files(owner).items(): check_guard(path,content)
        if state is not None and (not isinstance(state,dict) or set(state)!={'certificate_timer_active'} or type(state['certificate_timer_active']) is not bool):
            raise ValueError('Invalid saved restore runtime state')
        if state is None and (self.table() is not None or ISOLATION.exists() or ISOLATION.is_symlink()): raise ValueError('An existing restore isolation needs investigation')
        managed=owner.get('tls_mode')=='managed-acme'
        self.timer_active=(state['certificate_timer_active'] if state else self.is_active(TIMER)) if managed else False
        if managed:
            self.stop(TIMER)
            try:
                fd=os.open('/etc/rdc-tls/lock',os.O_RDWR|os.O_NOFOLLOW)
                self.lock=os.fdopen(fd,'a');fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BaseException:
                if self.lock: self.lock.close();self.lock=None
                if self.timer_active: self.start(TIMER)
                raise
        self.prepared=True
        return {'certificate_timer_active':self.timer_active}
    def isolate(self,owner):
        from restore_transaction import atomic_json
        marker=root_json(self.pending);identifier=marker.get('transaction_id')
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier): raise ValueError('Missing restore transaction identity')
        self.identifier=identifier
        record=None
        if ISOLATION.exists() or ISOLATION.is_symlink():
            record=root_json(ISOLATION)
            if set(record)!={'schema_version','transaction_id','role','digest'} or record['schema_version']!=1 or record['transaction_id']!=identifier or record['role']!=owner['role']:
                raise ValueError('Restore isolation belongs to another transaction')
        current=self.table()
        if current is not None:
            digest=rules_digest(current,identifier)
            if record is None or (record['digest'] is not None and digest!=record['digest']): raise ValueError('Restore firewall rules changed; automatic recovery is blocked')
        else:
            record={'schema_version':1,'transaction_id':identifier,'role':owner['role'],'digest':None}
            atomic_json(ISOLATION,record)
            self.nft('-f','-',input=isolation_rules(owner['role'],identifier))
            current=self.table()
            digest=rules_digest(current,identifier)
        chains=[e['chain']['name'] for e in current['nftables'] if 'chain' in e]
        rules=[e['rule'] for e in current['nftables'] if 'rule' in e]
        if sorted(chains)!=['forward','input'] or len(rules)!={'controller':2,'relay':3,'peer':4,'portable':2}[owner['role']]:
            raise ValueError('Recovery ingress rules were not installed completely')
        record['digest']=digest;atomic_json(ISOLATION,record)
    def allow_validation(self):
        if PERMIT.exists() or PERMIT.is_symlink():
            info=PERMIT.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077: raise ValueError('Unsafe restore validation permit')
            return
        fd=os.open(PERMIT,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
    def finish_validation(self):
        if PERMIT.is_symlink(): raise ValueError('Unsafe restore validation permit')
        PERMIT.unlink(missing_ok=True)
    def release(self):
        if self.identifier:
            current=self.table()
            if current is not None:
                record=root_json(ISOLATION)
                if record.get('transaction_id')!=self.identifier or rules_digest(current,self.identifier)!=record.get('digest'):
                    raise ValueError('Restore isolation changed; automatic removal blocked')
                self.nft('delete','table','inet','rdc_restore')
            ISOLATION.unlink(missing_ok=True)
        if self.lock: self.lock.close();self.lock=None
        if self.prepared and self.timer_active: self.start(TIMER)
        self.prepared=False
    def verify(self,owner):
        if not all(self.is_active(n) for n in resources(owner).services): raise ValueError('Restored service did not stay active')
        if owner['role'] in ('peer','portable'):
            manifest={'kind':'local-node','schema_version':1,'institution_id':owner['institution_id'],'node_name':owner['node_name'],
                      'headscale_hostname':owner.get('controller_hostname'),'node_tag':owner.get('node_tag')}
            if owner['role']=='peer':verify_peer(manifest)
            else:
                from application_access import verify_local_address
                verify_local_address(owner)
            if 'applications' in owner:
                from backup_scope import application_runtime
                runtime=application_runtime(owner['applications']);settings=runtime.read_settings()
                for name in reversed(list(runtime.UNITS)):runtime.ready(name,settings)
        else:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from certificate_lifecycle import Runtime as TLSRuntime
            if owner.get('tls_mode')=='managed-acme': cert=Path('/etc/rdc-tls/active/tls.crt');hostname=owner['certificate_hostname']
            elif owner['role']=='controller': cert=Path('/etc/headscale/tls.crt');hostname=owner['controller_hostname']
            else:
                certs=list(Path('/etc/sc-derp').glob('*.crt'))
                if len(certs)!=1: raise ValueError('Cannot determine the supplied relay certificate')
                cert=certs[0];hostname=cert.stem
            fingerprint=x509.load_pem_x509_certificate(cert.read_bytes()).fingerprint(hashes.SHA256()).hex()
            TLSRuntime().verify(hostname,fingerprint)
            if owner['role']=='controller':
                import sqlite3
                with sqlite3.connect('file:/var/lib/headscale/db.sqlite?mode=ro',uri=True,timeout=5) as db:
                    if db.execute('PRAGMA quick_check').fetchall()!=[('ok',)]: raise ValueError('Restored controller database integrity check failed')

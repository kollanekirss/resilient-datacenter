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
from backup_contracts import resources
from backup_snapshot import Services
from backup_operations import root_json

PENDING=Path('/etc/rdc-restore-pending.json')
ISOLATION=Path('/etc/rdc-restore-isolation.json')
PERMIT=Path('/run/rdc-restore-validation')
GUARD=Path('/usr/local/sbin/rdc-restore-guard')
TIMER='rdc-certificate-renew.timer'


def guard_script(pending=PENDING,permit=PERMIT):
    return '#!/bin/sh\nset -eu\nif [ -e '+shlex.quote(str(pending))+' ] && [ ! -f '+shlex.quote(str(permit))+' ]; then\n  echo "A pending RDC restore blocks automatic startup; use restore-recover." >&2\n  exit 1\nfi\n'


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


def install_guards(owner):
    entries=guard_files(owner)
    for path,(content,mode) in entries.items():
        if path.exists() or path.is_symlink(): check_guard(path,content)
        if path.parent.is_symlink(): raise ValueError('Linked service drop-in directory is unsupported')
    for path,(content,mode) in entries.items():
        if path.exists(): continue
        path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'w') as stream: stream.write(content)
    subprocess.run(['/bin/systemctl','daemon-reload'],check=True,timeout=30)


def isolation_rules(role,identifier):
    if role not in ('controller','relay','peer') or not re.fullmatch('[a-f0-9]{32}',identifier): raise ValueError('Invalid restore isolation identity')
    rules=['iifname "lo" accept']
    if role=='peer': rules.append('iifname "tailscale0" drop')
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


class Runtime(Services):
    def close_gateway(self):
        import gateway_runtime
        from gateway_store import Store
        gateway_runtime.Runtime(Store(gateway_runtime.BASE)).close()

    def __init__(self,owner):
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
        marker=root_json(PENDING);identifier=marker.get('transaction_id')
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
        if sorted(chains)!=['forward','input'] or len(rules)!=(2 if owner['role']=='controller' else 3):
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
        if owner['role']=='peer':
            from local_checks import inspect_local_checks
            manifest={'kind':'local-node','schema_version':1,'institution_id':owner['institution_id'],'node_name':owner['node_name'],
                      'headscale_hostname':owner['controller_hostname'],'node_tag':owner['node_tag']}
            checks=inspect_local_checks(manifest,require_owned=True,check_tls=False)
            if any(c.outcome!='pass' for c in checks) or not any(c.code=='client.verified' for c in checks): raise ValueError('Restored networking identity could not be verified')
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

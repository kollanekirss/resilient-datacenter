#!/usr/bin/python3
"""Root-only managed TLS activation; fixed service names and paths, no issuer overrides."""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

BASE=Path('/etc/rdc-tls')
LINEAGE=Path('/etc/letsencrypt/live/rdc-managed')
SERVICES={'gateway':('rdc-regional-gateway','root'),'controller':('headscale','headscale'),'relay':('sc-derp','sc-derp'),'services':('rdc-service-proxy','root'),'nextcloud':('rdc-nextcloud-proxy','root')}

class ActivationError(ValueError):
    def __init__(self,recovered):
        super().__init__('Certificate activation failed; previous certificate recovery '+('verified.' if recovered else 'NOT verified.'))
        self.recovered=recovered


def validity(cert,which):
    modern=getattr(cert,'not_valid_'+which+'_utc',None)
    return modern if modern is not None else getattr(cert,'not_valid_'+which).replace(tzinfo=timezone.utc)


def validate_material(cert,key,hostname,*,verify_at=None):
    chain=x509.load_pem_x509_certificates(cert)
    if not chain: raise ValueError('Empty certificate chain')
    leaf=chain[0]; private=serialization.load_pem_private_key(key,password=None)
    now=datetime.now(timezone.utc)
    before=validity(leaf,'before')
    after=validity(leaf,'after')
    if before>now or after<now+timedelta(days=7): raise ValueError('Certificate validity is unsuitable')
    encoding=serialization.Encoding.DER; form=serialization.PublicFormat.SubjectPublicKeyInfo
    if leaf.public_key().public_bytes(encoding,form)!=private.public_key().public_bytes(encoding,form):
        raise ValueError('Private key does not match certificate')
    names=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if hostname not in names: raise ValueError('Certificate does not name this server')
    with tempfile.TemporaryDirectory(prefix='rdc-tls-validation-') as directory:
        folder=Path(directory)
        (folder/'leaf.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (folder/'chain.pem').write_bytes(b''.join(c.public_bytes(serialization.Encoding.PEM) for c in chain[1:]))
        argv=['/usr/bin/openssl','verify','-purpose','sslserver','-verify_hostname',hostname,'-CApath','/etc/ssl/certs']
        if len(chain)>1: argv+=['-untrusted',str(folder/'chain.pem')]
        argv.append(str(folder/'leaf.pem'))
        subprocess.run(argv,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        if verify_at is not None:
            # Validate the entire selected trust path at the offline horizon.
            subprocess.run(argv[:2]+['-attime',str(int(verify_at.timestamp()))]+argv[2:],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    return {'fingerprint':leaf.fingerprint(hashes.SHA256()).hex(),'expires_at':after.isoformat()}


class Runtime:
    def restart(self,service):
        subprocess.run(['/bin/systemctl','restart',service],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def verify(self,hostname,fingerprint):
        for attempt in range(6):
            try:
                context=ssl.create_default_context()
                with socket.create_connection(('127.0.0.1',443),timeout=3) as raw:
                    with context.wrap_socket(raw,server_hostname=hostname) as secure:
                        if hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()!=fingerprint:
                            raise ValueError('Service is not serving the selected certificate')
                return
            except (OSError,ValueError):
                if attempt==5: raise
                time.sleep(1)


def generation(base,name):
    path=base/name
    if not path.exists() and not path.is_symlink(): return None
    if not path.is_symlink(): raise ValueError('Managed certificate pointer is not a symlink')
    target=path.readlink()
    if not re.fullmatch(r'generations/[a-f0-9]{64}',str(target)): raise ValueError('Unsafe certificate generation pointer')
    if (base/target).is_symlink() or not (base/target).is_dir(): raise ValueError('Missing or unsafe certificate generation')
    return target


def point(base,name,target):
    path=base/(name+'.new')
    if path.exists() or path.is_symlink(): raise ValueError('Stale certificate transaction; inspect it before retrying')
    path.symlink_to(target)
    os.replace(path,base/name)


def activate(base,hostname,role,cert,key,*,gid,validator=validate_material,runtime=None,initial=False):
    runtime=runtime or Runtime()
    if role not in SERVICES: raise ValueError('Unsupported managed certificate role')
    previous=generation(base,'active')
    if previous is None and not initial: raise ValueError('No managed certificate exists; use initial deployment')
    info=validator(cert,key,hostname)
    digest=hashlib.sha256(cert+key).hexdigest()
    target=Path('generations')/digest
    if previous==target:
        if not initial:
            try: runtime.verify(hostname,info['fingerprint'])
            except (OSError,ValueError):
                runtime.restart(SERVICES[role][0]); runtime.verify(hostname,info['fingerprint'])
        return dict(info,state='staged' if initial else 'active')
    generations=base/'generations'
    if generations.is_symlink(): raise ValueError('Unsafe generation directory')
    generations.mkdir(mode=0o750,exist_ok=True); os.chown(generations,-1,gid)
    candidate=base/target
    if candidate.exists() or candidate.is_symlink():
        # Never trust stale generation bytes simply because their directory is named by a hash.
        if candidate.is_symlink() or any((candidate/n).is_symlink() for n in ('tls.crt','tls.key')):
            raise ValueError('Unsafe existing generation')
        if (candidate/'tls.crt').read_bytes()!=cert or (candidate/'tls.key').read_bytes()!=key:
            raise ValueError('Existing generation differs from certificate input')
    else:
        candidate.mkdir(mode=0o750); os.chown(candidate,-1,gid)
        (candidate/'metadata.json').write_text(json.dumps(info))
        (candidate/'metadata.json').chmod(0o640); os.chown(candidate/'metadata.json',-1,gid)
        for name,content in {'tls.crt':cert,'tls.key':key,hostname+'.crt':cert,hostname+'.key':key}.items():
            path=candidate/name
            with path.open('xb') as stream: stream.write(content)
            path.chmod(0o640); os.chown(path,-1,gid)
    old_info=json.loads((base/previous/'metadata.json').read_text()) if previous else None
    point(base,'active',target)
    if initial and previous is None: return dict(info,state='staged')
    try:
        runtime.restart(SERVICES[role][0]); runtime.verify(hostname,info['fingerprint'])
    except (OSError,ValueError,subprocess.SubprocessError):
        recovered=False
        if previous:
            point(base,'active',previous)
            try:
                runtime.restart(SERVICES[role][0]); runtime.verify(hostname,old_info['fingerprint']); recovered=True
            except (OSError,ValueError,subprocess.SubprocessError): pass
        raise ActivationError(recovered) from None
    if previous: point(base,'previous',previous)
    keep={target,previous}
    for path in generations.iterdir():
        if Path('generations')/path.name not in keep and re.fullmatch('[a-f0-9]{64}',path.name) and path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    return dict(info,state='active')


def root_file(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise ValueError('Certificate administration files must be root-owned and not writable by other users')
    return json.loads(path.read_text())


def configuration():
    if os.geteuid()!=0: raise ValueError('Run certificate administration through sudo on its managed server')
    data=root_file(BASE/'config.json')
    if set(data)!={'schema_version','hostname','role','institution_id','controller_hostname'} or data['schema_version']!=1 or data['role'] not in SERVICES:
        raise ValueError('Invalid managed certificate configuration')
    if not isinstance(data['hostname'],str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]',data['hostname']):
        raise ValueError('Invalid managed certificate hostname')
    owner=root_file(Path('/etc/server-connectivity-profile.json'))
    expected={'schema_version':3,'deployment_mode':'independent','institution_id':data['institution_id'],
              'role':data['role'],'controller_hostname':data['controller_hostname'],'tls_mode':'managed-acme','certificate_hostname':data['hostname']}
    if owner!=expected: raise ValueError('Certificate ownership does not match this installation')
    return data


def record(data):
    data=dict(data,checked_at=datetime.now(timezone.utc).isoformat())
    path=BASE/'status.new'
    with path.open('w') as stream: json.dump(data,stream)
    path.chmod(0o640); os.replace(path,BASE/'status.json')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('stage','activate','renew','status'))
    args=parser.parse_args(argv)
    data=None
    try:
        data=configuration()
        if args.action=='status':
            current=root_file(BASE/'status.json')
            pointer=generation(BASE,'active')
            cert=x509.load_pem_x509_certificate((BASE/pointer/'tls.crt').read_bytes()) if pointer else None
            current['currently_expired']=cert is None or validity(cert,'after')<=datetime.now(timezone.utc)
            current['expires_within_14_days']=cert is None or validity(cert,'after')<=datetime.now(timezone.utc)+timedelta(days=14)
            try:
                if cert is None: raise ValueError('No active certificate')
                Runtime().verify(data['hostname'],cert.fingerprint(hashes.SHA256()).hex())
                current['serving_certificate_verified']=True
            except (OSError,ValueError): current['serving_certificate_verified']=False
            print(json.dumps(current,indent=2)); return 0 if current.get('state')=='active' and not current['expires_within_14_days'] and current['serving_certificate_verified'] else 1
        with (BASE/'lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:
                if args.action=='renew':
                    subprocess.run(['/usr/bin/certbot','renew','--cert-name','rdc-managed','--non-interactive','--no-directory-hooks'],check=True,timeout=600)
                info=activate(BASE,data['hostname'],data['role'],(LINEAGE/'fullchain.pem').read_bytes(),(LINEAGE/'privkey.pem').read_bytes(),
                              gid=grp.getgrnam(SERVICES[data['role']][1]).gr_gid,initial=args.action=='stage')
                record(info)
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                record({'state':'failed','previous_certificate_recovered':error.recovered if isinstance(error,ActivationError) else None,
                        'next_step':'Inspect rdc-certificate-renew.service logs and the currently served certificate.'})
                raise
        print('Managed certificate '+info['state']+'.'); return 0
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print('Certificate action failed. Existing identity was preserved; inspect the service and certificate status.'); return 1

if __name__=='__main__': raise SystemExit(main())

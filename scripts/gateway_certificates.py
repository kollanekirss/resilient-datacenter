"""Verified gateway TLS changes with durable closed-on-interruption intent."""
import hashlib
import json
import os
import socket
import ssl
import time
from certificate_lifecycle import activate,validate_material,ActivationError,generation
from regional_workspace import private_read,private_write
from gateway_store import decode

MARKER='certificate-pending.json'


def pending(store):
    path=store.base/MARKER
    if not (path.exists() or path.is_symlink()):return None
    value=decode(private_read(path))
    if not isinstance(value,dict) or set(value)!={'schema_version','material_digest'} or type(value['schema_version']) is not int or value['schema_version']!=1:
        raise ValueError('Invalid pending gateway certificate intent')
    digest=value['material_digest']
    if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise ValueError('Invalid pending gateway certificate digest')
    return value


def clear(store):
    pending(store)  # Reject unsafe or unowned marker before removal.
    (store.base/MARKER).unlink()
    descriptor=os.open(store.base,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


class Runtime:
    def __init__(self,store):self.store=store
    def close(self):
        from gateway_runtime import Runtime as Gateway
        Gateway(self.store).close()
    def restart(self,service):
        from gateway_runtime import Runtime as Gateway
        Gateway(self.store).restart()
    def verify(self,hostname,fingerprint):
        for attempt in range(6):
            try:
                with socket.create_connection(('127.0.0.1',9443),timeout=3) as connection:
                    with ssl.create_default_context().wrap_socket(connection,server_hostname=hostname) as secure:
                        if hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()!=fingerprint:raise ValueError('Gateway is not serving the selected certificate')
                return
            except (OSError,ValueError):
                if attempt==5:raise
                time.sleep(1)
    def reopen(self):
        from gateway_runtime import Runtime as Gateway
        Gateway(self.store).open(self.store.state())


def activate_certificate(store,cert,key,*,initial=False,validator=validate_material,runtime=None,gid=0):
    """Caller holds ordered backup/gateway locks; never edits partner policy."""
    store.check();store.state()
    if store.pending():raise ValueError('Complete the pending gateway policy change before changing its certificate')
    names=sorted(store.identity()['payload']['services'].values())
    runtime=runtime or Runtime(store)
    def all_names(chain,private,unused):
        results=[validator(chain,private,name) for name in names]
        if len({item['fingerprint'] for item in results})!=1:raise ValueError('Gateway certificate identities differ')
        return results[0]
    all_names(cert,key,names[0])  # Bad input must not close a working gateway.
    directory=store.base/'tls'
    if directory.is_symlink():raise ValueError('Unsafe gateway TLS directory')
    directory.mkdir(mode=0o700,exist_ok=True)
    class EveryName:
        def restart(self,service):runtime.restart(service)
        def verify(self,unused,fingerprint):
            for name in names:runtime.verify(name,fingerprint)
    def perform():
        return activate(directory,names[0],'gateway',cert,key,gid=gid,validator=all_names,runtime=EveryName(),initial=initial)
    if initial:
        current=generation(directory,'active')
        if current is not None and ((directory/current/'tls.crt').read_bytes()!=cert or (directory/current/'tls.key').read_bytes()!=key):raise ValueError('Use explicit gateway certificate replacement for existing material')
        if pending(store):raise ValueError('Resume the pending certificate transaction before installation')
        return perform()
    intent={'schema_version':1,'material_digest':hashlib.sha256(cert+key).hexdigest()}
    previous=pending(store)
    if previous is not None and previous!=intent:raise ValueError('Resume the same pending gateway certificate before selecting another')
    private_write(store.base/MARKER,json.dumps(intent).encode(),replace=True)
    try:
        runtime.close()
        try:result=perform()
        except ActivationError as error:
            if error.recovered:
                clear(store);runtime.reopen()
            raise
        clear(store);runtime.reopen()
        return result
    except ActivationError as error:
        if error.recovered and pending(store) is None:raise
        private_write(store.base/MARKER,json.dumps(intent).encode(),replace=True)
        runtime.close();raise
    except BaseException:
        private_write(store.base/MARKER,json.dumps(intent).encode(),replace=True)
        runtime.close();raise


def managed_material(store):
    from pathlib import Path
    import stat
    directory=store.base/'tls'
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe managed gateway TLS directory')
    current=generation(directory,'active')
    if current is None:raise ValueError('Gateway TLS has not been staged')
    contents=[]
    for name in ('tls.crt','tls.key'):
        path=directory/current/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022 or info.st_size>262144:raise ValueError('Unsafe managed gateway certificate file')
        if name=='tls.key' and info.st_mode&0o007:raise ValueError('Gateway certificate key is publicly readable')
        contents.append(path.read_bytes())
    return tuple(contents)


def replace(certificate,private_key):
    from contextlib import ExitStack
    import fcntl
    from pathlib import Path
    from backup_operations import require_platform
    import gateway_runtime as gateway
    from gateway_operations import tls_inputs
    from gateway_store import Store
    require_platform();gateway.verify_runtime();store=Store(gateway.BASE)
    with ExitStack() as stack:
        backup=Path('/etc/rdc-backup')
        if backup.exists():
            fd=os.open(backup/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            stream=stack.enter_context(os.fdopen(fd,'a'));fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        stack.enter_context(store.lock(wait_seconds=10))
        if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Complete fenced recovery before changing gateway certificates')
        profile=dict(store.profile(),tls_certificate=str(certificate),tls_private_key=str(private_key))
        cert,key=tls_inputs(profile,store.identity())
        return activate_certificate(store,cert,key)


def status(store):
    from datetime import datetime,timedelta,timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from certificate_lifecycle import validity
    cert,key=managed_material(store)
    leaf=x509.load_pem_x509_certificate(cert);expiry=validity(leaf,'after');fingerprint=leaf.fingerprint(hashes.SHA256()).hex()
    verified=True
    try:
        for name in sorted(store.identity()['payload']['services'].values()):Runtime(store).verify(name,fingerprint)
    except (OSError,ValueError):verified=False
    intent=pending(store)
    return {'state':'gateway-certificate-pending' if intent else 'gateway-certificate-configured',
            'expires_at':expiry.isoformat(),'expires_within_14_days':expiry<=datetime.now(timezone.utc)+timedelta(days=14),
            'serving_certificate_verified':verified,'fingerprint':fingerprint,'renewal_status_command':'rdc gateway issuer status',
            'next_step':'Resume the exact pending certificate replacement.' if intent else 'Inspect gateway issuer status to verify automatic renewal.'}

"""Capture owned persistent resources while relevant services are quiescent."""
from datetime import datetime,timezone
import json
import hashlib
import fcntl
from contextlib import contextmanager,nullcontext
import os
from pathlib import Path
import posixpath
import shutil
import stat
import subprocess
from backup_contracts import resources,binary_paths

class ServiceRecoveryError(OSError): pass


class Services:
    def is_active(self,name):
        result=subprocess.run(['/bin/systemctl','is-active',name],capture_output=True,text=True,timeout=15)
        if result.returncode not in (0,3) or result.stdout.strip() not in ('active','inactive','failed'): raise ValueError('Cannot determine managed service state')
        return result.returncode==0
    def verify_binary(self,name,expected):
        result=subprocess.run(['/bin/systemctl','show','--property=MainPID','--value',name],check=True,capture_output=True,text=True,timeout=15)
        pid=result.stdout.strip()
        if not pid.isdigit() or int(pid)<=0: raise ValueError('Cannot establish the running service executable')
        with (Path('/proc')/pid/'exe').open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=expected: raise ValueError('Running service differs from its installed binary; resolve the pending upgrade before snapshotting')
    def stop(self,name): subprocess.run(['/bin/systemctl','stop',name],check=True,timeout=60)
    def start(self,name): subprocess.run(['/bin/systemctl','start',name],check=True,timeout=60)


def copy_resource(source,destination):
    if source.is_dir(): shutil.copytree(source,destination,symlinks=True)
    else:
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,destination,follow_symlinks=False)
    # copy2 preserves modes/time, not owner. Preserve original numeric ownership
    # in staging so the encrypted snapshot contains the actual source metadata.
    entries=[source]+(list(source.rglob('*')) if source.is_dir() else [])
    for path in entries:
        target=destination/path.relative_to(source) if path!=source else destination
        original=path.lstat(); copied=target.lstat()
        if (original.st_uid,original.st_gid)!=(copied.st_uid,copied.st_gid):
            os.chown(target,original.st_uid,original.st_gid,follow_symlinks=False)


def inspect_resources(root,paths):
    size=0
    def allowed(path): return any(path==p or path.startswith(p+'/') for p in paths)
    for name in paths:
        source=root/name
        if not source.exists() or source.is_symlink(): raise ValueError('A required persistent resource is missing or linked')
        for parent in source.parents:
            if parent==root: break
            if parent.is_symlink(): raise ValueError('Persistent resource parent is linked')
        entries=[source]+(list(source.rglob('*')) if source.is_dir() else [])
        for path in entries:
            info=path.lstat()
            if stat.S_ISREG(info.st_mode): size+=info.st_size
            elif stat.S_ISLNK(info.st_mode):
                link=str(path.readlink())
                resolved=posixpath.normpath(link.lstrip('/') if link.startswith('/') else str(path.relative_to(root).parent/ link))
                if not allowed(resolved): raise ValueError('Persistent data contains a link outside the backup catalogue')
            elif not stat.S_ISDIR(info.st_mode): raise ValueError('Persistent data contains an unsupported special file')
    return size


@contextmanager
def certificate_lock(root):
    path=Path(root)/'etc/rdc-tls/lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def capture(root,destination,owner,*,services=None):
    try: actual=json.loads((Path(root)/'etc/server-connectivity-profile.json').read_text())
    except (OSError,ValueError): raise ValueError('Cannot verify snapshot ownership') from None
    if actual!=owner: raise ValueError('Snapshot ownership differs from the installed role')
    with certificate_lock(root) if owner.get('tls_mode')=='managed-acme' else nullcontext():
        return _capture(root,destination,owner,services=services)


def component_hashes(root,owner):
    hashes={}
    for name in binary_paths(owner):
        path=Path(root)/name
        if path.is_symlink() or not path.is_file(): raise ValueError('Cannot establish installed component identity')
        with path.open('rb') as stream: hashes[name]=hashlib.file_digest(stream,'sha256').hexdigest()
    return hashes


def _capture(root,destination,owner,*,services=None):
    root=Path(root);destination=Path(destination); services=services or Services()
    catalogue=resources(owner)
    if destination.exists() or destination.is_symlink(): raise ValueError('Snapshot destination already exists')
    size=inspect_resources(root,catalogue.paths)
    if shutil.disk_usage(destination.parent).free < size*1.1+64*1024*1024:
        raise ValueError('Insufficient free space for a consistent local snapshot')
    components=component_hashes(root,owner)
    original={name:services.is_active(name) for name in catalogue.services}
    daemon={'controller':'usr/bin/headscale','relay':'usr/local/bin/sc-derper','peer':'usr/local/bin/tailscaled'}[owner['role']]
    if hasattr(services,'verify_binary'):
        for name,active in original.items():
            if active: services.verify_binary(name,components[daemon])
    recovery=[]
    try:
        for name,active in original.items():
            if active:
                recovery.append(name)  # A failed stop can still have stopped the service.
                services.stop(name)
                if services.is_active(name): raise ValueError('Service did not stop; snapshot refused')
        # Repeat inspection after the write-producing services have stopped.
        inspect_resources(root,catalogue.paths)
        destination.mkdir(mode=0o700)
        for name in catalogue.paths: copy_resource(root/name,destination/'data'/name)
        metadata={'schema_version':1,'captured_at':datetime.now(timezone.utc).isoformat(),
                  'ownership':owner,'binary_sha256':components,'paths':list(catalogue.paths),'services_originally_active':original}
        (destination/'snapshot.json').write_text(json.dumps(metadata,indent=2)+'\n')
        (destination/'snapshot.json').chmod(0o600)
    except BaseException:
        if destination.exists(): shutil.rmtree(destination)
        raise
    finally:
        failed=[]
        for name in recovery:
            try:
                services.start(name)
                if not services.is_active(name): failed.append(name)
            except (OSError,ValueError,subprocess.SubprocessError): failed.append(name)
        if failed:
            if destination.exists(): shutil.rmtree(destination)
            raise ServiceRecoveryError('A managed service could not be restarted; backup upload was not attempted.')
    return metadata

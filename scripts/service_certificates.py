"""Service TLS generations: validate both browser origins and verify activation."""
from contextlib import ExitStack,contextmanager
import fcntl
import os
from pathlib import Path
import subprocess
from certificate_lifecycle import activate,validate_material
import service_runtime

BASE=Path('/etc/rdc-service-tls')
PENDING=Path('/etc/rdc-restore-pending.json')
BACKUP=Path('/etc/rdc-backup')
LOCK=Path('/run/rdc-services-operation.lock')


class Runtime:
    def __init__(self,settings):self.settings=settings
    def restart(self,service):subprocess.run(['/bin/systemctl','restart','rdc-service-proxy.service'],check=True,capture_output=True,timeout=180)
    def verify(self,hostname,fingerprint):service_runtime.verify_https(self.settings)


def activate_pair(base,settings,cert,key,*,initial=False,validator=validate_material,gid=0,runtime=None):
    owner=settings['ownership']
    def both(chain,private,hostname):
        first=validator(chain,private,owner['matrix_hostname'])
        second=validator(chain,private,owner['element_hostname'])
        if first['fingerprint']!=second['fingerprint']:raise ValueError('Service certificate identities differ')
        return first
    return activate(Path(base),owner['matrix_hostname'],'services',cert,key,gid=gid,
                    validator=both,runtime=runtime or Runtime(settings),initial=initial)


def replace(certificate,private_key):
    from backup_operations import require_platform
    from backup_scope import application_profile
    from service_operations import tls_inputs
    require_platform();settings=service_runtime.read_settings()
    profile=application_profile(settings['ownership'])
    profile.update(tls_certificate=str(certificate),tls_private_key=str(private_key))
    cert,key=tls_inputs(profile)
    with operation_lock():
        return activate_pair(BASE,settings,cert,key)


@contextmanager
def operation_lock(*,lock_path=None):
    with ExitStack() as stack:
        paths=[LOCK if lock_path is None else lock_path]
        if BACKUP.exists():paths.insert(0,BACKUP/'operation.lock')
        for path in paths:
            fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            stream=stack.enter_context(os.fdopen(fd,'a'));fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if PENDING.exists() or PENDING.is_symlink():raise ValueError('Resolve the pending restore before administering applications')
        yield

"""File-service certificate activation independent of installation and backups."""
from pathlib import Path
import subprocess
from certificate_lifecycle import activate
import nextcloud_runtime

BASE=Path('/etc/rdc-nextcloud-tls')


class Runtime:
    def __init__(self,settings):self.settings=settings
    def restart(self,service):subprocess.run(['/bin/systemctl','restart','rdc-nextcloud-proxy.service'],check=True,capture_output=True,timeout=180)
    def verify(self,hostname,fingerprint):nextcloud_runtime.verify_https(self.settings)


def activate_certificate(settings,cert,key,*,initial=False):
    return activate(BASE,settings['ownership']['nextcloud_hostname'],'nextcloud',cert,key,gid=0,initial=initial,runtime=Runtime(settings))

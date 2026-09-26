"""Read-only local software gate. Never install, pull, resolve DNS or start services."""
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import subprocess
from service_runtime import verify_image

TOOLS=('/usr/bin/podman','/usr/bin/runc','/usr/sbin/nft','/bin/systemctl','/usr/bin/openssl','/usr/bin/ss','/usr/bin/python3')


def platform_errors():
    from local_checks import platform_errors as supported
    try:release=platform.freedesktop_os_release() if platform.system()=='Linux' else {}
    except OSError:release={}
    errors=supported(platform.system(),platform.machine(),release,Path('/run/systemd/system').is_dir())
    if os.geteuid()!=0:errors.append('Run the read-only check with sudo on the intended guest to inspect its root-managed image store.')
    if any(os.environ.get(name) for name in ('CONTAINER_HOST','CONTAINER_CONNECTION')):
        errors.append('Remote Podman configuration is unsupported; inspect the local root-managed image store.')
    return errors


def executable(path):
    return Path(path).is_file() and os.access(path,os.X_OK)


def check(role):
    if role not in ('chat','files'):raise ValueError('Choose chat or files for the local software check.')
    checks=[]
    errors=platform_errors()
    checks.append({'id':'platform','status':'blocked' if errors else 'verified',
                   'detail':' '.join(errors) if errors else 'Supported local Ubuntu guest and root image store.'})
    if not errors:
        for path in TOOLS:
            ready=executable(path)
            checks.append({'id':path,'status':'verified' if ready else 'blocked',
                           'detail':'Local executable available.' if ready else 'Prepare this system dependency before disconnected installation.'})
        if executable('/usr/bin/podman'):
            if role=='chat':from service_contracts import image_pins
            else:from nextcloud_contracts import image_pins
            pins=image_pins()
            for name in pins:
                try:
                    verify_image(name,{'components':pins})
                    status='verified';detail='Reviewed Linux/amd64 image identity is present locally.'
                except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError):
                    status='blocked';detail='Pinned image is missing, mismatched or could not be inspected. Prepare the reviewed local image cache.'
                checks.append({'id':'image.'+name,'status':status,'detail':detail})
        else:
            checks.append({'id':'images','status':'blocked','detail':'Cannot inspect images without local Podman.'})
    return {'state':'application-software-blocked' if any(c['status']!='verified' for c in checks) else 'application-software-prepared',
            'role':role,'checked_at':datetime.now(timezone.utc).isoformat(),'checks':checks,
            'certificates':'not-tested','application_operations':'not-tested','recovery':'not-tested',
            'notice':'Software presence is not installation, local user access or whole-kit offline recovery evidence.'}


def require(role):
    report=check(role)
    if report['state']!='application-software-prepared':
        missing=', '.join(item['id'] for item in report['checks'] if item['status']!='verified')
        raise ValueError('Offline software is incomplete or unverified: '+missing+'. Run portable applications-check on this guest; no downloads were attempted.')

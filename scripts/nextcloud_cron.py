#!/usr/bin/python3
"""Fixed installed background job; serialized with future file-service recovery."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,'/usr/local/lib/rdc-nextcloud')
from nextcloud_runtime import read_settings,inspect_container,UNITS


def main():
    descriptor=os.open('/run/rdc-nextcloud-operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Restore pending')
        settings=read_settings();record=inspect_container('nextcloud',settings)
        if record is None or not record.get('State',{}).get('Running'):raise ValueError('File service unavailable')
        result=subprocess.run(['/usr/bin/podman','exec','--user','33:33',UNITS['nextcloud'],'php','-f','/var/www/html/cron.php'],capture_output=True,timeout=240)
        if result.returncode:raise ValueError('Application background job failed')
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,subprocess.SubprocessError):
        print('Nextcloud background job could not complete; inspect service and recovery status.',file=sys.stderr);raise SystemExit(1)

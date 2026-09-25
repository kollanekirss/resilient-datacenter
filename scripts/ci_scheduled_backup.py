"""Actual scheduled entry-point acceptance inside the disposable controller fixture."""
import json
import os
from pathlib import Path
import subprocess
import backup_target
import backup_schedule
from backup_operations import configure,configured,backup_now


def exercise():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Scheduled acceptance requires a disposable GitHub runner')
    def run(*args): return subprocess.run(list(args),check=True,capture_output=True,text=True,timeout=120)
    owner=json.loads(Path('/etc/server-connectivity-profile.json').read_text())
    if owner['role']!='controller': raise ValueError('Use the real disposable controller fixture')
    run('ip','address','add','100.64.0.12/32','dev','lo')
    # Transport dependency stub only. Actual controller and SFTP services run;
    # this fixture makes no VPN or physical-offsite claim.
    Path('/etc/systemd/system/tailscaled.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    run('systemctl','daemon-reload');run('systemctl','start','tailscaled')
    endpoint=backup_target.provision_storage(owner,'100.64.0.12')
    profile={'kind':'backup-profile','schema_version':1,'institution_id':'ci','node_name':'control','role':'controller',
             **{k:endpoint[k] for k in ('backup_host','backup_port','backup_host_key')}}
    configure(profile)
    backup_target.authorize(Path('/etc/rdc-backup/ssh_key.pub'))
    data,transport=configured();transport.initialize();backup_now()
    backup_schedule.enable('daily')
    # Stop only the timer, then invoke its actual installed unit deterministically.
    backup_schedule.disable()
    run('systemctl','start','rdc-backup.service')
    status=backup_schedule.status(0)
    assert status['state']=='disabled' and status['attempts']['last_attempt']['outcome']=='succeeded'
    previous=status['attempts']['last_success']
    password=Path('/etc/rdc-backup/password');saved=password.read_text();password.write_text('wrong-ci-password')
    failed=subprocess.run(['systemctl','start','rdc-backup.service'],capture_output=True,timeout=120)
    assert failed.returncode!=0
    status=backup_schedule.status(0)
    assert status['attempts']['last_attempt']['outcome']=='failed' and status['attempts']['last_success']==previous
    password.write_text(saved)
    run('systemctl','reset-failed','rdc-backup.service')
    run('systemctl','start','rdc-backup.service')
    assert backup_schedule.status(0)['attempts']['last_attempt']['outcome']=='succeeded'
    run('systemctl','stop',backup_target.SERVICE)
    print('Installed root-managed scheduled entry point: actual controller quiesce, encrypted SFTP backup, failure status preserving last success, and successful retry PASS.')

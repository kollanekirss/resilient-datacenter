"""Disposable real application backup/recovery; network daemon is an explicit stub."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def guard():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Only disposable GitHub-hosted runners are allowed')


def prepare_network():
    guard()
    # Test networking identity capture without installing a VPN on this fixture.
    Path('/var/lib/tailscale').mkdir(mode=0o700)
    Path('/var/lib/tailscale/ci-identity').write_text('synthetic network identity')
    for destination in ('/usr/local/bin/tailscale','/usr/local/sbin/tailscaled'):shutil.copy2('/usr/bin/sleep',destination)
    Path('/etc/systemd/system/tailscaled.service').write_text('[Service]\nType=simple\nExecStart=/usr/local/sbin/tailscaled infinity\n')
    subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','start','tailscaled'],check=True)


def prepare_backup(network,*,address='100.64.0.12'):
    guard()
    from backup_target import provision_storage,authorize
    from backup_operations import configure,configured,backup_now
    from backup_schedule import enable,disable
    subprocess.run(['ip','address','add',address+'/32','dev','lo'],check=True)
    endpoint=provision_storage(network,address)
    profile={'kind':'backup-profile','schema_version':1,'institution_id':network['institution_id'],'node_name':network['node_name'],'role':'peer',
             **{k:endpoint[k] for k in ('backup_host','backup_port','backup_host_key')}}
    configure(profile);authorize(Path('/etc/rdc-backup/ssh_key.pub'))
    _,transport=configured();transport.initialize();snapshot=backup_now()['snapshot_id']
    enable('daily');disable()
    return snapshot


def snapshot(network_snapshot):
    guard()
    from backup_operations import configured,backup_now
    from backup_scope import installed_application,application_backup,package
    application=installed_application();include_services=application_backup(application).include_services
    credentials={name:hashlib.sha256(Path('/etc/rdc-backup',name).read_bytes()).hexdigest() for name in ('password','ssh_key')}
    try:backup_now()
    except ValueError as error:assert 'only networking' in str(error)
    else:raise AssertionError('Network-only backup accepted an installed application')
    include_services()
    assert credentials=={name:hashlib.sha256(Path('/etc/rdc-backup',name).read_bytes()).hexdigest() for name in credentials}
    _,transport=configured();assert transport.snapshots()==[]
    # Actual installed timer entry point and frozen runtime, not just the library.
    subprocess.run(['systemctl','start','rdc-backup.service'],check=True,timeout=240)
    from backup_schedule import status
    assert status(0)['attempts']['last_attempt']['outcome']=='succeeded'
    snapshots=transport.snapshots();assert len(snapshots)==1 and snapshots[0]['id']!=network_snapshot
    assert 'rdc-'+package(application)+'-v1' in snapshots[0]['tags']
    from backup_operations import status_summary
    evidence=status_summary(snapshots)
    assert evidence['state']=='snapshot-present' and evidence['backup_age_seconds']>=0
    print('Captured '+package(application)+' snapshot age at acceptance check seconds: '+str(round(evidence['backup_age_seconds'],2)),flush=True)
    return snapshots[0]['id']


def restore(identifier,*,staged=False):
    guard()
    from backup_operations import configured,stage_restore,WORK
    from restore_runtime import Runtime
    from restore_transaction import apply
    from backup_scope import application_runtime
    from backup_contracts import resources
    data,_=configured()
    if not staged:stage_restore(identifier)
    class ApplicationRuntime(Runtime):
        def verify(self,owner):
            # Actual applications are verified; dummy transport cannot prove VPN.
            assert all(self.is_active(n) for n in resources(owner).services)
            runtime=application_runtime(owner['applications']);settings=runtime.read_settings()
            for name in runtime.UNITS:runtime.ready(name,settings)
    started=time.monotonic()
    result=apply(WORK/'restores'/identifier,data['ownership'],runtime=ApplicationRuntime(data['ownership']))
    assert result['state']=='restored-service-verified'
    assert not Path('/etc/rdc-restore-pending.json').exists()
    from restore_evidence import latest
    proof=latest(Path('/'),data['ownership'])
    assert proof['state']=='service-verified' and proof['snapshot_id']==identifier
    assert proof['user_operation']=='not-recorded'
    from product_status import run_probe
    assert run_probe('applications')['state']=='service-listeners-verified'
    assert run_probe('recovery')['state']=='service-verified'
    assert run_probe('backup')['state']=='backup-current'
    certificate_evidence=run_probe('certificates')
    assert certificate_evidence['state'] in ('certificate-valid','renewal-failed')
    assert certificate_evidence['serving_verified'] is True
    print('Disposable application restore service verification elapsed seconds: '+str(round(time.monotonic()-started,2)),flush=True)

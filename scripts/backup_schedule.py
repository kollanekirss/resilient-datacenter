"""Explicit scheduled backups using a frozen, root-managed runtime."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

BASE=Path('/etc/rdc-backup')
RUNTIME=Path('/opt/rdc-backup-runtime')
UNIT=Path('/etc/systemd/system/rdc-backup.service')
TIMER=Path('/etc/systemd/system/rdc-backup.timer')
FILES=('backup_runner.py','backup_schedule.py','backup_operations.py','backup_contracts.py','backup_snapshot.py','backup_transport.py',
       'profile_config.py','setup_contracts.py','validate_inventory.py','validate_tls.py')
CALENDARS={'hourly':'*-*-* *:00:00 UTC','daily':'*-*-* 02:00:00 UTC'}


def private_json(path,data):
    fd,name=tempfile.mkstemp(prefix='.rdc-status-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(data,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)


def read_private(path,*,require_root=True):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&0o077 or info.st_size>65536:
        raise ValueError('Unsafe scheduled-backup administration file')
    return json.loads(path.read_text())


def record_attempt(path,result,*,now=None):
    previous=read_private(path,require_root=False) if path.exists() else {'schema_version':1,'last_success':None}
    if previous.get('schema_version')!=1: raise ValueError('Unknown backup attempt record')
    when=now or datetime.now(timezone.utc).isoformat()
    data={'schema_version':1,'last_success':previous['last_success'],'last_attempt':{'finished_at':when,'outcome':'failed'}}
    if result is not None:
        from backup_transport import SNAPSHOT
        if result.get('state')!='snapshot-created' or not SNAPSHOT.fullmatch(str(result.get('snapshot_id',''))): raise ValueError('Cannot record an unverified backup success')
        data['last_success']={'finished_at':when,'snapshot_id':result['snapshot_id']};data['last_attempt']['outcome']='succeeded'
    private_json(path,data)


def overdue(frequency,age):
    if frequency not in CALENDARS: raise ValueError('Choose hourly or daily backups')
    # A grace period accommodates jitter and upload time; this is a status
    # threshold, not a recovery-point guarantee.
    return age is None or age>(3600 if frequency=='hourly' else 86400)+1800


def create_runtime(source,destination):
    source=Path(source);destination=Path(destination)
    if destination.exists() or destination.is_symlink(): raise ValueError('Scheduled runtime already exists; it is not replaced automatically')
    for name in FILES:
        path=source/name
        if path.is_symlink() or not path.is_file(): raise ValueError('Scheduled backup source is incomplete or linked')
    destination.mkdir(mode=0o700)
    try:
        hashes={}
        for name in FILES:
            content=(source/name).read_bytes();(destination/name).write_bytes(content);(destination/name).chmod(0o600)
            hashes[name]=hashlib.sha256(content).hexdigest()
        private_json(destination/'manifest.json',{'schema_version':1,'files':hashes})
    except BaseException:
        shutil.rmtree(destination)
        raise


def verify_runtime(directory=RUNTIME,*,require_root=True):
    directory=Path(directory);info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&0o077: raise ValueError('Unsafe scheduled backup runtime directory')
    data=read_private(directory/'manifest.json',require_root=require_root)
    if set(data)!={'schema_version','files'} or data['schema_version']!=1 or not isinstance(data['files'],dict) or set(data['files'])!=set(FILES):
        raise ValueError('Unknown scheduled backup runtime manifest')
    if set(p.name for p in directory.iterdir())!=set(FILES)|{'manifest.json'}: raise ValueError('Unexpected scheduled runtime files')
    for name,digest in data['files'].items():
        path=directory/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&0o077 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Scheduled runtime code changed; backup is blocked pending review')
    return data


def unit_text():
    return '''[Unit]
Description=RDC consistent encrypted backup
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /opt/rdc-backup-runtime/backup_runner.py
UMask=0077
TimeoutStartSec=0
# Do not interrupt a consistent snapshot with a short systemd timeout.
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
PrivateTmp=true
ProtectHome=true
[Install]
WantedBy=multi-user.target
'''


def timer_text(frequency):
    if frequency not in CALENDARS: raise ValueError('Choose hourly or daily backups')
    return '[Unit]\nDescription=RDC encrypted backup schedule\n[Timer]\nOnCalendar='+CALENDARS[frequency]+'\nRandomizedDelaySec=600\nPersistent=true\nUnit=rdc-backup.service\n[Install]\nWantedBy=timers.target\n'


def owned_schedule():
    data=read_private(BASE/'schedule.json')
    if set(data)!={'schema_version','frequency','ownership'} or data['schema_version']!=1 or data['frequency'] not in CALENDARS: raise ValueError('Unknown backup schedule')
    from backup_operations import root_json
    if data['ownership']!=root_json(Path('/etc/server-connectivity-profile.json')): raise ValueError('Backup schedule ownership changed')
    for path,content in ((UNIT,unit_text()),(TIMER,timer_text(data['frequency']))):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or path.read_text()!=content: raise ValueError('Backup scheduler units changed')
    verify_runtime()
    return data


def systemctl(*args):
    return subprocess.run(['/bin/systemctl',*args],check=True,capture_output=True,text=True,timeout=30)


def enable(frequency):
    from backup_operations import configured,private_write
    if frequency not in CALENDARS: raise ValueError('Choose hourly or daily backups')
    data,transport=configured()
    if not transport.snapshots(): raise ValueError('Take and inspect a successful manual backup before enabling its schedule')
    if (BASE/'schedule.json').exists():
        existing=owned_schedule()
        if existing['frequency']!=frequency: raise ValueError('Disable and review an existing schedule before changing its frequency; automatic replacement is not supported')
        systemctl('enable','--now','rdc-backup.timer')
        return {'state':'schedule-enabled','frequency':frequency}
    if any(p.exists() or p.is_symlink() for p in (RUNTIME,UNIT,TIMER,BASE/'schedule.json')): raise ValueError('Unknown scheduler files exist; automatic adoption is blocked')
    # Only library packages are installed, not a new network service.
    probe=subprocess.run(['/usr/bin/python3','-I','-c','import yaml; import cryptography'],capture_output=True,timeout=15)
    if probe.returncode:
        subprocess.run(['/usr/bin/apt-get','update','-qq'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300)
        subprocess.run(['/usr/bin/apt-get','install','-y','python3-yaml','python3-cryptography'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300)
    create_runtime(Path(__file__).resolve().parent,RUNTIME)
    private_write(UNIT,unit_text());UNIT.chmod(0o644)
    private_write(TIMER,timer_text(frequency));TIMER.chmod(0o644)
    private_json(BASE/'schedule.json',{'schema_version':1,'frequency':frequency,'ownership':data['ownership']})
    systemctl('daemon-reload');systemctl('enable','--now','rdc-backup.timer')
    return {'state':'schedule-enabled','frequency':frequency,'pause':'Each consistent snapshot briefly pauses the owned service','retention':'No snapshots are deleted automatically'}


def disable():
    owned_schedule()
    systemctl('disable','--now','rdc-backup.timer')
    return {'state':'schedule-disabled','running_backup':'Any already-running backup is allowed to finish'}


def status(age=None):
    if not (BASE/'schedule.json').exists(): return {'state':'not-configured'}
    data=owned_schedule()
    active=subprocess.run(['/bin/systemctl','is-active','rdc-backup.timer'],capture_output=True,text=True,timeout=15)
    if active.returncode not in (0,3): raise ValueError('Cannot establish backup timer state')
    result={'state':'enabled' if active.returncode==0 else 'disabled','frequency':data['frequency'],'overdue':overdue(data['frequency'],age)}
    if (BASE/'last-attempt.json').exists(): result['attempts']=read_private(BASE/'last-attempt.json')
    return result


def run_scheduled():
    import fcntl
    from backup_operations import configured,backup_now
    owned_schedule();configured()
    fd=os.open(BASE/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another backup or recovery is active. Scheduled run skipped; no new backup claimed.');return 3
        try:
            result=backup_now();record_attempt(BASE/'last-attempt.json',result)
            print('Encrypted scheduled backup completed. Check backup status for age and recovery evidence.');return 0
        except Exception:
            record_attempt(BASE/'last-attempt.json',None)
            print('Scheduled backup failed. Previous success is retained; inspect storage reachability, credentials, disk space and owned service state.');return 1

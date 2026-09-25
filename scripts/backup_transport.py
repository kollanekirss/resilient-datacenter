"""Pinned Restic operations over explicitly pinned SFTP; no shell or ambient credentials."""
import json
from datetime import datetime,timezone
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import socket
import subprocess
import tempfile
import time
from backup_contracts import validate,repository

SNAPSHOT=re.compile('[a-f0-9]{64}')


class Restic:
    def __init__(self,profile,*,base=Path('/etc/rdc-backup'),binary=Path('/usr/local/bin/rdc-restic'),scope='network'):
        if validate(profile): raise ValueError('Invalid backup profile')
        if scope not in ('network','matrix','nextcloud'): raise ValueError('Unknown backup scope')
        self.scope=scope
        self.profile=profile; self.base=Path(base); self.binary=Path(binary)

    def wait_ready(self):
        # A peer snapshot restarts its network daemon before upload. This probe
        # only waits for transport; SSH still verifies the pinned host key.
        # No repository write is retried.
        for attempt in range(10):
            try:
                with socket.create_connection((self.profile['backup_host'],self.profile['backup_port']),timeout=3):return
            except OSError:
                if attempt==9:raise ValueError('Backup storage did not become reachable after service restart') from None
                time.sleep(1)

    def known_hosts(self):
        host=self.profile['backup_host'];port=self.profile['backup_port']
        return (host if port==22 else '['+host+']:'+str(port))+' '+self.profile['backup_host_key']+'\n'

    def check_credentials(self):
        for name in ('password','ssh_key','known_hosts'):
            path=self.base/name;info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077:
                raise ValueError('Backup credentials must be private, regular root-owned files')
        if (self.base/'known_hosts').read_text()!=self.known_hosts(): raise ValueError('Saved SSH host key differs from the reviewed profile')
        if not (self.base/'password').stat().st_size: raise ValueError('Repository password is missing')
        info=self.binary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise ValueError('Restic executable must be managed by root')

    def command(self,args):
        ssh=['/usr/bin/ssh','-F','/dev/null','-i',str(self.base/'ssh_key'),'-p',str(self.profile['backup_port']),
             '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
             '-o','HostKeyAlgorithms=ssh-ed25519','-o','UserKnownHostsFile='+str(self.base/'known_hosts'),
             '-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=10','-o','ServerAliveInterval=30',
             '-o','ServerAliveCountMax=3','-s','rdc-backup@'+self.profile['backup_host'],'sftp']
        return [str(self.binary),'--repo',repository(self.profile),'--password-file',str(self.base/'password'),
                '--no-cache','-o','sftp.command='+shlex.join(ssh),*args]

    def execute(self,args,*,cwd=None,timeout=1800):
        self.check_credentials()
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'}
        with tempfile.TemporaryFile() as output:
            result=subprocess.run(self.command(args),cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=output,
                                  stderr=subprocess.DEVNULL,timeout=timeout)
            if result.returncode: raise ValueError('Encrypted backup operation failed; no successful backup or restore is claimed')
            output.seek(0);data=output.read(2*1024*1024+1)
            if len(data)>2*1024*1024: raise ValueError('Backup response exceeded the supported size')
        return data.decode('utf-8')

    def initialize(self):
        # Restic itself refuses to initialize over an existing repository.
        self.execute(['init','--repository-version','2'],timeout=120)

    def backup(self,stage):
        captured=datetime.fromisoformat(json.loads((Path(stage)/'snapshot.json').read_text())['captured_at'])
        if captured.tzinfo is None: raise ValueError('Snapshot capture time must include a timezone')
        timestamp=captured.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        tags=['--tag','rdc-v1']+(['--tag','rdc-'+self.scope+'-v1'] if self.scope!='network' else [])
        text=self.execute(['backup','--time',timestamp,'--json','--host',self.profile['node_name'],*tags,'.'],cwd=stage)
        records=[json.loads(line) for line in text.splitlines() if line.strip()]
        summaries=[r for r in records if isinstance(r,dict) and r.get('message_type')=='summary']
        if len(summaries)!=1 or not isinstance(summaries[0].get('snapshot_id'),str) or not SNAPSHOT.fullmatch(summaries[0]['snapshot_id']):
            raise ValueError('Backup did not return one complete snapshot identity')
        return summaries[0]['snapshot_id']

    def snapshots(self):
        tags='rdc-v1,rdc-'+self.scope+'-v1' if self.scope!='network' else 'rdc-v1'
        data=json.loads(self.execute(['--no-lock','snapshots','--json','--host',self.profile['node_name'],'--tag',tags],timeout=120))
        if not isinstance(data,list) or len(data)>10000: raise ValueError('Invalid snapshot listing')
        for item in data:
            if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not SNAPSHOT.fullmatch(item['id']) or not isinstance(item.get('time'),str):
                raise ValueError('Invalid snapshot identity or timestamp')
        return data

    def restore(self,identifier,destination):
        destination=Path(destination)
        if not isinstance(identifier,str) or not SNAPSHOT.fullmatch(identifier): raise ValueError('Select the full snapshot ID, never latest or an ambiguous prefix')
        if destination.exists() or destination.is_symlink(): raise ValueError('Restore staging directory already exists')
        destination.mkdir(mode=0o700)
        try:
            self.execute(['restore',identifier,'--target',str(destination),'--verify'])
        except BaseException:
            shutil.rmtree(destination)
            raise
        return destination

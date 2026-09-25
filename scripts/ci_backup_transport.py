#!/usr/bin/env python3
"""Disposable Ubuntu encrypted SFTP backup/restore acceptance; no regional resilience claim."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import backup_target
from backup_operations import install_binary,private_write,validate_restore
from backup_snapshot import capture
from backup_transport import Restic
from setup_contracts import local_ownership


def run(args,**kwargs): return subprocess.run(args,check=True,timeout=120,**kwargs)

class Services:
    def is_active(self,name): return False
    def stop(self,name): raise AssertionError('Synthetic source service is not running')
    def start(self,name): raise AssertionError('Synthetic source service must remain stopped')


def main():
    if (os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
        or platform.system()!='Linux' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text()):
        raise SystemExit('Only disposable GitHub-hosted Ubuntu runners are permitted.')
    for path in (backup_target.BASE,backup_target.STORAGE,Path('/etc/server-connectivity-profile.json')):
        if path.exists(): raise SystemExit('Disposable target is not fresh')
    run(['ip','address','add','100.64.0.12/32','dev','lo'])
    unit=Path('/etc/systemd/system/tailscaled.service')
    if unit.exists(): raise SystemExit('A real client unit already exists')
    unit.write_text('[Unit]\nDescription=CI dependency stub; NOT a network client\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    run(['systemctl','daemon-reload']);run(['systemctl','start','tailscaled'])
    manifest={'kind':'local-node','schema_version':1,'institution_id':'ci','node_name':'source','headscale_hostname':'control.ci.test','node_tag':'tag:source'}
    owner=local_ownership(manifest)
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps(owner))
    endpoint=backup_target.provision_storage(owner,'100.64.0.12')
    with tempfile.TemporaryDirectory(prefix='rdc-backup-ci-') as temporary:
        folder=Path(temporary);credentials=folder/'credentials';credentials.mkdir(mode=0o700)
        private_write(credentials/'password','ci-only-repository-password-'+os.urandom(32).hex()+'\n')
        run(['ssh-keygen','-q','-t','ed25519','-N','','-C','ci-writer','-f',str(credentials/'ssh_key')])
        backup_target.authorize(credentials/'ssh_key.pub')
        profile={'kind':'backup-profile','schema_version':1,'institution_id':'ci','node_name':'source','role':'peer',
                 **{k:endpoint[k] for k in ('backup_host','backup_port','backup_host_key')}}
        binary=folder/'restic';install_binary(binary)
        transport=Restic(profile,base=credentials,binary=binary)
        private_write(credentials/'known_hosts',transport.known_hosts())
        # CI-only diagnostics for these synthetic inputs; production suppresses raw transport output.
        real_run=subprocess.run
        def diagnostic(args,**kwargs):
            if str(args[0])==str(binary):
                kwargs['stderr']=subprocess.PIPE
                result=real_run(args,**kwargs)
                if result.returncode: print(result.stderr.decode('utf-8',errors='replace'))
                return result
            return real_run(args,**kwargs)
        subprocess.run=diagnostic
        transport.initialize()
        root=folder/'source';(root/'var/lib/tailscale').mkdir(parents=True);(root/'etc').mkdir();(root/'usr/local/bin').mkdir(parents=True)
        secret=b'CI-ONLY-IDENTITY-'+os.urandom(128)
        (root/'var/lib/tailscale/tailscaled.state').write_bytes(secret)
        (root/'etc/server-connectivity-profile.json').write_text(json.dumps(owner))
        for name in ('tailscale','tailscaled'): (root/'usr/local/bin'/name).write_bytes(b'CI placeholder; never executed')
        stage=folder/'snapshot';capture(root,stage,owner,services=Services())
        identifier=transport.backup(stage)
        snapshots=transport.snapshots();assert any(s['id']==identifier for s in snapshots)
        restored=folder/'restored';transport.restore(identifier,restored)
        validate_restore(restored,owner)
        assert (restored/'data/var/lib/tailscale/tailscaled.state').read_bytes()==secret
        # Source identity must not be present as plaintext in encrypted repository files.
        for path in (backup_target.STORAGE/'data').rglob('*'):
            if path.is_file(): assert secret not in path.read_bytes()
        saved=(credentials/'known_hosts').read_text()
        run(['ssh-keygen','-q','-t','ed25519','-N','','-C','wrong-host','-f',str(folder/'wrong-host')])
        wrong_profile=dict(profile,backup_host_key=backup_target.public_key((folder/'wrong-host.pub').read_text()))
        wrong_transport=Restic(wrong_profile,base=credentials,binary=binary)
        (credentials/'known_hosts').write_text(wrong_transport.known_hosts())
        try: wrong_transport.snapshots()
        except ValueError: pass
        else: raise AssertionError('An actual SSH host-key mismatch was accepted')
        (credentials/'known_hosts').write_text(saved)
        (credentials/'password').write_text('wrong repository password\n')
        try: transport.snapshots()
        except ValueError: pass
        else: raise AssertionError('Wrong encryption password was accepted')
        print('Actual pinned Restic + restricted SFTP: backup, full-ID restore, byte integrity, encryption, wrong-host-key and wrong-password rejection PASS.')
        print('Real VPN traversal, physical offsite placement and service promotion NOT RUN by this transport test.')
    run(['systemctl','stop',backup_target.SERVICE])

if __name__=='__main__': main()

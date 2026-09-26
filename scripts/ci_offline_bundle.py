#!/usr/bin/env python3
"""Fresh pinned Ubuntu guest bootstrap with an uplink blocked before first boot."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import ci_home_vm as virtual
from offline_bundle_build import build

ROOT=Path('/var/lib/rdc-bundle-ci')


def main():
    virtual.guard()
    if ROOT.exists():raise ValueError('Use a fresh disposable bundle acceptance host')
    ROOT.mkdir(mode=0o700)
    result=build(ROOT/'kit');trusted=result['manifest_sha256']
    (ROOT/'evidence.json').write_text(json.dumps(result,indent=2))
    virtual.image(ROOT/'ubuntu.img')
    archive=ROOT/'kit.tar'
    with tarfile.open(archive,'w') as stream:stream.add(ROOT/'kit',arcname='kit')
    for role in ('chat','files'):
        vm=None
        try:
            vm=virtual.VM(ROOT/role,ROOT/'ubuntu.img',port=22222,ca='',
                controller_address='127.0.0.1',controller_hostname='unused.ci.test',offline=True)
            # No package downloads by cloud-init; the actual guest was isolated
            # at QEMU creation, before any bootstrap command or cache import.
            vm.ssh(['test','!','-e','/usr/bin/podman'])
            vm.ssh(['test','!','-e','/usr/bin/skopeo'])
            vm.ssh(['python3','-c',"import socket; s=socket.socket(); s.settimeout(3); r=s.connect_ex(('1.1.1.1',443)); s.close(); assert r!=0"])
            vm.put(archive,'/root/kit.tar',timeout=900)
            vm.ssh(['tar','-xf','/root/kit.tar','-C','/root'],timeout=300)
            vm.ssh(['rm','/root/kit.tar'])
            bootstrap=['python3','/root/kit/source/scripts/offline_bundle.py','bootstrap','/root/kit',
                       '--manifest-sha256',trusted,'--confirm-fresh-guest']
            output=vm.ssh(bootstrap,timeout=1500).decode()
            record=json.loads(output)
            assert record['state']=='role-software-prepared'
            print('Offline fresh guest dependencies and pinned images verified: '+role,flush=True)
            # Repeat bootstrap before deploying identities: no change of bundle
            # or source is accepted, and imported image identities remain exact.
            repeated=json.loads(vm.ssh(bootstrap,timeout=1200))
            assert repeated['source']==record['source']
            source=Path(record['source']);python=source/'.venv/bin/python'
            vm.ssh(['systemctl','disable','--now','nginx.service'])
            # Install the recovery executable from the bundle, without using a
            # repository password or involving any external backup destination.
            code="import sys; sys.path.insert(0,sys.argv[1]); from backup_operations import install_binary; install_binary('/root/restic-check',artifact=sys.argv[2])"
            vm.ssh([python,'-c',code,str(source/'scripts'),record['restic_artifact']])
            vm.ssh(['/root/restic-check','version'])
            # Same real application/frontend, isolation, login and snapshot
            # restoration fixture as portable acceptance, now inside a cold VM.
            output=vm.ssh(['env','GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted','RDC_OFFLINE_BUNDLE_ACCEPTANCE=1',python,
                source/'scripts/ci_portable_applications.py',role],timeout=1500).decode()
            assert 'native fenced application snapshot restore PASS' in output
            print('Cold disconnected '+role+' installation, local operation and native snapshot restoration PASS',flush=True)
        except subprocess.CalledProcessError as error:
            print((error.stdout or b'')[-7000:].decode(errors='replace'),file=sys.stderr)
            print((error.stderr or b'')[-7000:].decode(errors='replace'),file=sys.stderr)
            raise
        finally:
            if vm:vm.stop()
        shutil.rmtree(ROOT/role) # only this just-fenced disposable test guest
    print('Role-software acceptance PASS. Physical kit, guest media boot and private whole-site recovery are NOT RUN.',flush=True)


if __name__=='__main__':main()

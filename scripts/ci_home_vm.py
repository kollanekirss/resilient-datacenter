"""Pinned fresh Ubuntu guests behind user-mode NAT on disposable CI only."""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import subprocess
import time
import urllib.request
import yaml

IMAGE_URL='https://cloud-images.ubuntu.com/noble/20260911/noble-server-cloudimg-amd64.img'
IMAGE_SHA256='612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354'


def guard():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.geteuid()!=0 or platform.system()!='Linux' or platform.machine()!='x86_64':
        raise ValueError('Fresh VM acceptance runs only on disposable GitHub-hosted Ubuntu amd64')
    if 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text() or not Path('/dev/kvm').exists():
        raise ValueError('The disposable Ubuntu runner must provide KVM; no workstation or emulation fallback')


def qemu_command(folder,port,*,offline=False):
    if type(port) is not int or port not in (22222,22223):raise ValueError('Use the fixed private console ports')
    folder=Path(folder)
    return ['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','2','-m','4096','-display','none','-no-reboot',
        '-drive','file='+str(folder/'disk.qcow2')+',format=qcow2,if=virtio',
        '-drive','file='+str(folder/'seed.img')+',format=raw,if=virtio,readonly=on',
        '-netdev','user,id=home,'+('restrict=on,' if offline else '')+'hostfwd=tcp:127.0.0.1:'+str(port)+'-:22','-device','virtio-net-pci,netdev=home',
        '-serial','file:'+str(folder/'console.log'),'-monitor','none']


def run(args,*,timeout=120,input=None):
    return subprocess.run(args,input=input,check=True,capture_output=True,timeout=timeout).stdout


def image(path):
    guard();path=Path(path)
    if path.exists():raise ValueError('Fresh pinned image destination required')
    digest=hashlib.sha256();size=0
    with urllib.request.urlopen(IMAGE_URL,timeout=120) as source,path.open('xb') as output:
        while chunk:=source.read(1024*1024):
            size+=len(chunk)
            if size>2*1024**3:raise ValueError('Oversized guest image')
            digest.update(chunk);output.write(chunk)
    if digest.hexdigest()!=IMAGE_SHA256:raise ValueError('Ubuntu image differs from its reviewed SHA256')
    path.chmod(0o400)


class VM:
    def __init__(self,folder,base,*,port,ca,controller_address,controller_hostname,offline=False):
        guard();self.folder=Path(folder);self.port=port;self.process=None
        self.folder.mkdir(mode=0o700)
        for name in ('console-key','host-key'):
            run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.folder/name)])
        host_key=' '.join((self.folder/'host-key.pub').read_text().split()[:2])
        (self.folder/'known_hosts').write_text('[127.0.0.1]:'+str(port)+' '+host_key+'\n')
        config={'hostname':self.folder.name,'ssh_pwauth':False,'disable_root':True,
            'users':[{'name':'ciadmin','shell':'/bin/bash','sudo':['ALL=(ALL) NOPASSWD:ALL'],
                      'ssh_authorized_keys':[(self.folder/'console-key.pub').read_text().strip()]}],
            'ssh_keys':{'ed25519_private':(self.folder/'host-key').read_text(),'ed25519_public':host_key},
            'ca_certs':{'trusted':[ca]},
            'write_files':[{'path':'/etc/cloud/cloud.cfg.d/99-rdc-hosts.cfg','content':'manage_etc_hosts: false\n'},
                           {'path':'/etc/hosts','append':True,'content':'\n'+controller_address+' '+controller_hostname+'\n'}],
            'packages':['python3-venv','python3-pip','nftables'],
            'runcmd':[['touch','/var/lib/rdc-ci-ready']]}
        if offline:
            config.pop('packages')
            config['package_update']=False
            config['package_upgrade']=False
            if not ca:config.pop('ca_certs')
        user=self.folder/'user-data';user.write_text('#cloud-config\n'+yaml.safe_dump(config));user.chmod(0o600)
        meta=self.folder/'meta-data';meta.write_text('instance-id: '+self.folder.name+'\nlocal-hostname: '+self.folder.name+'\n')
        run(['cloud-localds',str(self.folder/'seed.img'),str(user),str(meta)])
        (self.folder/'seed.img').chmod(0o600)
        run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(base),str(self.folder/'disk.qcow2'),'32G'])
        self.process=subprocess.Popen(qemu_command(self.folder,port,offline=offline),stdout=subprocess.DEVNULL,stderr=(self.folder/'qemu.log').open('wb'))
        for attempt in range(180):
            if self.process.poll() is not None:raise ValueError('Fresh guest exited before becoming ready')
            try:self.ssh(['test','-f','/var/lib/rdc-ci-ready'],timeout=8);break
            except (subprocess.SubprocessError,OSError):time.sleep(2)
        else:raise ValueError('Guest cloud-init did not finish within the test bound')

    def ssh_options(self):
        return ['-i',str(self.folder/'console-key'),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=5',
            '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(self.folder/'known_hosts'),'-o','GlobalKnownHostsFile=/dev/null']

    def ssh(self,args,*,input=None,timeout=120):
        return run(['ssh',*self.ssh_options(),'-p',str(self.port),'ciadmin@127.0.0.1',shlex.join(['sudo','--',*map(str,args)])],input=input,timeout=timeout)

    def put(self,source,destination,*,timeout=180):
        # Fixed private console; transfer first to the unprivileged home.
        run(['scp',*self.ssh_options(),'-P',str(self.port),str(source),'ciadmin@127.0.0.1:/home/ciadmin/rdc-transfer'],timeout=timeout)
        self.ssh(['install','-m','600','/home/ciadmin/rdc-transfer',destination]);self.ssh(['rm','/home/ciadmin/rdc-transfer'])

    def get(self,path):return self.ssh(['cat',path])

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=10)
        if self.process is not None and self.process.poll() is None:raise ValueError('Old guest was not fenced')

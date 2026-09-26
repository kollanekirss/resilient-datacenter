"""Private Linux routing/DNS/time/frontend fixture, not an OPNsense emulator."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from portable_network_render import unbound,chrony,firewall

BRIDGES={'staff':'rs-staff-br','front':'rs-front-br','apps':'rs-apps-br'}
NAMES=('rs-edge','rs-dns','rs-front','rs-staff')


def run(*args,**kwargs):return subprocess.run([str(a) for a in args],check=kwargs.pop('check',True),timeout=kwargs.pop('timeout',90),**kwargs)


def ns(name,*args,**kwargs):return run('ip','netns','exec',name,*args,**kwargs)


def attach(name,zone,interface,address,index):
    host='rs-v'+str(index)
    run('ip','link','add',host,'type','veth','peer','name',interface,'netns',name)
    run('ip','link','set',host,'master',BRIDGES[zone]);run('ip','link','set',host,'up')
    run('ip','-n',name,'address','add',address,'dev',interface);run('ip','-n',name,'link','set',interface,'up')


def edge_rules():
    return '''table inet rs_edge {
chain forward { type filter hook forward priority 0; policy drop;
ct state established,related accept
ip saddr 10.76.20.0/24 ip daddr 10.76.30.11 tcp dport 443 accept
ip saddr {10.76.20.0/24,10.76.40.0/24} ip daddr 10.76.30.10 udp dport {53,123} accept
ip saddr {10.76.20.0/24,10.76.40.0/24} ip daddr 10.76.30.10 tcp dport 53 accept
ip saddr 10.76.30.11 ip daddr {10.76.40.10,10.76.40.11} tcp dport 443 accept
}
chain input {type filter hook input priority 0; policy drop; iifname "lo" accept;}
chain output {type filter hook output priority 0; policy drop; oifname "lo" accept; ct state established,related accept;}
}'''


class Network:
    def __init__(self,work,plan,settings):
        self.processes=[];self.work=Path(work);self.plan=plan;self.settings=settings
        for bridge in BRIDGES.values():run('ip','link','add',bridge,'type','bridge');run('ip','link','set',bridge,'up')
        run('sysctl','-w','net.bridge.bridge-nf-call-iptables=0',check=False,stdout=subprocess.DEVNULL)
        for name in NAMES:
            run('ip','netns','add',name);run('ip','-n',name,'link','set','lo','up')
        index=0
        for zone,subnet in [('staff','20'),('front','30'),('apps','40')]:
            attach('rs-edge',zone,zone+'0','10.76.'+subnet+'.1/24',index);index+=1
        for name,zone,address in [('rs-dns','front','10.76.30.10'),('rs-front','front','10.76.30.11'),('rs-staff','staff','10.76.20.100')]:
            attach(name,zone,'lan0',address+'/24',index);index+=1
            run('ip','-n',name,'route','add','default','via','10.76.'+('20' if zone=='staff' else '30')+'.1')
            folder=Path('/etc/netns')/name;folder.mkdir(parents=True)
            (folder/'resolv.conf').write_text('nameserver 10.76.30.10\noptions timeout:1 attempts:1\n')
        ns('rs-edge','sysctl','-w','net.ipv4.ip_forward=1',stdout=subprocess.DEVNULL)
        ns('rs-edge','nft','-f','-',input=edge_rules(),text=True)
        for role in ('chat','files'):
            run('ip','tuntap','add','rs-'+role,'mode','tap');run('ip','link','set','rs-'+role,'master',BRIDGES['apps']);run('ip','link','set','rs-'+role,'up')
        run('systemctl','stop','chrony','unbound');run('systemctl','disable','--now','nginx')
        Path('/etc/unbound/rdc-portable.conf').write_text(unbound(plan))
        Path('/etc/chrony/rdc-portable.conf').write_text(chrony(plan,settings))
        ns('rs-dns','nft','-f','-',input=firewall(plan,settings),text=True)
        self.spawn('dns','rs-dns','unbound','-d','-c','/etc/unbound/rdc-portable.conf')
        self.spawn('time','rs-dns','chronyd','-x','-n','-f','/etc/chrony/rdc-portable.conf')

    def spawn(self,label,name,*args):
        with (self.work/(label+'.log')).open('w') as log:
            process=subprocess.Popen(['ip','netns','exec',name,*args],stdout=log,stderr=log)
        self.processes.append(process)

    def stop(self):
        run('systemctl','stop','rdc-frontend.service',check=False)
        for p in self.processes:
            if p.poll() is None:p.terminate()
        for p in self.processes:
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
        for name in NAMES:
            run('ip','netns','delete',name,check=False)
            shutil.rmtree(Path('/etc/netns')/name,ignore_errors=True)
        for role in ('chat','files'):run('ip','link','delete','rs-'+role,check=False)
        for bridge in BRIDGES.values():run('ip','link','delete',bridge,check=False)


def frontend(material):
    from portable_application_install import frontend as install
    import portable_application_install as module
    root=Path(material);plan=json.loads((root/'configuration/site.json').read_text());settings=json.loads((root/'configuration/network.json').read_text())
    original=module.frontend_unit
    module.frontend_unit=lambda:original()+'\n[Service]\nNetworkNamespacePath=/run/netns/rs-front\n'
    result=install(plan,settings,root/'tls/frontend')
    if result['state']!='local-frontend-tls-verified':raise ValueError('Frontend was not ready')


if __name__=='__main__':
    from ci_portable_applications import guard
    guard();frontend(sys.argv[1])

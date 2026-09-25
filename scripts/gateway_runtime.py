#!/usr/bin/python3
"""Root-owned single-membership gateway runtime with closed interrupted changes."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import socket
import stat
import subprocess
import sys
import time
import gateway_contracts as contracts
import gateway_rendering as rendering
from gateway_store import Store,decode
from regional_workspace import private_read,private_write
import regional_agreements as agreements

BASE=Path('/etc/rdc-gateway')
INSTALLED=Path('/usr/local/lib/rdc-gateway')
UNIT='rdc-regional-gateway'
CONTAINER='rdc-regional-gateway'


def command(*args,timeout=30,input=None):
    result=subprocess.run(list(args),check=True,capture_output=True,text=True,timeout=timeout,input=input)
    if len(result.stdout)>2*1024*1024:raise ValueError('Oversized gateway command response')
    return result.stdout


def root_json(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>512*1024:raise ValueError('Unsafe gateway administration file')
    return decode(path.read_bytes())


def validate_network(profile,identity,network,status,prefs):
    owned=identity['payload']
    expected={'schema_version':2,'deployment_mode':'join','institution_id':profile['institution_id'],'role':'peer',
              'controller_hostname':profile['regional_controller'],'node_name':profile['node_name'],'install_method':'local'}
    if set(network)!=set(expected)|{'node_tag'} or any(network.get(k)!=v for k,v in expected.items()):raise ValueError('Use a dedicated locally enrolled regional gateway; this machine belongs to another role or network')
    if status.get('BackendState')!='Running' or owned['gateway_ipv4'] not in status.get('Self',{}).get('TailscaleIPs',[]):raise ValueError('Gateway is not running with its signed regional address')
    if prefs.get('ControlURL','').rstrip('/')!='https://'+profile['regional_controller'] or prefs.get('AdvertiseRoutes') or prefs.get('ExitNodeID') or prefs.get('ExitNodeIP') not in (None,'','0.0.0.0','::'):
        raise ValueError('Gateway must use one regional controller without advertised subnets or an exit node')


def network_check(store):
    profile=store.profile();identity=store.identity()
    validate_network(profile,identity,root_json(Path('/etc/server-connectivity-profile.json')),
        json.loads(command('/usr/local/bin/tailscale','status','--json')),json.loads(command('/usr/local/bin/tailscale','debug','prefs')))
    if any(Path(path).read_text().strip()!='0' for path in ('/proc/sys/net/ipv4/ip_forward','/proc/sys/net/ipv6/conf/all/forwarding')):raise ValueError('Disable general IPv4 and IPv6 forwarding on the dedicated gateway')
    if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Complete fenced network recovery and review current partners before opening the gateway')


def lan_interface(profile):
    records=json.loads(command('/usr/sbin/ip','-j','address','show'))
    matches=[item['ifname'] for item in records if any(address.get('local')==profile['lan_address'] and address.get('prefixlen')==ipaddress.ip_network(profile['lan_subnet']).prefixlen for address in item.get('addr_info',[]))]
    if len(matches)!=1 or matches[0] in ('lo','tailscale0') or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',matches[0]):raise ValueError('Assign the declared private LAN address and subnet to one dedicated interface')
    return matches[0]


def container_command(identity,*,validation=False):
    common=['/usr/bin/podman','--runtime=/usr/bin/runc','run','--network=host','--pull=never','--read-only',
            '--cap-drop=ALL','--cap-add=NET_BIND_SERVICE','--security-opt=no-new-privileges','--pids-limit=256','--memory=512m','--user=0:0',
            '--label','org.rdc.gateway='+agreements.fingerprint(identity),'--volume',str(BASE)+':/etc/rdc-gateway:ro',
            '--volume','/etc/ssl/certs:/etc/ssl/certs:ro','--entrypoint','/usr/local/bin/envoy']
    if validation:common+=['--rm']
    else:common+=['--name',CONTAINER]
    common += [contracts.image_pins()['gateway']['image'],'-c','/etc/rdc-gateway/'+('candidate.json' if validation else 'envoy.json'),'--concurrency','2']
    if validation:common+=['--mode','validate']
    return common


def inspect(identity):
    result=subprocess.run(['/usr/bin/podman','container','exists',CONTAINER],capture_output=True,timeout=15)
    if result.returncode==1:return None
    if result.returncode:raise ValueError('Cannot inspect gateway container')
    records=json.loads(command('/usr/bin/podman','inspect',CONTAINER))
    if len(records)!=1:raise ValueError('Cannot identify one gateway container')
    item=records[0];pin=contracts.image_pins()['gateway']
    if (item.get('Config',{}).get('Labels') or {}).get('org.rdc.gateway')!=agreements.fingerprint(identity) or str(item.get('Image','')).removeprefix('sha256:')!=pin['config_digest'].removeprefix('sha256:'):
        raise ValueError('Existing gateway container has another owner or image')
    return item


def verify_image():
    pin=contracts.image_pins()['gateway'];images=json.loads(command('/usr/bin/podman','image','inspect',pin['image']))
    if len(images)!=1 or images[0].get('Architecture')!='amd64' or images[0].get('Os')!='linux' or str(images[0].get('Id','')).removeprefix('sha256:')!=pin['config_digest'].removeprefix('sha256:'):
        raise ValueError('Gateway image differs from its reviewed digest or platform')


class Runtime:
    def __init__(self,store):self.store=store

    def firewall(self,peers):
        profile=self.store.profile();interface=lan_interface(profile)
        tables=json.loads(command('/usr/sbin/nft','-j','list','tables'))
        exists=any(item.get('table',{}).get('family')=='inet' and item['table'].get('name')=='rdc_gateway' for item in tables['nftables'])
        if exists:
            table=json.loads(command('/usr/sbin/nft','-j','list','table','inet','rdc_gateway'))
            metadata=[item['table'] for item in table['nftables'] if 'table' in item]
            if len(metadata)!=1 or metadata[0].get('comment')!='rdc-regional-gateway-v1':raise ValueError('The gateway firewall table belongs to another configuration')
        # Only this owned scoped table is replaced; other firewalls remain intact.
        text=rendering.firewall(profile,peers,lan_interface=interface,now=int(time.time()),replace=exists)
        command('/usr/sbin/nft','--check','-f','-',input=text)
        command('/usr/sbin/nft','-f','-',input=text)

    def close(self):self.firewall([])

    def validate(self,candidate):
        network_check(self.store);verify_image()
        generated=rendering.envoy(self.store.profile(),self.store.identity(),self.store.peers(candidate))
        private_write(BASE/'candidate.json',json.dumps(generated).encode(),replace=True)
        command(*container_command(self.store.identity(),validation=True),timeout=60)

    def install(self,candidate):
        generated=rendering.envoy(self.store.profile(),self.store.identity(),self.store.peers(candidate))
        private_write(BASE/'envoy.json',json.dumps(generated).encode(),replace=True)

    def restart(self):command('/bin/systemctl','restart',UNIT+'.service',timeout=120)

    def open(self,candidate):
        network_check(self.store)
        if self.store.state()!=candidate:raise ValueError('Gateway policy changed before activation')
        item=inspect(self.store.identity())
        if item is None or not item.get('State',{}).get('Running'):raise ValueError('Gateway proxy is not running')
        self.firewall(self.store.peers(candidate))


def verify_runtime():
    if os.geteuid()!=0 or sys.platform!='linux':raise ValueError('Use the managed Linux gateway')
    manifest=root_json(INSTALLED/'manifest.json')
    if not isinstance(manifest,dict) or set(manifest)!={'schema_version','files'} or manifest['schema_version']!=1:raise ValueError('Unknown gateway runtime manifest')
    if set(manifest['files'])!=set(RUNTIME_FILES):raise ValueError('Unknown gateway runtime files')
    for name,digest in manifest['files'].items():
        path=INSTALLED/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Gateway runtime changed; review a controlled upgrade')


RUNTIME_FILES=('gateway_entry.py','gateway_runtime.py','gateway_store.py','gateway_contracts.py','gateway_images.json','gateway_rendering.py',
               'gateway_transition.py','regional_workspace.py','regional_agreements.py','profile_config.py','validate_inventory.py','validate_tls.py')


def unit():
    return '''[Unit]
Description=RDC restricted regional application gateway
After=network-online.target tailscaled.service
Requires=tailscaled.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/rdc-gateway/gateway_entry.py run
ExecStartPost=/usr/bin/python3 -I -B /usr/local/lib/rdc-gateway/gateway_entry.py ready
ExecStop=/usr/bin/python3 -I -B /usr/local/lib/rdc-gateway/gateway_entry.py stop
ExecStopPost=/usr/bin/python3 -I -B /usr/local/lib/rdc-gateway/gateway_entry.py close
Restart=on-failure
RestartSec=5
TimeoutStartSec=90
TimeoutStopSec=60
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def main(action):
    verify_runtime();store=Store(BASE);runtime=Runtime(store)
    if action=='close':runtime.close();return 0
    identity=store.identity()
    if action=='stop':
        item=inspect(identity)
        if item is not None:command('/usr/bin/podman','stop','--time','30',CONTAINER,timeout=45)
        return 0
    if action=='ready':
        for _ in range(60):
            item=inspect(identity)
            if item and item.get('State',{}).get('Running'):
                # Local socket connection verifies that Envoy finished binding;
                # packet/TLS validation across the boundary belongs to acceptance.
                listeners=command('/usr/bin/ss','-H','-lnt')
                if all(endpoint in listeners for endpoint in (identity['payload']['gateway_ipv4']+':443',store.profile()['lan_address']+':3128')):return 0
            time.sleep(1)
        raise ValueError('Gateway listeners did not become ready')
    if action!='run':raise ValueError('Unsupported gateway runtime action')
    runtime.close();network_check(store);verify_image()
    state=store.state();runtime.install(state)
    item=inspect(identity)
    if item:
        if item.get('State',{}).get('Running'):raise ValueError('An owned gateway container is already running outside this service invocation')
        command('/usr/bin/podman','rm',CONTAINER)
    # Pending changes launch the candidate listeners behind a closed firewall.
    # The explicit transaction opens them only after verified restart.
    if not store.pending():runtime.firewall(store.peers(state))
    return subprocess.run(container_command(identity)).returncode

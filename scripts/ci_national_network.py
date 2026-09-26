"""Disposable domestic authorities, private relays, DNS and an outside canary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import yaml
from jinja2 import Environment,FileSystemLoader,StrictUndefined
import ci_regional_network as network
from ci_national_contract import cut_rules,restart_command

NAMES=[]
RELAYS={}
DNS='172.29.10.200'
FOREIGN='172.29.10.250'


def namespace(name,index):
    network.namespace(name,index);NAMES.append(name)


def start_controller(control):
    old=control['process']
    if old.poll() is None:old.terminate();old.wait(timeout=15)
    process=network.spawn('controller-'+control['namespace'],['ip','netns','exec',control['namespace'],*control['command'],'serve'])
    control['process']=process
    for _ in range(60):
        if process.poll() is not None:raise ValueError('Domestic controller exited')
        result=subprocess.run([*control['command'],'users','list','--output','json'],capture_output=True,timeout=5)
        if result.returncode==0:return
        time.sleep(.5)
    raise ValueError('Domestic controller did not restart')


def prepare():
    network.require_ci();root=network.ROOT
    if root.exists():raise ValueError('Use a fresh disposable network runner')
    root.mkdir(mode=0o700);network.prepare_binaries()
    network.run('ip','link','add','rdc-wan','type','bridge');network.run('ip','link','set','rdc-wan','up')
    for index,name in enumerate(('regional','north','south'),1):
        ns=name+'-control';namespace(ns,40+index)
        network.controller(name,index,namespace_name=ns)
    from ci_certificate_lifecycle import download
    binary=root/'derper'
    download('https://github.com/kollanekirss/resilient-datacenter/releases/download/v0.2.0-alpha.1/derper-linux-amd64',binary,'1ae593bc6e4d31c774538982cd6400f6503e053d6a15f9373f98aa5e141f85e5')
    binary.chmod(0o755)
    template=Environment(loader=FileSystemLoader(network.SOURCE/'roles'),undefined=StrictUndefined).get_template('controller/templates/derp-map.yml.j2')
    for offset,authority in enumerate(('regional','north','south')):
        control=network.CONTROLLERS[authority];relays=[]
        for slot in (1,2):
            index=20+offset*2+slot;name=authority+'-relay-'+str(slot);host=name+'.ci.test'
            namespace(name,index);folder=root/name;folder.mkdir(mode=0o700);network.issue(host,folder)
            (folder/'tls.crt').rename(folder/(host+'.crt'));(folder/'tls.key').rename(folder/(host+'.key'))
            args=['ip','netns','exec',name,str(binary),'-a',':443','-http-port=-1','-stun=true','-stun-port=3478',
                  '-hostname='+host,'-certmode=manual','-certdir='+str(folder),'-c='+str(folder/'identity.key'),
                  '-verify-client-url=https://'+control['hostname']+'/verify','-verify-client-url-fail-open=false']
            item={'host':name,'hostname':host,'region_id':1000+index,'address':'172.29.10.'+str(20+index)}
            item['process']=network.spawn(name,args);item['args']=args;RELAYS[name]=item
            relays.append({k:v for k,v in item.items() if k in ('host','hostname','region_id','address')})
        path=control['folder']/'derp-map.yml';path.write_text(template.render(profile_relays=relays))
        config_path=control['folder']/'config.yaml';config=yaml.safe_load(config_path.read_text())
        config['derp']={'server':{'enabled':False},'urls':[],'paths':[str(path)],'auto_update_enabled':False}
        config_path.write_text(yaml.safe_dump(config));network.run(*control['command'],'configtest');start_controller(control)
    for index,(name,authority) in enumerate((('north-gateway','regional'),('south-gateway','regional'),('north-service','north'),('north-user','north'),('south-service','south'),('south-user','south')),1):
        network.client(name,authority,index);NAMES.append(name)
    namespace('domestic-dns',80)
    network.run('ip','netns','exec','domestic-dns','ip','address','add',DNS+'/24','dev','wan0')
    records={item['hostname']:item['address'] for item in network.CONTROLLERS.values()}
    records.update({item['hostname']:item['address'] for item in RELAYS.values()})
    records.update({'matrix.'+name+'.ci.test':network.NODES[name+'-service']['address'] for name in ('north','south')})
    config=['server:','    interface: '+DNS,'    username: unbound','    chroot: ""','    directory: /etc/unbound',
            '    pidfile: ""','    do-ip6: no','    access-control: 172.29.10.0/24 allow','    local-zone: "." refuse']
    for host,address in records.items():config+=['    local-zone: "'+host+'." static','    local-data: "'+host+'. 30 IN A '+address+'"']
    Path('/etc/unbound/rdc-domestic-ci.conf').write_text('\n'.join(config)+'\n')
    network.spawn('domestic-dns',['ip','netns','exec','domestic-dns','unbound','-d','-c','/etc/unbound/rdc-domestic-ci.conf'])
    for name in NAMES:
        folder=Path('/etc/netns')/name
        (folder/'hosts').write_text('127.0.0.1 localhost\n')
        (folder/'resolv.conf').write_text('nameserver '+DNS+'\noptions timeout:1 attempts:1\n')
    for name,item in RELAYS.items():
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if item['process'].poll() is not None:raise ValueError('Domestic relay exited: '+name)
            probe=subprocess.run(['ip','netns','exec',name,'curl','--noproxy','*','--silent','--fail',
                '--connect-timeout','2','--max-time','4','https://'+item['hostname']+'/derp/probe'],capture_output=True,timeout=6)
            if probe.returncode==0:break
            time.sleep(.5)
        else:raise ValueError('Domestic relay TLS probe did not become ready: '+name)
    print('All six production relay processes passed trusted TLS readiness probes.',flush=True)
    # A known reachable endpoint stands in for outside-region infrastructure.
    # It stays alive after the cut to distinguish network denial from server loss.
    network.run('ip','address','add',FOREIGN+'/24','dev','rdc-wan')
    script=root/'outside-canary.py';script.write_text('''import http.server
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'outside-canary')
 def log_message(self,*args):pass
http.server.HTTPServer(('172.29.10.250',8080),Handler).serve_forever()
''')
    network.spawn('outside-canary',[sys.executable,str(script)])
    for _ in range(30):
        if canary('north-user'):break
        time.sleep(.5)
    else:raise ValueError('Outside-region positive control did not become reachable')
    return network.NODES


def canary(name=None):
    prefix=['ip','netns','exec',name] if name else []
    result=subprocess.run([*prefix,'curl','--noproxy','*','--silent','--max-time','2','http://'+FOREIGN+':8080/'],capture_output=True,timeout=4)
    return result.returncode==0 and result.stdout==b'outside-canary'


def cut():
    bootstrap=[DNS,*[c['address'] for c in network.CONTROLLERS.values()],*[r['address'] for r in RELAYS.values()]]
    participants=set(bootstrap+['172.29.10.141','172.29.10.142'])
    for name in NAMES:
        for link in json.loads(network.run('ip','-n',name,'-j','address','show','dev','wan0')):
            participants.update(a['local'] for a in link['addr_info'] if a['family']=='inet')
        if not canary(name):raise ValueError('Missing pre-cut outside positive control: '+name)
    for name in NAMES:network.run('ip','netns','exec',name,'nft','-f','-',input=cut_rules(bootstrap,sorted(participants)))
    for name in NAMES:
        if canary(name):raise ValueError('Outside-region path survived isolation: '+name)
    if not canary():raise ValueError('Outside-region canary died; negative controls invalid')
    print('Outside canary reachable before cut, blocked afterward from every controller, relay, resolver and client; canary remains alive PASS.',flush=True)


def restart(name,*,change_address=None,require_running=True):
    item=network.NODES[name];old=item['process']
    if old.poll() is None:old.terminate();old.wait(timeout=15)
    if old.poll() is None:raise ValueError('Field client process did not stop')
    if change_address:
        network.run('ip','-n',name,'address','flush','dev','wan0','scope','global')
        network.run('ip','-n',name,'address','add',change_address+'/24','dev','wan0')
    socket=item['folder']/'tailscale.sock';socket.unlink(missing_ok=True)
    item['process']=network.spawn('restarted-'+name,restart_command(name,network.ROOT),env=dict(os.environ,TS_NO_LOGS_NO_SUPPORT='true'))
    for _ in range(60):
        if item['process'].poll() is not None:raise ValueError('Restarted field client exited')
        if socket.exists():
            if not require_running:return
            data=subprocess.run([*item['command'],'status','--json'],capture_output=True,text=True,timeout=5)
            if data.returncode==0:
                state=json.loads(data.stdout)
                if state.get('BackendState')=='Running':
                    identity=state['Self']
                    if identity['PublicKey']!=item['public_key'] or item['address'] not in identity['TailscaleIPs']:raise ValueError('Restart changed field identity')
                    return
        time.sleep(.5)
    raise ValueError('Prepared field identity did not restart')


def peer_relay(user,service):
    status=json.loads(network.run(*network.NODES[user]['command'],'status','--json'))
    peer=next(p for p in status['Peer'].values() if network.NODES[service]['public_key']==p['PublicKey'])
    if peer.get('CurAddr'):raise ValueError('Direct path invalidates relay-loss evidence')
    code=peer.get('Relay')
    name=next((name for name,item in RELAYS.items() if code=='rdc'+str(item['region_id'])),None)
    if name is None:raise ValueError('No approved relay observed')
    return name

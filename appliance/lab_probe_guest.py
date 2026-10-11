"""Actual neutral guest console and short-lived peers inside the disposable PVE VM.

No namespace, bridge or VM in this module exists on the machine running the lab:
lab_guest verifies the fresh QEMU SMBIOS identity before invoking it. Temporary
peers are removed before any product host audit; they never change host routes,
forwarding, firewall rules or the site's persistent configuration.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import time

from .contracts import ApplianceError, canonical, require
from . import probe, proxmox, state


def python_command(source,parameters,nonce):
    require(type(source) is str and len(source)<100000 and re.fullmatch('[0-9a-f]{32}',nonce),'lab-console-program')
    program='import base64,json; p=json.loads(base64.b64decode('+repr(base64.b64encode(canonical(parameters)).decode())+')); '+source
    wrapped='import base64; exec(base64.b64decode('+repr(base64.b64encode(program.encode()).decode())+'))'
    return 'python3 -c '+shlex.quote(wrapped)


class ProbeConsole:
    def __init__(self,vmid,password):
        require(type(vmid) is int and 100<=vmid<=999999999,'lab-probe-vmid')
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(1);self.buffer=bytearray()
        path='/var/run/qemu-server/'+str(vmid)+'.serial0';deadline=time.monotonic()+180
        while True:
            try:self.socket.connect(path);break
            except (FileNotFoundError,ConnectionRefusedError):
                require(time.monotonic()<deadline,'lab-probe-console-unavailable');time.sleep(.2)
        self.socket.sendall(b'\r')
        marker=self.wait_any((b'login:',b'probe@'),180)
        if marker==b'login:':
            self.socket.sendall(b'probe\r');self.wait_any((b'Password:',),30)
            self.socket.sendall(password.encode()+b'\r');self.wait_any((b'probe@',),60)
        self.socket.sendall(b"stty -icanon -echo min 1 time 0; export PS1='RDC-PROBE-SHELL> '\r")
        self.wait_any((b'RDC-PROBE-SHELL> ',),30)
    def wait_any(self,markers,timeout):
        deadline=time.monotonic()+timeout
        while True:
            for marker in markers:
                index=self.buffer.find(marker)
                if index>=0:self.buffer=self.buffer[index+len(marker):];return marker
            require(time.monotonic()<deadline and len(self.buffer)<2*1024*1024,'lab-probe-console-timeout')
            try:raw=self.socket.recv(65536)
            except TimeoutError:continue
            require(raw,'lab-probe-console-closed');self.buffer.extend(raw)
    def call(self,source,parameters=None,timeout=60):
        nonce=secrets.token_hex(16);marker=('RDC-PROBE-'+nonce+' ').encode()
        program=source.rstrip()+'\nprint('+repr(marker.decode())+'+json.dumps(result,separators=(",",":")),flush=True)'
        command=python_command(program,parameters or {},nonce)
        self.buffer.clear();self.socket.sendall(command.encode()+b'\r');self.wait_any((marker,),timeout)
        deadline=time.monotonic()+10
        while b'\n' not in self.buffer:
            require(time.monotonic()<deadline,'lab-probe-response-timeout')
            try:self.buffer.extend(self.socket.recv(65536))
            except TimeoutError:continue
        line,_,remaining=self.buffer.partition(b'\n');self.buffer=bytearray(remaining)
        try:return json.loads(line)
        except ValueError:raise ApplianceError('lab-probe-response') from None
    def close(self):self.socket.close()


CHECK_PROGRAM="""import os,subprocess; result={'cloud_init':subprocess.run(['/usr/bin/cloud-init','status','--wait','--format','json'],capture_output=True,text=True,timeout=180).stdout,'links':json.loads(subprocess.check_output(['/usr/sbin/ip','-json','address','show'])),'ipv6':subprocess.check_output(['/usr/sbin/ip','-6','address','show']).decode(),'identity':json.load(open('/etc/rdc-probe.json')),'roles_present':[x for x in ('/etc/headscale','/var/lib/tailscale','/var/lib/headscale','/usr/local/bin/derper') if os.path.exists(x)],'user':os.getuid()}"""


def setup_probe(plan,release,runner,private,credentials,*,attach=True):
    work=Path(private).parent/'lab';seed=work/'probe-seed.iso'
    probe.build_seed(plan,seed,runner,password_hash=credentials['password_hash'],ssh_public_key=credentials['ssh_public'])
    probe.prepare_probe(plan,release,Path(private).parent/'media/probe-image',seed,runner,private)
    probe.start_probe(plan,runner,private)
    console=ProbeConsole(plan['vms']['probe']['vmid'],credentials['password'])
    try:
        actual=console.call(CHECK_PROGRAM,timeout=240)
        status=json.loads(actual['cloud_init']);spec,nic,_=probe._site(plan)
        interfaces=[i for i in actual['links'] if i['ifname']!='lo']
        checks={'cloud_init_done':status.get('status')=='done' and not status.get('errors'),
            'workload_mac_address':len(interfaces)==1 and interfaces[0]['address']==nic['mac']
                and any(a['local']==nic['address'] for a in interfaces[0].get('addr_info',[])),
            'ipv6_disabled':actual['ipv6'].strip()=='',
            'no_optional_roles':actual['roles_present']==[] and actual['identity']['role']=='neutral-probe',
            'unique_login':actual['user']>0}
        require(all(checks.values()),'lab-probe-console-checks')
        attestation=probe.attest_console(plan,checks,runner,private)
        result=probe.attach_workload(plan,runner,private,attestation=attestation) if attach else proxmox.observe_vm(spec['vmid'],runner)
        # Only the source-pinned wire client is transferred, as ordinary probe
        # user data, through this inspected serial console. No guest agent/key.
        module=Path(__file__).with_name('lab_probe.py').read_bytes()
        ca=state.read(work/'tls.json')['ca_pem']
        console.call("from pathlib import Path; Path('/home/probe/rdc_lab_probe.py').write_bytes(base64.b64decode(p['code'])); Path('/home/probe/rdc_lab_ca.pem').write_text(p['ca']); result={'code_sha256':__import__('hashlib').sha256(Path('/home/probe/rdc_lab_probe.py').read_bytes()).hexdigest()}",
            {'code':base64.b64encode(module).decode(),'ca':ca})
        return {'vmid':spec['vmid'],'boot_id':result['boot_id'],'console_observations':actual}
    finally:console.close()


def attach_probe(plan,runner,private,credentials):
    record=probe._read(plan,private)
    if record['connected']:return probe._observe(record,runner)
    console=ProbeConsole(plan['vms']['probe']['vmid'],credentials['password'])
    try:
        actual=console.call(CHECK_PROGRAM,timeout=240);status=json.loads(actual['cloud_init']);spec,nic,_=probe._site(plan)
        interfaces=[i for i in actual['links'] if i['ifname']!='lo']
        checks={'cloud_init_done':status.get('status')=='done' and not status.get('errors'),
            'workload_mac_address':len(interfaces)==1 and interfaces[0]['address']==nic['mac']
                and any(a['local']==nic['address'] for a in interfaces[0].get('addr_info',[])),
            'ipv6_disabled':actual['ipv6'].strip()=='','no_optional_roles':actual['roles_present']==[]
                and actual['identity']['role']=='neutral-probe','unique_login':actual['user']>0}
        return probe.attach_workload(plan,runner,private,attestation=probe.attest_console(plan,checks,runner,private))
    finally:console.close()


def peer_parameters(plan,zone,*,offset=20):
    require(zone in plan['networks'] and zone in ('management','infrastructure','workload','relay'),'lab-peer-zone')
    network=plan['networks'][zone];bridge=network['bridge']
    require(re.fullmatch('vmbr[0-4]',bridge),'lab-peer-bridge')
    subnet=ipaddress.IPv4Network(network['cidr']);address=subnet.network_address+offset
    require(address<subnet.broadcast_address and str(address)!=network['gateway'],'lab-peer-address')
    return {'address':str(address),'prefix':subnet.prefixlen,'gateway':network['gateway'],'bridge':bridge}


@contextmanager
def peer_namespace(plan,zone,runner,*,offset=20):
    item=peer_parameters(plan,zone,offset=offset);name='rdclab'+secrets.token_hex(4);host=name+'h';guest=name+'g'
    created=False
    try:
        existing=json.loads(runner.run(['/usr/sbin/ip','-json','netns','list']).stdout)
        require(not any(n.get('name')==name for n in existing),'lab-peer-collision')
        runner.run(['/usr/sbin/ip','netns','add',name]);created=True
        runner.run(['/usr/sbin/ip','link','add',host,'type','veth','peer','name',guest])
        runner.run(['/usr/sbin/ip','link','set',guest,'netns',name])
        runner.run(['/usr/sbin/ip','link','set',host,'master',item['bridge']]);runner.run(['/usr/sbin/ip','link','set',host,'up'])
        for argv in (['link','set','lo','up'],['address','add',item['address']+'/'+str(item['prefix']),'dev',guest],
            ['link','set',guest,'up'],['route','add','default','via',item['gateway']]):
            runner.run(['/usr/sbin/ip','-n',name,*argv])
        yield name,item
    finally:
        if created:
            # No peer processes survive this context; callers close listener
            # handles before this deletion. Kernel removes only its veth pair.
            runner.run(['/usr/sbin/ip','netns','delete',name])


CONTROL_PROGRAM = """import http.server,threading
class Control(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(args['nonce'].encode())
    def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),Control)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
    control=probe_network('http',host='127.0.0.1',port=server.server_port,nonce=args['nonce'])
    result=probe_network(kind,**args)
    result['source_control']=control
finally:
    server.shutdown();server.server_close();thread.join(5)
"""


def _client_in_namespace(namespace,kind,args,runner):
    source="import sys,json;sys.path.insert(0,'/usr/lib/rdc-appliance');from appliance.lab_probe import probe_network;kind=sys.argv[1];args=json.loads(sys.argv[2]);exec("+repr(CONTROL_PROGRAM)+");print(json.dumps(result))"
    command=['/usr/bin/python3','-c',source,kind,canonical(args).decode()]
    if namespace:command=['/usr/sbin/ip','netns','exec',namespace,*command]
    result=runner.run(command,timeout_s=40)
    return json.loads(result.stdout)


def _client_probe(plan,kind,args,runner,private):
    credentials=state.read(Path(private).parent/'lab/credentials.json')
    console=ProbeConsole(plan['vms']['probe']['vmid'],credentials['password'])
    try:
        if args.get('ca_file'):
            pem=Path(args['ca_file']).read_text()
            console.call("from pathlib import Path; Path('/home/probe/rdc_request_ca.pem').write_text(p['pem']);result={}",{'pem':pem})
            args={**args,'ca_file':'/home/probe/rdc_request_ca.pem'}
        source="import sys;sys.path.insert(0,'/home/probe');from rdc_lab_probe import probe_network;kind=p['kind'];args=p['args'];exec("+repr(CONTROL_PROGRAM)+")"
        return console.call(source,{'kind':kind,'args':args},timeout=45)
    finally:console.close()


@contextmanager
def source_client(plan,zone,runner,private):
    if zone=='host':yield lambda kind,args:_client_in_namespace(None,kind,args,runner),plan['networks']['management']['host_ip']
    elif zone=='workload' and probe._read(plan,private)['connected'] and proxmox.observe_vm(plan['vms']['probe']['vmid'],runner)['running']:
        yield lambda kind,args:_client_probe(plan,kind,args,runner,private),probe._site(plan)[1]['address']
    else:
        with peer_namespace(plan,zone,runner) as (namespace,item):
            yield lambda kind,args:_client_in_namespace(namespace,kind,args,runner),item['address']


@contextmanager
def listener(namespace,address,nonce):
    # A real listening HTTP endpoint with a bounded lifetime and private token.
    program="import http.server,sys; nonce=sys.argv[2]; H=type('H',(http.server.BaseHTTPRequestHandler,),{'do_GET':lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(nonce.encode())), 'log_message':lambda *a:None});http.server.HTTPServer((sys.argv[1],18080),H).serve_forever()"
    args=['/usr/bin/python3','-u','-c',program,address,nonce]
    if namespace:args=['/usr/sbin/ip','netns','exec',namespace,*args]
    process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
    try:
        require(process.poll() is None,'lab-listener-failed');time.sleep(.1);yield
    finally:
        import signal
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait(timeout=5)


def guest_probe(plan,parameters,runner,private):
    nonce=parameters['nonce'];kind=parameters['kind'];zone=parameters.get('zone','management')
    require(re.fullmatch('[0-9a-f]{32}',nonce),'lab-probe-challenge')
    ca=Path(private).parent/'lab/ca.pem'
    if not ca.exists():ca.write_text(state.read(Path(private).parent/'lab/tls.json')['ca_pem']);ca.chmod(0o600)
    if kind in ('dns','ntp','https'):
        destination=plan['networks']['management' if zone=='host' else zone]['gateway'] if kind in ('dns','ntp') else parameters['peer_address']
        args={'host':destination,'nonce':nonce,'timeout_s':10}
        if kind=='dns' and parameters.get('query_name'):args['query_name']=parameters['query_name']
        if kind=='https':args.update(ca_file=str(ca),server_name='lab.invalid')
        with source_client(plan,zone,runner,private) as (client,address):
            result=client(kind,args)
        return {**result,'expected_address':parameters['peer_address'],'source':address}
    if kind=='cross-zone':
        source,destination=parameters['source'],parameters['destination']
        with peer_namespace(plan,destination,runner,offset=21) as (ns,endpoint):
            args={'host':endpoint['address'],'port':18080,'nonce':nonce,'timeout_s':5}
            with listener(ns,endpoint['address'],nonce):
                control=_client_in_namespace(ns,'http',args,runner)
                with source_client(plan,source,runner,private) as (client,address):attempt=client('http',args)
        return {**attempt,'destination_control':control,'source':address}
    if kind in ('zone-admin','management','wan-admin'):
        targets=('host','router') if parameters.get('target')=='both' else (parameters.get('target','host'),)
        checks=[]
        for target in targets:
            address=plan['networks']['management']['host_ip' if target=='host' else 'gateway'];port=8006 if target=='host' else 443
            # Certificate pin is obtained through the local guest/helper console,
            # not discovered from an unauthenticated blocked network.
            if target=='host':pem=Path('/etc/pve/local/pve-ssl.pem').read_bytes()
            else:
                from .lab_router import router_certificate
                pem=router_certificate(plan,runner,private).encode()
            import ssl
            der=ssl.PEM_cert_to_DER_cert(pem.decode());digest=hashlib.sha256(der).hexdigest()
            cert=Path(private).parent/'lab'/('admin-'+target+'.pem');cert.write_bytes(pem);cert.chmod(0o600)
            trust=Path('/etc/pve/pve-root-ca.pem').read_bytes() if target=='host' else pem
            trust_file=cert.with_suffix('.ca.pem');trust_file.write_bytes(trust);trust_file.chmod(0o600)
            # Hostname comes from the pinned console certificate itself; the
            # exact DER hash is independently checked by the scenario.
            names=ssl._ssl._test_decode_cert(str(cert))
            hostname=next((v for k,v in names.get('subjectAltName',[]) if k=='DNS'),None)
            if hostname is None:hostname=next(v for group in names['subject'] for k,v in group if k=='commonName')
            args={'host':address,'port':port,'nonce':nonce,'timeout_s':5,'ca_file':str(trust_file),'server_name':hostname}
            with source_client(plan,'host',runner,private) as (client,_):control=client('https',args)
            with source_client(plan,zone,runner,private) as (client,source):attempt=client('https',args)
            checks.append({'target':target,'certificate_pem':pem.decode(),'ca_pem':trust.decode(),'server_name':hostname,'expected_certificate_sha256':digest,'attempt':attempt,'destination_control':control,'source_control':attempt.get('source_control')})
        return {'nonce':nonce,'admin_checks':checks}
    raise ApplianceError('lab-probe-kind')


FLOW_PROGRAM = r'''
import json,os,socket,ssl,sys,time
path,host,port,nonce,ca=sys.argv[1:]; context=ssl.create_default_context(cafile=ca);context.minimum_version=ssl.TLSVersion.TLSv1_2
remote=context.wrap_socket(socket.create_connection((host,int(port)),timeout=5),server_hostname='lab.invalid');remote.settimeout(5)
remote.sendall(('RDCFLOW '+nonce+'\n').encode());answer=remote.recv(1024).decode().strip()
initial={'returncode':0 if answer==nonce else 1,'stdout':answer,'stderr':''}
source=list(remote.getsockname());destination=list(remote.getpeername())
control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);control.bind(path);os.chmod(path,0o600);control.listen(1);control.settimeout(180)
try:
    for index in range(2):
        client,_=control.accept();client.settimeout(5);request=json.loads(client.recv(4096))
        if request['action']=='before':result={'before':initial,'source':source,'destination':destination,'nonce':nonce}
        else:
            try:
                remote.sendall(('RDCFLOW '+request['nonce']+'\n').encode());body=remote.recv(1024).decode().strip()
                after={'returncode':0 if body==request['nonce'] else 1,'stdout':body,'stderr':''}
            except (OSError,TimeoutError):after={'returncode':28,'stdout':'','stderr':'socket-withdrawn'}
            result={'after':after,'source':source,'destination':destination,'nonce':request['nonce']}
        client.sendall(json.dumps(result).encode());client.close()
finally:
    remote.close();control.close();os.unlink(path)
'''


def forwarding_state(plan,parameters,runner,private):
    operation=parameters.get('operation');require(operation in ('open','check'),'lab-flow-action')
    work=Path(private).parent/'lab';credentials=state.read(work/'credentials.json')
    connection=secrets.token_hex(16) if operation=='open' else parameters.get('connection')
    require(type(connection) is str and re.fullmatch('[0-9a-f]{32}',connection),'lab-flow-connection')
    nonce=parameters.get('nonce') or secrets.token_hex(16);path='/home/probe/.rdc-flow-'+connection+'.sock'
    console=ProbeConsole(plan['vms']['probe']['vmid'],credentials['password'])
    try:
        if operation=='open':
            program="import subprocess,sys;child=subprocess.Popen([sys.executable,'-c',p['program'],p['path'],p['host'],'443',p['nonce'],'/home/probe/rdc_lab_ca.pem'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);result={'pid':child.pid}"
            started=console.call(program,{'program':FLOW_PROGRAM,'path':path,'host':parameters['peer_address'],'nonce':nonce})
            state.write(work/('flow-'+connection+'.json'),{'connection':connection,'pid':started['pid'],'nonce':nonce})
        else:require(state.read(work/('flow-'+connection+'.json'))['connection']==connection,'lab-flow-binding')
        # The control socket is private inside the neutral probe. Missing or
        # expired harness processes are failures, never blocked-flow evidence.
        program="""import socket,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);deadline=time.monotonic()+15
while True:
    try:s.connect(p['path']);break
    except FileNotFoundError:
        if time.monotonic()>=deadline:raise
        time.sleep(.1)
s.sendall(json.dumps(p['request']).encode());result=json.loads(s.recv(65536));s.close()
"""
        data=console.call(program,{'path':path,'request':{'action':'before' if operation=='open' else 'check','nonce':nonce}},timeout=35)
        data.update(connection=connection)
        if operation=='check':
            from .router import collect_router
            observed=collect_router(plan,runner);table=observed.get('state_table')
            require(type(table) is str,'lab-pf-states-unobserved')
            source,port=data['source'];destination,dport=data['destination']
            data['pf_state_matches']=[line for line in table.splitlines() if source in line and destination in line and str(port) in line]
        return data
    finally:console.close()

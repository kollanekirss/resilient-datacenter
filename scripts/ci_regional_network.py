#!/usr/bin/env python3
"""Real isolated Headscale/Tailscale memberships on disposable Ubuntu only.

Each Linux namespace represents one machine with one ordinary Tailscale client.
The three controllers and their embedded DERP fixtures are separate processes;
this test is not evidence for physical site diversity or the production relay.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
import yaml
from jinja2 import Environment,FileSystemLoader,StrictUndefined

ROOT=Path('/var/lib/rdc-regional-network-ci')
SOURCE=Path(__file__).resolve().parents[1]
PROCESSES=[]
CONTROLLERS={}
NODES={}


def require_ci():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise ValueError('Disposable GitHub-hosted Ubuntu 24.04 only')


def run(*args,input=None,timeout=60):
    try:return subprocess.run(list(args),input=input,check=True,capture_output=True,text=True,timeout=timeout).stdout
    except subprocess.CalledProcessError as error:
        lines=(error.stderr or '').splitlines()[-30:]
        detail='\n'.join(line[:500] for line in lines if not any(term in line.lower() for term in ('auth','token','key=','key:','register')))
        print('Disposable native command failed: '+detail,flush=True)
        raise


def spawn(name,args,*,env=None):
    log=(ROOT/(name+'.log')).open('w');process=subprocess.Popen(args,stdout=log,stderr=log,env=env)
    PROCESSES.append(process);return process


def issue(hostname,folder):
    import ci_matrix_services as fixture
    fixture.MATRIX=hostname;fixture.ELEMENT='unused.'+hostname
    cert,key=fixture.certificates()
    (folder/'tls.crt').write_bytes(cert.read_bytes());(folder/'tls.key').write_bytes(key.read_bytes());(folder/'tls.key').chmod(0o600)


def prepare_binaries():
    from ci_certificate_lifecycle import download
    versions=yaml.safe_load((SOURCE/'versions.yml').read_text())
    deb=ROOT/'headscale.deb';version=versions['headscale_version']
    download('https://github.com/juanfont/headscale/releases/download/v'+version+'/headscale_'+version+'_linux_amd64.deb',deb,versions['headscale_sha256'])
    run('dpkg-deb','--extract',str(deb),str(ROOT/'headscale-package'))
    version=versions['tailscale_version'];archive=ROOT/'tailscale.tgz'
    download('https://pkgs.tailscale.com/stable/tailscale_'+version+'_amd64.tgz',archive,versions['tailscale_sha256'])
    # Extract only the two exact reviewed archive members, never archive paths.
    with tarfile.open(archive) as package:
        for name in ('tailscale','tailscaled'):
            member=package.getmember('tailscale_'+version+'_amd64/'+name)
            if not member.isfile():raise ValueError('Expected one regular client binary')
            with package.extractfile(member) as stream:(ROOT/name).write_bytes(stream.read())
            (ROOT/name).chmod(0o755)


def controller(name,index):
    folder=ROOT/name;folder.mkdir(mode=0o700);hostname=name+'.control.ci.test';address='172.29.10.'+str(index+1)
    run('ip','address','add',address+'/24','dev','rdc-wan')
    issue(hostname,folder)
    template=Environment(loader=FileSystemLoader(SOURCE/'roles'),undefined=StrictUndefined).get_template('controller/templates/config.yaml.j2')
    config=yaml.safe_load(template.render(headscale_hostname=hostname))
    config.update(listen_addr=address+':443',metrics_listen_addr='',grpc_listen_addr='127.0.0.1:'+str(50443+index),unix_socket=str(folder/'control.sock'))
    config['noise']['private_key_path']=str(folder/'noise.key')
    config['database']['sqlite']['path']=str(folder/'database.sqlite')
    config['tls_cert_path']=str(folder/'tls.crt');config['tls_key_path']=str(folder/'tls.key')
    config['policy']['path']=str(folder/'policy.json');config['dns']['base_domain']=name+'.internal.ci.test'
    config['log']['level']='warn'
    config['derp']={'server':{'enabled':True,'region_id':901+index,'region_code':name,'region_name':'Disposable '+name,
                    'verify_clients':True,'stun_listen_addr':address+':3478','private_key_path':str(folder/'derp.key'),
                    'automatically_add_embedded_derp_region':True,'ipv4':address},'urls':[],'paths':[],'auto_update_enabled':False}
    (folder/'config.yaml').write_text(yaml.safe_dump(config))
    (folder/'policy.json').write_text(json.dumps({'grants':[{'src':['*'],'dst':['*'],'ip':['tcp:443']}]}))
    binary=str(ROOT/'headscale-package/usr/bin/headscale');command=[binary,'--config',str(folder/'config.yaml')]
    run(*command,'configtest')
    process=spawn('controller-'+name,[*command,'serve'])
    for _ in range(60):
        if (folder/'control.sock').exists():break
        if process.poll() is not None:raise ValueError('Controller failed to start: '+name)
        time.sleep(.5)
    else:raise ValueError('Controller socket did not appear')
    user=json.loads(run(*command,'users','create','ci-operator','--output','json'))
    result={'folder':folder,'hostname':hostname,'address':address,'command':command,'process':process,'user_id':str(user['id'])}
    CONTROLLERS[name]=result;return result


def namespace(name,index):
    run('ip','netns','add',name)
    host='rdcw'+str(index);peer='rdcp'+str(index)
    run('ip','link','add',host,'type','veth','peer','name',peer)
    run('ip','link','set',host,'master','rdc-wan');run('ip','link','set',host,'up')
    run('ip','link','set',peer,'netns',name);run('ip','netns','exec',name,'ip','link','set',peer,'name','wan0')
    run('ip','netns','exec',name,'ip','address','add','172.29.10.'+str(20+index)+'/24','dev','wan0')
    run('ip','netns','exec',name,'ip','link','set','wan0','up');run('ip','netns','exec',name,'ip','link','set','lo','up')
    etc=Path('/etc/netns')/name;etc.mkdir(parents=True)
    (etc/'hosts').write_text('127.0.0.1 localhost\n'+'\n'.join(item['address']+' '+item['hostname'] for item in CONTROLLERS.values())+'\n')
    # The lab has no general internet route. Static hosts bootstrap controllers;
    # application DNS is supplied separately as an explicit test fixture.
    (etc/'resolv.conf').write_text('nameserver 127.0.0.1\noptions timeout:1 attempts:1\n')


def client(name,controller_name,index):
    namespace(name,index);folder=ROOT/name;folder.mkdir(mode=0o700)
    control=CONTROLLERS[controller_name]
    key=json.loads(run(*control['command'],'preauthkeys','create','--user',control['user_id'],'--expiration','5m','--output','json'))
    auth=folder/'one-use-auth.key';auth.write_text(key['key']);auth.chmod(0o600)
    socket=str(folder/'tailscale.sock')
    environment=dict(os.environ,TS_NO_LOGS_NO_SUPPORT='true')
    spawn('client-'+name,['ip','netns','exec',name,str(ROOT/'tailscaled'),'--state='+str(folder/'tailscaled.state'),'--socket='+socket,'--tun=tailscale0','--port=41641'],env=environment)
    for _ in range(60):
        if Path(socket).exists():break
        time.sleep(.25)
    command=['ip','netns','exec',name,str(ROOT/'tailscale'),'--socket='+socket]
    try:run(*command,'up','--login-server=https://'+control['hostname'],'--hostname='+name,'--auth-key=file:'+str(auth),'--accept-dns=false','--accept-routes=false','--ssh=false','--timeout=60s',timeout=75)
    finally:auth.unlink(missing_ok=True)
    status=json.loads(run(*command,'status','--json'));prefs=json.loads(run(*command,'debug','prefs'))
    if status['BackendState']!='Running' or prefs['ControlURL'].rstrip('/')!='https://'+control['hostname'] or prefs.get('AdvertiseRoutes'):raise ValueError('Actual client membership differs from its one selected controller')
    address=next(value for value in status['Self']['TailscaleIPs'] if '.' in value)
    result={'name':name,'controller':controller_name,'command':command,'address':address,'public_key':status['Self']['PublicKey'],'folder':folder}
    NODES[name]=result;return result


def prepare():
    require_ci();ROOT.mkdir(mode=0o700)
    prepare_binaries();run('ip','link','add','rdc-wan','type','bridge');run('ip','link','set','rdc-wan','up')
    for index,name in enumerate(('regional','north','south'),1):controller(name,index)
    for index,(name,authority) in enumerate((('north-gateway','regional'),('south-gateway','regional'),('north-service','north'),('north-user','north'),('south-service','south'),('south-user','south'),('outsider','regional')),1):client(name,authority,index)
    keys={item['public_key'] for item in NODES.values()};assert len(keys)==7
    for item in NODES.values():
        status=json.loads(run(*item['command'],'status','--json'))
        visible=set((status.get('Peer') or {}).keys())
        other={peer['public_key'] for peer in NODES.values() if peer['controller']!=item['controller']}
        assert not visible&other,'A node saw peers from an independent controller'
    # All authorities allocate the same overlay range; distinct namespaces keep
    # the ordinary clients separate instead of inventing dual-tailnet membership.
    assert NODES['north-service']['address']==NODES['south-service']['address']
    print('Actual pinned Headscale/Tailscale: three independent controllers, seven separate single-membership clients, distinct node keys, overlapping internal address ranges and no cross-controller peer visibility PASS.',flush=True)
    return NODES


def cleanup():
    for process in reversed(PROCESSES):
        if process.poll() is None:process.terminate()
    for process in reversed(PROCESSES):
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill()


if __name__=='__main__':
    try:prepare()
    finally:cleanup()

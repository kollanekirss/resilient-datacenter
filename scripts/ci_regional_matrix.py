#!/usr/bin/env python3
"""Real Matrix exchange across two institutions' independent overlay networks.

Uses the product's pinned images and generated configuration. Per-node container
launches are fixture orchestration; the separate package workflows test installers.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
import ci_regional_network as network
import regional_agreements as agreements
import gateway_contracts
import gateway_rendering
import gateway_runtime
import service_contracts
import service_rendering
import service_runtime
import service_regional
import service_link
from setup_contracts import local_ownership
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTAINERS=[]
ROOT=network.ROOT


def client_main():
    network.require_ci();data=json.load(sys.stdin)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    headers={'Content-Type':'application/json'}
    if data.get('token'):headers['Authorization']='Bearer '+data['token']
    body=json.dumps(data['data']).encode() if data.get('data') is not None else None
    try:
        response=opener.open(urllib.request.Request(data['url'],data=body,headers=headers,method=data['method']),timeout=data.get('timeout',45))
        raw=response.read(2*1024*1024);status=response.status
    except urllib.error.HTTPError as error:raw=error.read(1024*1024);status=error.code
    except (OSError,urllib.error.URLError):print(json.dumps({'status':0,'body':'connection-unavailable'}));return
    try:body=json.loads(raw)
    except (ValueError,UnicodeError):body=raw.decode(errors='replace')[:2000]
    print(json.dumps({'status':status,'body':body}))


def request(node,method,url,data=None,token=None,*,timeout=45):
    result=json.loads(network.run('ip','netns','exec',node,sys.executable,str(Path(__file__)), 'client',
        input=json.dumps({'method':method,'url':url,'data':data,'token':token,'timeout':timeout}),timeout=timeout+15))
    return result


def api(node,method,host,path,data=None,token=None):
    result=request(node,method,'https://'+host+path,data,token)
    if not 200<=result['status']<300:raise ValueError('Matrix API '+method+' '+path.split('?')[0]+' failed: '+str(result['status'])+' '+str(result['body'])[:1500])
    return result['body']


def dns_main():
    network.require_ci();listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);listener.bind(('127.0.0.1',53))
    while True:
        data,address=listener.recvfrom(4096)
        if len(data)>=12:listener.sendto(data[:2]+b'\x81\x83'+data[4:6]+b'\x00\x00\x00\x00'+data[10:12]+data[12:],address)


def private_lan(institution,index):
    gateway=institution+'-gateway';service=institution+'-service';left='rdcl'+str(index);right='rdcr'+str(index)
    network.run('ip','link','add',left,'type','veth','peer','name',right)
    for iface,node,name,address in ((left,gateway,'lan0','10.203.'+str(index)+'.1'),(right,service,'regional0','10.203.'+str(index)+'.10')):
        network.run('ip','link','set',iface,'netns',node);network.run('ip','netns','exec',node,'ip','link','set',iface,'name',name)
        network.run('ip','netns','exec',node,'ip','address','add',address+'/24','dev',name);network.run('ip','netns','exec',node,'ip','link','set',name,'up')
    network.run('ip','netns','exec',gateway,'sysctl','-w','net.ipv4.ip_forward=0','net.ipv6.conf.all.forwarding=0')
    network.spawn(institution+'-dns',['ip','netns','exec',service,sys.executable,str(Path(__file__)),'dns'])


def launch(node,name,command):
    # The normal product command runs in the foreground under systemd. This
    # fixture runs it detached inside the node's real isolated network namespace.
    arguments=list(command);arguments.insert(arguments.index('run')+1,'--detach')
    network.run('ip','netns','exec',node,*arguments,timeout=120);CONTAINERS.append(name)


def setup_application(institution,index,identity,document):
    folder=ROOT/(institution+'-application');folder.mkdir(mode=0o700)
    config=folder/'config';config.mkdir(mode=0o700)
    state=folder/'state';state.mkdir(mode=0o700)
    tls=folder/'tls';tls.mkdir(mode=0o700);host='matrix.'+institution+'.ci.test';network.issue(host,tls)
    local=local_ownership({'kind':'local-node','schema_version':1,'institution_id':institution,'node_name':institution+'-service',
                           'headscale_hostname':network.CONTROLLERS[institution]['hostname'],'node_tag':'tag:services'})
    profile={'kind':'matrix-services','schema_version':1,'institution_id':institution,'node_name':institution+'-service','matrix_hostname':host,
             'element_hostname':'unused.'+host,'tls_mode':'supplied','tls_certificate':str(tls/'tls.crt'),'tls_private_key':str(tls/'tls.key')}
    settings={'schema_version':1,'ownership':service_contracts.ownership(profile,local),'bind_address':network.NODES[institution+'-service']['address'],'components':service_contracts.image_pins()}
    generated={key:secrets.token_hex(32) for key in ('database_password','registration_secret','macaroon_secret','form_secret')}
    for name,uid in (('postgres',999),('synapse',991)):
        (state/name).mkdir(mode=0o700);os.chown(state/name,uid,uid)
    synapse=config/'synapse';synapse.mkdir(mode=0o750);os.chown(synapse,0,991)
    for name,text in (('homeserver.yaml',service_rendering.synapse(profile,generated)),('log.config',service_rendering.logging_config())):
        (synapse/name).write_text(text);os.chown(synapse/name,0,991);(synapse/name).chmod(0o640)
    password=config/'database-password';password.write_text(generated['database_password']+'\n');password.chmod(0o400);os.chown(password,999,999)
    (config/'Caddyfile').write_text(service_rendering.proxy(profile,settings['bind_address']))
    regional=folder/'regional';regional.mkdir(mode=0o750);os.chown(regional,0,991)
    bundle={'kind':'regional-service-link','schema_version':1,'package':'matrix','gateway_identity':identity,
            'gateway_lan_address':'10.203.'+str(index)+'.1','service_lan_address':'10.203.'+str(index)+'.10','lan_subnet':'10.203.'+str(index)+'.0/24','agreements':[document]}
    prepared=service_link.prepare(bundle,settings,expected_fingerprint=agreements.fingerprint(identity),now=int(time.time()))
    (regional/'configuration.json').write_text(json.dumps(prepared))
    service_regional.BASE=regional;service_regional.materialize(settings,(config/'Caddyfile').read_text())
    service_runtime.BASE=config;service_runtime.STATE=state;service_runtime.TLS=tls
    service_runtime.UNITS={name:institution+'-'+name for name in ('postgres','synapse','element','proxy')}
    node=institution+'-service'
    launch(node,institution+'-postgres',service_runtime.container_command('postgres',settings))
    for _ in range(60):
        result=subprocess.run(['podman','exec',institution+'-postgres','pg_isready','-h','127.0.0.1','-p','5433','-U','synapse','-d','synapse'],capture_output=True)
        if result.returncode==0:break
        time.sleep(.5)
    else:raise ValueError('Fixture PostgreSQL did not become ready')
    launch(node,institution+'-synapse',service_runtime.container_command('synapse',settings))
    for _ in range(60):
        response=request(node,'GET','http://127.0.0.1:8008/_synapse/admin/v1/server_version',timeout=3)
        if response['status']==200:break
        time.sleep(1)
    else:raise ValueError('Fixture Synapse did not become ready')
    launch(node,institution+'-proxy',service_runtime.container_command('proxy',settings))
    etc=Path('/etc/netns')/(institution+'-user')/'hosts'
    with etc.open('a') as stream:stream.write(settings['bind_address']+' '+host+'\n')
    for _ in range(30):
        response=request(institution+'-user','GET','https://'+host+'/_matrix/client/versions',timeout=3)
        if response['status']==200:break
        time.sleep(1)
    else:raise ValueError('Actual internal user overlay could not reach Matrix HTTPS')
    return {'settings':settings,'generated':generated,'tls':tls,'hostname':host,'node':node,'user':institution+'-user'}


def setup_gateway(institution,index,identity,document,tls):
    node=institution+'-gateway';folder=ROOT/(institution+'-proxy');folder.mkdir(mode=0o700)
    for name in ('tls.crt','tls.key'):(folder/name).write_bytes((tls/name).read_bytes());(folder/name).chmod(0o600)
    profile={'kind':'regional-gateway','schema_version':1,'institution_id':institution,'node_name':node,
             'regional_controller':network.CONTROLLERS['regional']['hostname'],'lan_address':'10.203.'+str(index)+'.1','lan_subnet':'10.203.'+str(index)+'.0/24',
             'identity_file':'/root/public-identity.json','tls_certificate':str(folder/'tls.crt'),'tls_private_key':str(folder/'tls.key'),'upstreams':{'matrix':'10.203.'+str(index)+'.10'}}
    peers=gateway_contracts.peer_rules(identity,[document],[],now=int(time.time()))
    (folder/'envoy.json').write_text(json.dumps(gateway_rendering.envoy(profile,identity,peers)))
    gateway_runtime.BASE=folder;gateway_runtime.CONTAINER=institution+'-gateway-proxy'
    launch(node,gateway_runtime.CONTAINER,gateway_runtime.container_command(identity))
    network.run('ip','netns','exec',node,'nft','-f','-',input=gateway_rendering.firewall(profile,peers,lan_interface='lan0',now=int(time.time()),replace=False))
    return profile


def account(application,username):
    password=secrets.token_urlsafe(24);url='http://127.0.0.1:8008/_synapse/admin/v1/register'
    nonce=request(application['node'],'GET',url)['body']['nonce']
    message='\x00'.join((nonce,username,password,'notadmin')).encode()
    mac=hmac.new(application['generated']['registration_secret'].encode(),message,hashlib.sha1).hexdigest()
    assert request(application['node'],'POST',url,{'nonce':nonce,'username':username,'password':password,'admin':False,'mac':mac,'inhibit_login':True})['status']==200
    return api(application['user'],'POST',application['hostname'],'/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':username},'password':password})['access_token']


def wait_event(application,room,event,token):
    path='/_matrix/client/v3/rooms/'+urllib.parse.quote(room,safe='')+'/event/'+urllib.parse.quote(event,safe='')
    for _ in range(40):
        result=request(application['user'],'GET','https://'+application['hostname']+path,token=token)
        if result['status']==200:return result['body']
        time.sleep(1)
    raise ValueError('Federated room event was not delivered: '+str(result))


def main():
    nodes=network.prepare()
    images=service_contracts.image_pins()
    for image in {images[key]['image'] for key in ('postgres','synapse','proxy')}|{gateway_contracts.image_pins()['gateway']['image']}:network.run('podman','pull',image,timeout=600)
    identities={};keys={}
    for index,institution in enumerate(('north','south'),1):
        private_lan(institution,index);keys[institution]=Ed25519PrivateKey.generate().private_bytes_raw()
        identities[institution]=agreements.identity(keys[institution],institution_id=institution,regional_controller=network.CONTROLLERS['regional']['hostname'],
            gateway_node=institution+'-gateway',gateway_ipv4=nodes[institution+'-gateway']['address'],services={'matrix':'matrix.'+institution+'.ci.test'})
    now=int(time.time());offer=agreements.offer(keys['north'],identities['north'],identities['south'],['matrix'],now=now,expires_at=now+3600,expected_peer=agreements.fingerprint(identities['south']))
    document=agreements.accept(keys['south'],offer,now=now,expected_peer=agreements.fingerprint(identities['north']))
    applications={};profiles={}
    for index,institution in enumerate(('north','south'),1):
        applications[institution]=setup_application(institution,index,identities[institution],document)
        profiles[institution]=setup_gateway(institution,index,identities[institution],document,applications[institution]['tls'])
    for node in ('north-gateway','south-gateway','outsider'):
        with (Path('/etc/netns')/node/'hosts').open('a') as stream:
            for institution in ('north','south'):stream.write(nodes[institution+'-gateway']['address']+' matrix.'+institution+'.ci.test\n')
    north=applications['north'];south=applications['south']
    for _ in range(30):
        response=request('south-gateway','GET','https://'+north['hostname']+'/_matrix/federation/v1/version',timeout=3)
        if response['status']==200:break
        time.sleep(1)
    else:raise ValueError('Real regional overlay could not reach the approved federation endpoint: '+str(response))
    for path in ('/_matrix/client/versions','/_synapse/admin/v1/server_version','/remote.php/dav/'):
        assert request('south-gateway','GET','https://'+north['hostname']+path)['status'] in (403,404)
    # This node is admitted to Headscale with HTTPS transport permission, but
    # has no bilateral application approval and is denied by the gateway.
    assert request('outsider','GET','https://'+north['hostname']+'/_matrix/federation/v1/version',timeout=3)['status']==0
    alice=account(north,'alice');bob=account(south,'bob')
    room=api(north['user'],'POST',north['hostname'],'/_matrix/client/v3/createRoom',{'preset':'private_chat','name':'Independent institutional proof'},alice)['room_id']
    encoded=urllib.parse.quote(room,safe='')
    api(north['user'],'POST',north['hostname'],'/_matrix/client/v3/rooms/'+encoded+'/invite',{'user_id':'@bob:'+south['hostname']},alice)
    api(south['user'],'POST',south['hostname'],'/_matrix/client/v3/join/'+encoded,{},bob)
    def send(app,token,transaction,body):return api(app['user'],'PUT',app['hostname'],'/_matrix/client/v3/rooms/'+encoded+'/send/m.room.message/'+transaction,{'msgtype':'m.text','body':body},token)['event_id']
    event=send(north,alice,'north-first','Approved institutional message')
    assert wait_event(south,room,event,bob)['content']['body']=='Approved institutional message'
    reply=send(south,bob,'south-first','Independent partner reply')
    assert wait_event(north,room,reply,alice)['content']['body']=='Independent partner reply'
    print('Actual Matrix federation: users on separate internal Headscale networks log in, invite/join a private room and exchange messages both ways through separate approved regional gateways. Client/admin paths and an admitted but unapproved regional node are denied PASS.',flush=True)
    # Close the same kernel boundary used by the product's already-tested
    # revocation transaction, then remove the regional controller/gateways.
    for institution in ('north','south'):
        network.run('ip','netns','exec',institution+'-gateway','nft','-f','-',input=gateway_rendering.firewall(profiles[institution],[],lan_interface='lan0',now=int(time.time()),replace=True))
    later=send(north,alice,'after-revocation','This message must not cross the revoked boundary')
    time.sleep(3)
    path='/_matrix/client/v3/rooms/'+encoded+'/event/'+urllib.parse.quote(later,safe='')
    assert request(south['user'],'GET','https://'+south['hostname']+path,token=bob)['status']!=200
    assert wait_event(south,room,event,bob)['content']['body']=='Approved institutional message'
    network.CONTROLLERS['regional']['process'].terminate();network.CONTROLLERS['regional']['process'].wait(timeout=10)
    for institution in ('north','south'):network.run('podman','stop',institution+'-gateway-proxy')
    for app,token in ((north,alice),(south,bob)):
        local_room=api(app['user'],'POST',app['hostname'],'/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}},token)['room_id']
        local=urllib.parse.quote(local_room,safe='')
        local_event=api(app['user'],'PUT',app['hostname'],'/_matrix/client/v3/rooms/'+local+'/send/m.room.message/internal-only',{'msgtype':'m.text','body':'Internal chat survives regional loss'},token)['event_id']
        assert wait_event(app,local_room,local_event,token)['content']['body']=='Internal chat survives regional loss'
    print('Actual regional revocation prevents later cross-institution delivery while retained messages remain readable. Loss of regional controller and gateways leaves both internal networks and local chat operations available PASS.',flush=True)
    print('Physical multi-site/home NAT, production relay placement, Nextcloud federation, encrypted cross-institution browser exchange and beginner acceptance are NOT established by this run.',flush=True)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='client':client_main()
    elif len(sys.argv)>1 and sys.argv[1]=='dns':dns_main()
    else:
        try:main()
        finally:
            for name in reversed(CONTAINERS):
                subprocess.run(['podman','stop','--time','5',name],capture_output=True,timeout=15)
            network.cleanup()

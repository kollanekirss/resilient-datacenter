#!/usr/bin/env python3
"""Candidate file federation across actual isolated institutional networks.

This opts into unadvertised Nextcloud routes only in a disposable acceptance job.
Normal gateway runtime stays Matrix-only until this acceptance is complete.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import ci_regional_network as network
import ci_regional_matrix as fixture
import nextcloud_runtime as runtime
import nextcloud_regional as connector
import nextcloud_contracts as contracts
import nextcloud_rendering as rendering
import nextcloud_operations as operations
import gateway_rendering
import gateway_contracts
import gateway_runtime
import regional_agreements as agreements
import service_link
from setup_contracts import local_ownership
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=network.ROOT
API='/ocs/v2.php/apps/files_sharing/api/v1/'


def paths(institution):
    folder=ROOT/(institution+'-files')
    runtime.BASE=folder/'config';runtime.STATE=folder/'state';runtime.APP=folder/'app';runtime.TLS=folder/'tls'
    runtime.UNITS={name:institution+'-'+name for name in ('postgres','nextcloud','proxy')}
    connector.BASE=folder/'regional'
    return folder


def child():
    network.require_ci();data=json.load(sys.stdin);paths(data['institution'])
    if data['action']=='bootstrap':
        operations.bootstrap(data['settings'],data['profile'],'alice',data['password'],data['database_password'])
    elif data['action']=='controls':runtime.synchronize_regional(data['settings'])
    else:raise ValueError('Unsupported disposable file child')


def client():
    network.require_ci();data=json.load(sys.stdin)
    headers={}
    if data.get('password'):headers['Authorization']='Basic '+base64.b64encode(('alice:'+data['password']).encode()).decode()
    if data['form']:headers.update({'OCS-APIRequest':'true','Content-Type':'application/x-www-form-urlencoded'})
    body=base64.b64decode(data['body']) if data['body'] is not None else None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(data['url'],body,headers,method=data['method']),timeout=data['timeout']) as response:
            code=response.status;body=response.read(2*1024*1024)
    except urllib.error.HTTPError as error:code=error.code;body=error.read(65536)
    except (OSError,urllib.error.URLError):code=0;body=b'connection-unavailable'
    print(json.dumps({'status':code,'body':base64.b64encode(body).decode()}))


def request(node,method,url,*,password=None,body=None,form=False,timeout=60):
    if isinstance(body,dict):body=urllib.parse.urlencode(body).encode()
    result=json.loads(network.run('ip','netns','exec',node,sys.executable,str(Path(__file__)),'client',
        input=json.dumps({'method':method,'url':url,'password':password,'body':base64.b64encode(body).decode() if body is not None else None,'form':form,'timeout':timeout}),timeout=timeout+15))
    return result['status'],base64.b64decode(result['body'])


def own(app,method,path,body=None,*,form=False):
    code,raw=request(app['user'],method,'https://'+app['hostname']+path,password=app['password'],body=body,form=form)
    if not 200<=code<300:raise ValueError('Internal file operation '+method+' failed '+str(code)+': '+raw.decode(errors='replace')[:1500])
    return raw


def ocs(app,method,path,body=None):
    result=json.loads(own(app,method,API+path+'?format=json',body,form=True))['ocs']
    if result['meta']['status']!='ok':raise ValueError('File-sharing operation failed: '+str(result['meta']))
    return result['data']


def setup(institution,index,identity,document):
    folder=paths(institution);folder.mkdir(mode=0o700)
    for directory in (runtime.BASE,runtime.STATE,runtime.TLS,connector.BASE):directory.mkdir(mode=0o750)
    os.chown(connector.BASE,0,33)
    hostname='files.'+institution+'.ci.test';network.issue(hostname,runtime.TLS)
    local=local_ownership({'kind':'local-node','schema_version':1,'institution_id':institution,'node_name':institution+'-service','headscale_hostname':network.CONTROLLERS[institution]['hostname'],'node_tag':'tag:files'})
    profile={'kind':'nextcloud-services','schema_version':1,'institution_id':institution,'node_name':institution+'-service','nextcloud_hostname':hostname,'tls_mode':'supplied','tls_certificate':str(runtime.TLS/'tls.crt'),'tls_private_key':str(runtime.TLS/'tls.key')}
    settings={'schema_version':1,'ownership':contracts.ownership(profile,local),'bind_address':network.NODES[institution+'-service']['address'],'components':contracts.image_pins()}
    password=secrets.token_urlsafe(24);database_password=secrets.token_hex(32)
    for name,uid in (('postgres',999),('files',33)):
        (runtime.STATE/name).mkdir(mode=0o700);os.chown(runtime.STATE/name,uid,uid)
    path=runtime.BASE/'database-password';path.write_text(database_password+'\n');os.chown(path,999,999);path.chmod(0o400)
    for name,text in (('ports.conf',rendering.apache_ports()),('site.conf',rendering.apache_site()),('Caddyfile',rendering.proxy(profile,settings['bind_address']))):(runtime.BASE/name).write_text(text)
    node=institution+'-service';fixture.launch(node,institution+'-postgres',runtime.container_command('postgres',settings))
    for _ in range(60):
        result=subprocess.run(['nsenter','--net=/var/run/netns/'+node,'podman','exec',institution+'-postgres','pg_isready','-h','127.0.0.1','-p','5434','-U','nextcloud','-d','nextcloud'],capture_output=True)
        if result.returncode==0:break
        time.sleep(.5)
    else:raise ValueError('File fixture PostgreSQL not ready')
    network.run('nsenter','--net=/var/run/netns/'+node,sys.executable,str(Path(__file__)),'child',input=json.dumps({'action':'bootstrap','institution':institution,'settings':settings,'profile':profile,'password':password,'database_password':database_password}),timeout=300)
    network.run('nsenter','--net=/var/run/netns/'+node,'podman','exec','--user','999:999',institution+'-postgres','psql','-p','5434','-U','nextcloud','-d','nextcloud','-c','ALTER ROLE oc_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',timeout=30)
    bundle={'kind':'regional-service-link','schema_version':1,'package':'nextcloud','gateway_identity':identity,'gateway_lan_address':'10.203.'+str(index)+'.1','service_lan_address':'10.203.'+str(index)+'.10','lan_subnet':'10.203.'+str(index)+'.0/24','agreements':[document]}
    prepared=service_link.prepare(bundle,settings,expected_fingerprint=agreements.fingerprint(identity),now=int(time.time()))
    connector.write(connector.BASE/'configuration.json',json.dumps(prepared))
    network.run('nsenter','--net=/var/run/netns/'+node,sys.executable,str(Path(__file__)),'child',input=json.dumps({'action':'controls','institution':institution,'settings':settings}),timeout=180)
    command=runtime.container_command('nextcloud',settings);offset=command.index('run')+1
    command[offset:offset]=['--volume','/usr/local/share/ca-certificates/rdc-application-ci.crt:/ci-ca.crt:ro']
    fixture.launch(node,institution+'-nextcloud',command)
    network.run('nsenter','--net=/var/run/netns/'+node,'podman','exec','--user','33:33',institution+'-nextcloud','php','occ','security:certificates:import','/ci-ca.crt',timeout=60)
    for app in ('federation','updatenotification','sharebymail'):network.run('nsenter','--net=/var/run/netns/'+node,'podman','exec','--user','33:33',institution+'-nextcloud','php','occ','app:disable',app,timeout=60)
    fixture.launch(node,institution+'-proxy',runtime.container_command('proxy',settings))
    with (Path('/etc/netns')/(institution+'-user')/'hosts').open('a') as stream:stream.write(settings['bind_address']+' '+hostname+'\n')
    for _ in range(30):
        code,raw=request(institution+'-user','GET','https://'+hostname+'/status.php',timeout=3)
        if code==200 and json.loads(raw).get('installed'):break
        time.sleep(1)
    else:raise ValueError('Internal file HTTPS not ready')
    return {'hostname':hostname,'user':institution+'-user','node':node,'password':password,'settings':settings,'tls':runtime.TLS}


def gateway(institution,index,identity,document,tls):
    folder=ROOT/(institution+'-file-proxy');folder.mkdir(mode=0o700)
    for name in ('tls.crt','tls.key'):(folder/name).write_bytes((tls/name).read_bytes());(folder/name).chmod(0o600)
    profile={'kind':'regional-gateway','schema_version':1,'institution_id':institution,'node_name':institution+'-gateway','regional_controller':network.CONTROLLERS['regional']['hostname'],
        'lan_address':'10.203.'+str(index)+'.1','lan_subnet':'10.203.'+str(index)+'.0/24','identity_file':'/root/identity.json','tls_certificate':str(folder/'tls.crt'),'tls_private_key':str(folder/'tls.key'),'upstreams':{'nextcloud':'10.203.'+str(index)+'.10'}}
    peers=gateway_contracts.peer_rules(identity,[document],[],now=int(time.time()))
    rendered=gateway_rendering.envoy(profile,identity,peers,services=('nextcloud',))
    for listener in rendered['static_resources']['listeners']:
        hcm=listener['filter_chains'][0]['filters'][0]['typed_config']
        hcm['access_log']=[{'name':'envoy.access_loggers.stdout','typed_config':{
            '@type':'type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
            'log_format':{'json_format':{'method':'%REQ(:METHOD)%','code':'%RESPONSE_CODE%',
                'detail':'%RESPONSE_CODE_DETAILS%'}}}}]
    (folder/'envoy.json').write_text(json.dumps(rendered))
    gateway_runtime.BASE=folder;gateway_runtime.CONTAINER=institution+'-gateway-proxy'
    fixture.launch(institution+'-gateway',gateway_runtime.CONTAINER,gateway_runtime.container_command(identity))
    network.run('ip','netns','exec',institution+'-gateway','nft','-f','-',input=gateway_rendering.firewall(profile,peers,lan_interface='lan0',now=int(time.time()),replace=False,services=('nextcloud',)))
    return profile


def main():
    network.prepare()
    for image in {item['image'] for item in contracts.image_pins().values()}|{gateway_contracts.image_pins()['gateway']['image']}:network.run('podman','pull',image,timeout=600)
    identities={};keys={}
    for index,institution in enumerate(('north','south'),1):
        fixture.private_lan(institution,index);keys[institution]=Ed25519PrivateKey.generate().private_bytes_raw()
        identities[institution]=agreements.identity(keys[institution],institution_id=institution,regional_controller=network.CONTROLLERS['regional']['hostname'],gateway_node=institution+'-gateway',gateway_ipv4=network.NODES[institution+'-gateway']['address'],services={'nextcloud':'files.'+institution+'.ci.test'})
    now=int(time.time());offer=agreements.offer(keys['north'],identities['north'],identities['south'],['nextcloud'],now=now,expires_at=now+3600,expected_peer=agreements.fingerprint(identities['south']))
    document=agreements.accept(keys['south'],offer,now=now,expected_peer=agreements.fingerprint(identities['north']))
    apps={};profiles={}
    for index,institution in enumerate(('north','south'),1):
        apps[institution]=setup(institution,index,identities[institution],document)
        profiles[institution]=gateway(institution,index,identities[institution],document,apps[institution]['tls'])
    for node in ('north-gateway','south-gateway','outsider'):
        with (Path('/etc/netns')/node/'hosts').open('a') as stream:
            for institution in ('north','south'):stream.write(network.NODES[institution+'-gateway']['address']+' files.'+institution+'.ci.test\n')
    north,south=apps['north'],apps['south'];content=b'Approved cross-institution file '+os.urandom(128)
    # Exercise the actual application client, including its signed-request TLS
    # behavior. A missing-arguments response is expected for this empty payload.
    probe=('require "/var/www/html/lib/base.php";'
           '$s=\\OCP\\Server::get(\\OCP\\OCM\\IOCMDiscoveryService::class);'
           'try{$p=$s->discover("https://files.south.ci.test");'
           'echo json_encode(["enabled"=>$p->isEnabled(),"endpoint"=>$p->getEndPoint()])."\\n";'
           '$s->requestRemoteOcmEndpoint(null,"https://files.south.ci.test","/shares",[],"post",null,["verify"=>true]);'
           '}catch(\\Throwable $e){echo json_encode(["class"=>get_class($e),"error"=>$e->getMessage()])."\\n";}')
    diagnostic=network.run('nsenter','--net=/var/run/netns/north-service','podman','exec','--user','33:33','north-nextcloud','php','-r',probe,timeout=60)
    from ci_nextcloud_diagnostics import safe_message
    print('Application signed-request probe: '+safe_message(diagnostic),flush=True)
    own(north,'PUT','/remote.php/dav/files/alice/proof.txt',content)
    own(north,'PUT','/remote.php/dav/files/alice/private.txt',b'Unshared institutional data')
    assert own(north,'GET','/remote.php/dav/files/alice/proof.txt')==content
    share=ocs(north,'POST','shares',{'path':'/proof.txt','shareType':'6','shareWith':'alice@'+south['hostname'],'permissions':'1'})
    pending=ocs(south,'GET','remote_shares/pending');assert len(pending)==1,pending
    incoming=pending[0];ocs(south,'POST','remote_shares/pending/'+str(incoming['id']),{})
    mounted='/remote.php/dav/files/alice'+urllib.parse.quote(incoming.get('mountpoint','/proof.txt'))
    assert own(south,'GET',mounted)==content
    assert request('south-gateway','GET','https://'+north['hostname']+'/remote.php/dav/files/alice/private.txt',timeout=5)[0] in (403,404)
    for path in ('/index.php/login','/ocs/v2.php/cloud/users','/index.php/settings/admin'):
        assert request('south-gateway','GET','https://'+north['hostname']+path,timeout=5)[0] in (403,404)
    assert request('outsider','GET','https://'+north['hostname']+'/ocm-provider/',timeout=3)[0]==0
    # A well-formed application share without the sender's signature is denied
    # even though its source gateway has transport approval.
    forged={'shareWith':'alice','name':'forged.txt','description':'unsigned fixture','providerId':'999999',
            'owner':'alice@'+south['hostname'],'ownerDisplayName':'Alice','sharedBy':'alice@'+south['hostname'],'sharedByDisplayName':'Alice',
            'protocol[name]':'webdav','protocol[options][sharedSecret]':secrets.token_hex(16),'protocol[options][permissions]':'1',
            'shareType':'user','resourceType':'file'}
    code,body=request('south-gateway','POST','https://'+north['hostname']+'/index.php/ocm/shares',body=forged,form=True)
    assert code==400 and 'sign' in body.decode(errors='replace').lower(),(code,body[:500])
    ocs(north,'DELETE','shares/'+str(share['id']))
    assert request(south['user'],'GET','https://'+south['hostname']+mounted,password=south['password'],timeout=15)[0] in (401,403,404,503)
    print('Actual candidate Nextcloud federation: separate internal users upload, explicitly accept and read an approved share; unrelated DAV/admin routes, unapproved regional node and revoked share are denied PASS.',flush=True)
    own(north,'MKCOL','/remote.php/dav/files/alice/partner-folder')
    ocs(north,'POST','shares',{'path':'/partner-folder','shareType':'6','shareWith':'alice@'+south['hostname'],'permissions':'1'})
    pending=ocs(south,'GET','remote_shares/pending');assert len(pending)==1,pending
    incoming=pending[0];ocs(south,'POST','remote_shares/pending/'+str(incoming['id']),{})
    folder='/remote.php/dav/files/alice'+urllib.parse.quote(incoming.get('mountpoint','/partner-folder'))
    own(north,'PUT','/remote.php/dav/files/alice/partner-folder/before.txt',b'Previously approved')
    assert own(south,'GET',folder+'/before.txt')==b'Previously approved'
    for institution in ('north','south'):
        network.run('ip','netns','exec',institution+'-gateway','nft','-f','-',input=gateway_rendering.firewall(profiles[institution],[],lan_interface='lan0',now=int(time.time()),replace=True,services=('nextcloud',)))
    after=b'Created only after partnership revocation '+os.urandom(32)
    own(north,'PUT','/remote.php/dav/files/alice/partner-folder/after.txt',after)
    code,body=request(south['user'],'GET','https://'+south['hostname']+folder+'/after.txt',password=south['password'],timeout=15)
    assert not (code==200 and body==after),'New file crossed a revoked partnership'
    print('Actual candidate file partnership revocation blocks subsequently created content without claiming recall of delivered copies PASS.',flush=True)
    for institution in ('north','south'):network.run('podman','stop',institution+'-gateway-proxy')
    network.CONTROLLERS['regional']['process'].terminate();network.CONTROLLERS['regional']['process'].wait(timeout=10)
    for app in apps.values():
        own(app,'PUT','/remote.php/dav/files/alice/local-only.txt',b'Internal files survive regional loss')
        assert own(app,'GET','/remote.php/dav/files/alice/local-only.txt')==b'Internal files survive regional loss'
    print('Both independent institutions retain internal file operations after regional controller and gateway loss PASS. Physical sites, home NAT, public issuance and beginner acceptance remain untested.',flush=True)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='child':child()
    elif len(sys.argv)>1 and sys.argv[1]=='client':client()
    else:
        try:main()
        finally:
            for path in ROOT.glob('*-files/state/files/nextcloud.log'):
                from ci_nextcloud_diagnostics import report
                report(path)
            for institution in ('north','south'):
                subprocess.run(['podman','logs','--tail','15',institution+'-gateway-proxy'],timeout=15)
            for name in reversed(fixture.CONTAINERS):subprocess.run(['podman','stop','--time','5',name],capture_output=True,timeout=15)
            network.cleanup()

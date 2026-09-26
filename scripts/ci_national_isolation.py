#!/usr/bin/env python3
"""Two institutional access networks plus approved federation under a regional cut."""
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import ci_regional_network as network
import ci_regional_matrix as matrix
import ci_national_network as domestic
from ci_national_contract import evidence,cut_rules,partner_rules
import gateway_contracts
import regional_agreements as agreements
import service_contracts


def account(app,username):
    password=secrets.token_urlsafe(24);url='http://127.0.0.1:8008/_synapse/admin/v1/register'
    nonce=matrix.request(app['node'],'GET',url)['body']['nonce']
    mac=hmac.new(app['generated']['registration_secret'].encode(),'\x00'.join((nonce,username,password,'notadmin')).encode(),hashlib.sha1).hexdigest()
    assert matrix.request(app['node'],'POST',url,{'nonce':nonce,'username':username,'password':password,'admin':False,'mac':mac,'inhibit_login':True})['status']==200
    return {'username':username,'password':password}


def login(app,credentials):
    return matrix.api(app['user'],'POST',app['hostname'],'/_matrix/client/v3/login',{'type':'m.login.password',
        'identifier':{'type':'m.id.user','user':credentials['username']},'password':credentials['password']})['access_token']


def ready(app,seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if matrix.request(app['user'],'GET','https://'+app['hostname']+'/_matrix/client/versions',timeout=3)['status']==200:return
        time.sleep(1)
    raise ValueError('Field application did not become reachable: '+app['user'])


def send(app,room,token,label):
    path='/_matrix/client/v3/rooms/'+urllib.parse.quote(room,safe='')+'/send/m.room.message/'+label
    return matrix.api(app['user'],'PUT',app['hostname'],path,{'msgtype':'m.text','body':label},token)['event_id']


def field_proof(app,credentials,label,*,token=None):
    ready(app);mode='retained session' if token else 'fresh login'
    if token is None:token=login(app,credentials)
    room=matrix.api(app['user'],'POST',app['hostname'],'/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}},token)['room_id']
    event=send(app,room,token,label)
    assert matrix.wait_event(app,room,event,token)['content']['body']==label
    print('Prepared field '+mode+' and private Matrix write/read '+app['user']+' '+label+' PASS.',flush=True)
    return token


def federation(apps,tokens,room,label):
    for origin,target in (('north','south'),('south','north')):
        body=label+'-'+origin;event=send(apps[origin],room,tokens[origin],body)
        assert matrix.wait_event(apps[target],room,event,tokens[target])['content']['body']==body
    print('Approved service-network Matrix exchange '+label+' PASS.',flush=True)


def authenticated_available(app,token,label):
    base='https://'+app['hostname'];node=app['user']
    result=matrix.request(node,'POST',base+'/_matrix/client/v3/createRoom',
        {'preset':'private_chat','creation_content':{'m.federate':False}},token,timeout=5)
    if result['status']!=200:return False
    room=urllib.parse.quote(result['body']['room_id'],safe='')
    result=matrix.request(node,'PUT',base+'/_matrix/client/v3/rooms/'+room+'/send/m.room.message/'+label,
        {'msgtype':'m.text','body':label},token,timeout=5)
    if result['status']!=200:return False
    event=urllib.parse.quote(result['body']['event_id'],safe='')
    result=matrix.request(node,'GET',base+'/_matrix/client/v3/rooms/'+room+'/event/'+event,token=token,timeout=5)
    return result['status']==200 and result['body'].get('content',{}).get('body')==label


def boundary(apps):
    north=apps['north']
    # Known live federation endpoint is reachable, while regional peers cannot
    # use the same gateway as a staff login/admin route.
    response=matrix.request('south-gateway','GET','https://'+north['hostname']+'/_matrix/federation/v1/version',timeout=5)
    assert response['status']==200
    for path in ('/_matrix/client/versions','/_synapse/admin/v1/server_version'):
        assert matrix.request('south-gateway','GET','https://'+north['hostname']+path,timeout=5)['status'] in (403,404)
    for name in ('north','south'):
        node=network.NODES[name+'-user'];status=json.loads(network.run(*node['command'],'status','--json'))
        visible=set((status.get('Peer') or {}).keys())
        assert network.NODES[name+'-service']['public_key'] in visible
        assert not visible & {v['public_key'] for v in network.NODES.values() if v['controller']!=name}


def partition(enabled):
    for own,other in (('north','south'),('south','north')):
        node=own+'-gateway'
        if enabled:
            address=network.NODES[other+'-gateway']['address']
            rules=partner_rules(address)
            network.run('ip','netns','exec',node,'nft','-f','-',input=rules)
        else:network.run('ip','netns','exec',node,'nft','delete','table','inet','rdc_partner_cut')


def exercise():
    network.require_ci()
    for rules in (cut_rules(['172.29.10.2']),partner_rules('100.64.0.2')):
        network.run('nft','--check','--file','-',input=rules)
    nodes=domestic.prepare();phases={};observations={}
    images=service_contracts.image_pins()
    for image in {images[key]['image'] for key in ('postgres','synapse','proxy')}|{gateway_contracts.image_pins()['gateway']['image']}:network.run('podman','pull',image,timeout=600)
    keys={};identities={}
    for index,name in enumerate(('north','south'),1):
        matrix.private_lan(name,index);keys[name]=Ed25519PrivateKey.generate().private_bytes_raw()
        identities[name]=agreements.identity(keys[name],institution_id=name,regional_controller=network.CONTROLLERS['regional']['hostname'],
            gateway_node=name+'-gateway',gateway_ipv4=nodes[name+'-gateway']['address'],services={'matrix':'matrix.'+name+'.ci.test'})
    now=int(time.time())
    offer=agreements.offer(keys['north'],identities['north'],identities['south'],['matrix'],now=now,expires_at=now+3600,expected_peer=agreements.fingerprint(identities['south']))
    document=agreements.accept(keys['south'],offer,now=now,expected_peer=agreements.fingerprint(identities['north']))
    apps={}
    for index,name in enumerate(('north','south'),1):
        apps[name]=matrix.setup_application(name,index,identities[name],document)
        matrix.setup_gateway(name,index,identities[name],document,apps[name]['tls'])
        # Remove setup helper's user hosts entry: real domestic DNS is required.
        (Path('/etc/netns')/(name+'-user')/'hosts').write_text('127.0.0.1 localhost\n')
    for node in ('north-gateway','south-gateway'):
        with (Path('/etc/netns')/node/'hosts').open('a') as stream:
            for name in ('north','south'):stream.write(nodes[name+'-gateway']['address']+' matrix.'+name+'.ci.test\n')
    credentials={name:account(app,'fieldoperator') for name,app in apps.items()}
    tokens={name:field_proof(app,credentials[name],'baseline') for name,app in apps.items()}
    room=matrix.api(apps['north']['user'],'POST',apps['north']['hostname'],'/_matrix/client/v3/createRoom',{'preset':'private_chat'},tokens['north'])['room_id']
    encoded=urllib.parse.quote(room,safe='')
    matrix.api(apps['north']['user'],'POST',apps['north']['hostname'],'/_matrix/client/v3/rooms/'+encoded+'/invite',{'user_id':'@fieldoperator:'+apps['south']['hostname']},tokens['north'])
    matrix.api(apps['south']['user'],'POST',apps['south']['hostname'],'/_matrix/client/v3/join/'+encoded,{},tokens['south'])
    federation(apps,tokens,room,'baseline');boundary(apps);phases['baseline']=True
    domestic.cut();phases['outside_cut']=True
    for name,app in apps.items():tokens[name]=field_proof(app,credentials[name],'external-cut')
    federation(apps,tokens,room,'external-cut');phases['federation_after_cut']=True
    for name,app in apps.items():
        domestic.restart(app['user']);tokens[name]=field_proof(app,credentials[name],'client-restarted')
    phases['field_restart']=True
    for index,(name,app) in enumerate(apps.items(),1):
        domestic.restart(app['user'],change_address='172.29.10.'+str(140+index))
        tokens[name]=field_proof(app,credentials[name],'address-changed')
    phases['field_address_change']=True
    relay_times={}
    for name,app in apps.items():
        relay=domestic.peer_relay(app['user'],app['node']);item=domestic.RELAYS[relay]
        item['process'].terminate();item['process'].wait(timeout=15);started=time.monotonic()
        tokens[name]=field_proof(app,credentials[name],'relay-lost',token=tokens[name])
        survivor=domestic.peer_relay(app['user'],app['node'])
        assert survivor!=relay and domestic.RELAYS[survivor]['process'].poll() is None
        relay_times[name]=round(time.monotonic()-started,2)
    phases['relay_loss']=True
    boundary(apps);federation(apps,tokens,room,'after-relay-loss')
    partition(True)
    assert matrix.request('south-gateway','GET','https://'+apps['north']['hostname']+'/_matrix/federation/v1/version',timeout=3)['status']==0
    for name,app in apps.items():tokens[name]=field_proof(app,credentials[name],'partner-unreachable',token=tokens[name])
    phases['partner_partition']=True
    partition(False);federation(apps,tokens,room,'partner-returned');boundary(apps);phases['partner_reconnection']=True
    # Availability during authority loss is an observation, not a requirement
    # silently waived or an HA claim. Keep the same authority state; no restore.
    control=network.CONTROLLERS['north'];control['process'].terminate();control['process'].wait(timeout=15)
    app=apps['north']
    observations['north_existing_session']='available' if authenticated_available(app,tokens['north'],'authority-down-existing') else 'unavailable'
    domestic.restart(app['user'],require_running=False)
    time.sleep(5)
    observations['north_restarted_client']='available' if authenticated_available(app,tokens['north'],'authority-down-restarted') else 'unavailable'
    # Other institution and service-network authority remain independently live.
    tokens['south']=field_proof(apps['south'],credentials['south'],'other-authority-down',token=tokens['south'])
    domestic.start_controller(control)
    tokens['north']=field_proof(app,credentials['north'],'authority-returned')
    phases['authority_return']=True
    federation(apps,tokens,room,'final');boundary(apps)
    for name in domestic.NAMES:
        if domestic.canary(name):raise ValueError('Outside route reopened during exercise')
    assert domestic.canary()
    result=evidence(phases,observations);result['relay_failover_observed_seconds']=relay_times
    (network.ROOT/'national-isolation-evidence.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':
    try:exercise()
    finally:
        for name in reversed(matrix.CONTAINERS):subprocess.run(['podman','stop','--time','5',name],capture_output=True,timeout=15)
        network.cleanup()

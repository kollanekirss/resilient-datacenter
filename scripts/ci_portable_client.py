"""Actual protocol client, executed inside a disposable isolated staff namespace."""
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import urllib.parse

BASE=Path('/root/rdc-portable-ci')


def request(host,path,*,method='GET',data=None,headers=None,address='10.76.30.11',timeout=15):
    conn=http.client.HTTPSConnection(address,443,timeout=timeout,context=ssl.create_default_context())
    try:
        conn.sock=ssl.create_default_context().wrap_socket(socket.create_connection((address,443),timeout=timeout),server_hostname=host)
        conn.request(method,path,body=data,headers={'Host':host,**(headers or {})})
        reply=conn.getresponse();return reply.status,reply.read(2*1024*1024)
    finally:conn.close()


def main(role,phase):
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
    config=json.loads((BASE/'client.json').read_text());host=config['host'];password=config['password']
    state_path=BASE/'client-state.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else {}
    if phase=='negative':
        try:assert request(host,'/',headers={'Host':'unknown.ci.test'})[0] in (421,444,400)
        except http.client.RemoteDisconnected:pass
        other='files.ci.test' if role=='chat' else 'matrix.ci.test'
        assert request(host,'/',headers={'Host':other})[0]==421
        try:request('unknown.ci.test','/')
        except (ssl.SSLError,ConnectionError):pass
        else:raise AssertionError('Unknown TLS name accepted')
        try:request(host,'/',address=config['backend'],timeout=2)
        except (OSError,TimeoutError):pass
        else:raise AssertionError('Direct application backend was reachable')
        return
    if phase=='backend-untrusted':
        assert request(host,'/_matrix/client/versions' if role=='chat' else '/status.php')[0]==502
        return
    if phase=='direct':
        try:request(host,'/',address=config['backend'],timeout=2)
        except (OSError,TimeoutError):return
        raise AssertionError('Same-bridge backend access bypassed source restriction')
    if role=='chat':
        def api(method,path,data=None,token=None,extra=None):
            headers={'Content-Type':'application/json',**(extra or {})}
            if token:headers['Authorization']='Bearer '+token
            code,raw=request(host,path,method=method,data=json.dumps(data).encode() if data is not None else None,headers=headers)
            return code,json.loads(raw)
        code,login=api('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cialice'},'password':password},extra={'X-Forwarded-For':'198.51.100.99','X-Real-IP':'198.51.100.99','Forwarded':'for=198.51.100.99'})
        assert code==200;token=login['access_token']
        if phase=='create':
            code,room=api('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}},token)
            assert code==200;state['room']=urllib.parse.quote(room['room_id'],safe='')
            code,event=api('PUT','/_matrix/client/v3/rooms/'+state['room']+'/send/m.room.message/proof',{'msgtype':'m.text','body':'Portable offline proof'},token)
            assert code==200;state['event']=urllib.parse.quote(event['event_id'],safe='')
        elif phase=='mutate':
            code,event=api('PUT','/_matrix/client/v3/rooms/'+state['room']+'/send/m.room.message/later',{'msgtype':'m.text','body':'Later unprotected changes'},token)
            assert code==200;state['later']=urllib.parse.quote(event['event_id'],safe='')
        code,event=api('GET','/_matrix/client/v3/rooms/'+state['room']+'/event/'+state['event'],token=token)
        assert code==200 and event['content']['body']=='Portable offline proof'
        if phase=='restored':assert api('GET','/_matrix/client/v3/rooms/'+state['room']+'/event/'+state['later'],token=token)[0]==404
        assert request('element.ci.test','/config.json')[0]==200
        code,html=request('element.ci.test','/');assert code==200 and b'<html' in html.lower()
    else:
        headers={'Authorization':'Basic '+base64.b64encode(('cialice:'+password).encode()).decode(),
                 'X-Forwarded-For':'198.51.100.99','X-Real-IP':'198.51.100.99','Forwarded':'for=198.51.100.99'}
        path='/remote.php/dav/files/cialice/portable-proof.txt';proof=b'Portable offline file proof\n'
        if phase=='create':assert request(host,path,method='PUT',data=proof,headers=headers)[0]==201
        if phase=='mutate':assert request(host,path,method='PUT',data=b'Later changes',headers=headers)[0] in (201,204)
        else:
            code,raw=request(host,path,headers=headers);assert code==200 and raw==proof
        if phase=='create':
            code,raw=request(host,'/rdc-ci-ip.php',headers=headers)
            assert code==200 and json.loads(raw)['client']=='10.76.20.100'
    state_path.write_text(json.dumps(state));state_path.chmod(0o600)


if __name__=='__main__':main(sys.argv[1],sys.argv[2])

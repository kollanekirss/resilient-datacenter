"""Combined staff client: DNS, local time, TLS login, chat and file restoration."""
import base64
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
import urllib.parse
from portable_network_probe import dns_probe,ntp_probe


def main(material,state_dir,phase):
    from ci_portable_applications import guard
    guard();root=Path(material);state_dir=Path(state_dir)
    if phase not in ('probe','create','mutate','restored'):raise ValueError('Unsupported fixture phase')
    plan=json.loads((root/'configuration/site.json').read_text())
    credentials=json.loads((root/'backup-access/client.json').read_text())
    for host in plan['domains'].values():
        dns_probe('10.76.30.10',host,'10.76.30.11');dns_probe('10.76.30.10',host,'10.76.30.11',tcp=True)
        assert set(v[4][0] for v in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM))=={'10.76.30.11'}
    ntp_probe('10.76.30.10')
    try:
        with socket.create_connection(('1.1.1.1',443),timeout=1):pass
    except OSError:pass
    else:raise AssertionError('Staff namespace has an uplink')
    context=ssl.create_default_context(cafile=str(root/'trust/ca.crt'))
    def request(host,path,method='GET',data=None,headers=None):
        conn=http.client.HTTPSConnection(host,443,context=context,timeout=20)
        try:
            conn.request(method,path,body=data,headers=headers or {})
            response=conn.getresponse();return response.status,response.read(2*1024**2)
        finally:conn.close()
    if phase=='probe':return
    for role in ('chat','files'):
        host=plan['domains'][role];password=credentials[role]
        path=state_dir/(role+'.json');state=json.loads(path.read_text()) if path.exists() else {}
        if role=='chat':
            def api(method,url,data=None,token=None):
                headers={'Content-Type':'application/json'}
                if token:headers['Authorization']='Bearer '+token
                status,body=request(host,url,method,json.dumps(data).encode() if data is not None else None,headers)
                return status,json.loads(body)
            code,login=api('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cialice'},'password':password})
            assert code==200;token=login['access_token']
            if phase=='create':
                code,room=api('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}},token)
                assert code==200;state['room']=urllib.parse.quote(room['room_id'],safe='')
            if phase in ('create','mutate'):
                code,event=api('PUT','/_matrix/client/v3/rooms/'+state['room']+'/send/m.room.message/'+phase,{'msgtype':'m.text','body':phase},token)
                assert code==200;state[phase]=urllib.parse.quote(event['event_id'],safe='')
            code,event=api('GET','/_matrix/client/v3/rooms/'+state['room']+'/event/'+state['create'],token=token)
            assert code==200 and event['content']['body']=='create'
            if phase=='restored':assert api('GET','/_matrix/client/v3/rooms/'+state['room']+'/event/'+state['mutate'],token=token)[0]==404
            assert request(plan['domains']['element'],'/config.json')[0]==200
        else:
            headers={'Authorization':'Basic '+base64.b64encode(('cialice:'+password).encode()).decode()}
            url='/remote.php/dav/files/cialice/site-proof.txt'
            if phase in ('create','mutate'):
                assert request(host,url,'PUT',b'saved proof' if phase=='create' else b'later change',headers)[0] in (201,204)
            else:
                code,body=request(host,url,headers=headers);assert code==200 and body==b'saved proof'
        path.write_text(json.dumps(state));path.chmod(0o600)
        # Every denied backend is a known live TLS listener, positively accessed
        # by the shared frontend during the immediately preceding user operation.
        try:
            with socket.create_connection((plan['vms'][role]['address'],443),timeout=1):pass
        except OSError:pass
        else:raise AssertionError('Staff reached application backend directly')
    print('Shared staff DNS/time/TLS/chat/files '+phase+' PASS',flush=True)


if __name__=='__main__':main(*sys.argv[1:])

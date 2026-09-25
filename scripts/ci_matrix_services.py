#!/usr/bin/env python3
"""Destructive Matrix package acceptance restricted to disposable Ubuntu runners."""
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import urllib.request
import urllib.error
import urllib.parse
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from setup_contracts import local_ownership
from service_operations import install_or_resume
from service_accounts import create

ADDRESS='100.64.0.22'
MATRIX='matrix.ci.test'
ELEMENT='chat.ci.test'


def certificates():
    folder=Path('/root/rdc-application-ci');folder.mkdir(mode=0o700,exist_ok=True)
    now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable RDC application CA')])
    root=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
          .sign(key,hashes.SHA256()))
    ca=Path('/usr/local/share/ca-certificates/rdc-application-ci.crt');ca_key=folder/'ca.key'
    if ca.exists():
        root=x509.load_pem_x509_certificate(ca.read_bytes());key=serialization.load_pem_private_key(ca_key.read_bytes(),password=None)
        subject=root.subject
    else:
        ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        ca_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));ca_key.chmod(0o600)
        subprocess.run(['update-ca-certificates'],check=True,stdout=subprocess.DEVNULL,timeout=30)
    leafkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,MATRIX)]))
          .issuer_name(subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=60))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName(MATRIX),x509.DNSName(ELEMENT)]),critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(key,hashes.SHA256()))
    cert=folder/'tls.crt';private=folder/'tls.key'
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(leafkey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
    return cert,private


def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():
        raise SystemExit('Only disposable GitHub-hosted Ubuntu 24.04 runners are permitted.')
    if Path('/etc/server-connectivity-profile.json').exists():raise ValueError('Application fixture requires a fresh runner')
    subprocess.run(['ip','address','add',ADDRESS+'/32','dev','lo'],check=True)
    with Path('/etc/hosts').open('a') as stream:stream.write('\n'+ADDRESS+' '+MATRIX+' '+ELEMENT+'\n')
    from ci_matrix_backup import prepare_network,prepare_backup,snapshot,restore
    prepare_network()
    network=local_ownership({'kind':'local-node','schema_version':1,'institution_id':'ci','node_name':'services','headscale_hostname':'control.ci.test','node_tag':'tag:services'})
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps(network))
    network_snapshot=prepare_backup(network)
    cert,key=certificates()
    profile={'kind':'matrix-services','schema_version':1,'institution_id':'ci','node_name':'services','matrix_hostname':MATRIX,'element_hostname':ELEMENT,
             'tls_mode':'supplied','tls_certificate':str(cert),'tls_private_key':str(key)}
    result=install_or_resume(profile,network,ADDRESS)
    assert result['state']=='service-listeners-verified'
    from service_runtime import read_settings,inspect_container,UNITS
    settings=read_settings()
    for component in UNITS:
        record=inspect_container(component,settings)
        confinement=Path('/proc')/str(record['State']['Pid'])/'attr/current'
        assert 'containers-default-' in confinement.read_text() and '(enforce)' in confinement.read_text()
    print('All four containers retain enforced AppArmor confinement.',flush=True)
    # Exercise rapid consecutive lifecycle operations; a single successful TLS
    # rotation is insufficient evidence against container cleanup races.
    for attempt in range(20):
        subprocess.run(['systemctl','restart','rdc-service-proxy.service'],check=True,timeout=180)
        time.sleep(3)  # Respect systemd's normal five-starts-per-ten-seconds guard.
    print('Twenty consecutive verified proxy restarts PASS.',flush=True)
    alice_password=secrets.token_urlsafe(24);bob_password=secrets.token_urlsafe(24)
    pending=Path('/etc/rdc-restore-pending.json');pending.write_text('{}')
    try:
        try:create('cialice',alice_password,admin=True)
        except ValueError as error:assert 'pending restore' in str(error)
        else:raise AssertionError('Account creation bypassed pending recovery')
    finally:pending.unlink()
    assert create('cialice',alice_password,admin=True)['state']=='account-created'
    assert create('cibob',bob_password)['state']=='account-created'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def request(method,path,data=None,*,token=None,host=MATRIX,raw=False):
        headers={}
        if token:headers['Authorization']='Bearer '+token
        body=None
        if data is not None:
            body=data if isinstance(data,bytes) else json.dumps(data).encode()
            headers['Content-Type']='application/octet-stream' if isinstance(data,bytes) else 'application/json'
        with opener.open(urllib.request.Request('https://'+host+path,data=body,method=method,headers=headers),timeout=30) as response:
            content=response.read(1024*1024)
            return content if raw else json.loads(content)
    def denied(path,token=None,statuses=(401,403,404)):
        try:request('GET',path,token=token)
        except urllib.error.HTTPError as error:assert error.code in statuses
        else:raise AssertionError('An unapproved application endpoint was accessible')
    alice=request('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cialice'},'password':alice_password})['access_token']
    bob=request('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cibob'},'password':bob_password})['access_token']
    room=request('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','name':'Disposable CI room','creation_content':{'m.federate':False}},token=alice)['room_id']
    encoded=urllib.parse.quote(room,safe='')
    event=request('PUT','/_matrix/client/v3/rooms/'+encoded+'/send/m.room.message/ci-first',{'msgtype':'m.text','body':'Disposable RDC application proof'},token=alice)['event_id']
    event_path='/_matrix/client/v3/rooms/'+encoded+'/event/'+urllib.parse.quote(event,safe='')
    denied(event_path,token=bob)
    request('POST','/_matrix/client/v3/rooms/'+encoded+'/invite',{'user_id':'@cibob:'+MATRIX},token=alice)
    request('POST','/_matrix/client/v3/join/'+encoded,{},token=bob)
    assert request('GET',event_path,token=bob)['content']['body']=='Disposable RDC application proof'
    media=b'RDC disposable media '+os.urandom(64)
    uri=request('POST','/_matrix/media/v3/upload?filename=proof.bin',media,token=alice)['content_uri']
    server,identifier=uri.removeprefix('mxc://').split('/',1)
    downloaded=request('GET','/_matrix/client/v1/media/download/'+server+'/'+identifier,token=alice,raw=True)
    assert downloaded==media
    denied('/_matrix/client/v3/account/whoami')
    denied('/_synapse/admin/v1/register',statuses=(404,))
    denied('/_matrix/federation/v1/version',statuses=(404,))
    assert b'<html' in request('GET','/',host=ELEMENT,raw=True).lower()
    assert request('GET','/config.json',host=ELEMENT)['default_server_config']['m.homeserver']['base_url']=='https://'+MATRIX
    print('Actual pinned Matrix/PostgreSQL/Element/proxy: trusted HTTPS, two account logins, room permission denial, invited message read, media round trip and private admin/federation routes PASS.')
    import hashlib
    signing=Path('/var/lib/rdc-services/synapse/server.signing.key')
    signing_hash=hashlib.sha256(signing.read_bytes()).hexdigest()
    encrypted_room=request('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','name':'Encrypted recovery proof',
                           'creation_content':{'m.federate':False},'initial_state':[{'type':'m.room.encryption','state_key':'',
                           'content':{'algorithm':'m.megolm.v1.aes-sha2'}}]},token=alice)['room_id']
    from ci_element_browser import prepare_encrypted
    backup_check=lambda:request('GET','/_matrix/client/v3/room_keys/version',token=alice).get('count',0)>0
    recovery_key=prepare_encrypted('@cialice:'+MATRIX,alice_password,encrypted_room,backup_check)
    encrypted_history=request('GET','/_matrix/client/v3/rooms/'+urllib.parse.quote(encrypted_room,safe='')+'/messages?dir=b&limit=10',token=alice)
    encrypted_events=[e for e in encrypted_history['chunk'] if e['type']=='m.room.encrypted']
    assert encrypted_events and 'Encrypted history survives' not in json.dumps(encrypted_events)
    assert backup_check()
    selected=snapshot(network_snapshot)
    from service_certificates import replace,activate_pair,Runtime as CertificateRuntime,BASE as CERTBASE
    from certificate_lifecycle import ActivationError
    old_certificate=Path('/etc/rdc-service-tls/active/tls.crt').read_bytes()
    cert,key=certificates();assert replace(cert,key)['state']=='active'
    selected_certificate=cert.read_bytes();selected_key=key.read_bytes()
    assert selected_certificate!=old_certificate
    cert,key=certificates()
    class FailedActivation(CertificateRuntime):
        def __init__(self,settings):super().__init__(settings);self.first=True
        def verify(self,hostname,fingerprint):
            super().verify(hostname,fingerprint)
            if self.first:self.first=False;raise ValueError('Synthetic failure after actual new certificate verification')
    for attempt in range(10):
        cert,key=certificates()
        try:activate_pair(CERTBASE,settings,cert.read_bytes(),key.read_bytes(),runtime=FailedActivation(settings))
        except ActivationError as error:assert error.recovered
        else:raise AssertionError('Failed certificate activation was reported as success')
        time.sleep(3)
    print('Ten consecutive failed certificate activations recovered the selected live certificate PASS.',flush=True)
    cert.write_bytes(selected_certificate);key.write_bytes(selected_key)
    assert Path('/etc/rdc-service-tls/active/tls.crt').read_bytes()==selected_certificate
    later=request('PUT','/_matrix/client/v3/rooms/'+encoded+'/send/m.room.message/ci-after-backup',{'msgtype':'m.text','body':'This later change must not survive restoration'},token=alice)['event_id']
    restore(selected)
    assert Path('/etc/rdc-service-tls/active/tls.crt').read_bytes()==selected_certificate
    assert request('GET',event_path,token=bob)['content']['body']=='Disposable RDC application proof'
    assert request('GET','/_matrix/client/v1/media/download/'+server+'/'+identifier,token=alice,raw=True)==media
    denied('/_matrix/client/v3/rooms/'+encoded+'/event/'+urllib.parse.quote(later,safe=''),token=alice,statuses=(404,))
    assert hashlib.sha256(signing.read_bytes()).hexdigest()==signing_hash
    result=install_or_resume(profile,network,ADDRESS)
    assert result['state']=='service-listeners-verified' and hashlib.sha256(signing.read_bytes()).hexdigest()==signing_hash
    print('Actual encrypted SFTP scheduled application backup, scope transition, selected snapshot restore, account tokens/message/media/signing identity preservation and installation resume PASS.',flush=True)
    from ci_element_browser import exercise
    exercise('@cialice:'+MATRIX,alice_password,room,recovery_key=recovery_key,encrypted_room=encrypted_room)
    history=request('GET','/_matrix/client/v3/rooms/'+encoded+'/messages?dir=b&limit=10',token=bob)
    assert any(e.get('content',{}).get('body')=='Message sent from the actual Element browser' for e in history['chunk'])
    from ci_service_issuer import exercise as issuer_exercise
    issuer_exercise(certificates)
    print('Real Tailscale enrollment, home NAT, physical site separation and institutional acceptance NOT RUN by this package slice.')

if __name__=='__main__':main()

#!/usr/bin/env python3
"""Actual local install, service, overlay backup and fresh guest recovery under NAT."""
import base64
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import ci_home_vm as virtualization
import ci_regional_network as network

ROOT=Path('/var/lib/rdc-home-ci')
GUESTS=[]


def approved_key(control,tag):
    return json.loads(network.run(*control['command'],'preauthkeys','create','--user',control['user_id'],
        '--expiration','15m','--tags',tag,'--output','json'))['key']


def guest_phase(vm,phase,data):
    output=vm.ssh(['/opt/rdc/.venv/bin/python','/opt/rdc/scripts/ci_home_guest.py',phase],input=json.dumps(data).encode(),timeout=1200)
    records=[line.removeprefix('RDC_RESULT:') for line in output.decode().splitlines() if line.startswith('RDC_RESULT:')]
    if len(records)!=1:raise ValueError('Guest phase did not return one result')
    print('Fresh Ubuntu guest phase verified: '+phase,flush=True)
    return json.loads(records[0])


def prepare_guest(name,port,control,archive,cert,key):
    vm=virtualization.VM(ROOT/name,ROOT/'ubuntu.img',port=port,
        ca=Path('/usr/local/share/ca-certificates/rdc-application-ci.crt').read_text(),
        controller_address=control['address'],controller_hostname=control['hostname'])
    GUESTS.append(vm)
    vm.put(archive,'/root/source.tar');vm.ssh(['mkdir','/opt/rdc']);vm.ssh(['tar','-xf','/root/source.tar','-C','/opt/rdc'])
    vm.ssh(['python3','-m','venv','/opt/rdc/.venv'])
    vm.ssh(['/opt/rdc/.venv/bin/python','-m','pip','install','-r','/opt/rdc/requirements.txt'],timeout=300)
    vm.put(cert,'/root/service.crt');vm.put(key,'/root/service.key')
    return vm


def main(package):
    virtualization.guard()
    if package not in ('matrix','nextcloud') or ROOT.exists() or network.ROOT.exists() or Path('/etc/server-connectivity-profile.json').exists():raise ValueError('Fresh disposable host and selected package required')
    ROOT.mkdir(mode=0o700);network.ROOT.mkdir(mode=0o700)
    virtualization.image(ROOT/'ubuntu.img');network.prepare_binaries()
    run=network.run
    run('ip','link','add','rdc-wan','type','bridge');run('ip','link','set','rdc-wan','up')
    control=network.controller('home',1)
    # File policy reload is made explicit by restarting the fixture authority
    # before any device is enrolled. It uses its same persisted identity.
    control['process'].terminate();control['process'].wait(timeout=15)
    (control['folder']/'policy.json').write_text(json.dumps({'tagOwners':{'tag:backup':['ci-operator@'],'tag:home-services':['ci-operator@']},
        'grants':[{'src':['*'],'dst':['*'],'ip':['tcp:443','tcp:2222']}]}))
    control['process']=network.spawn('controller-home-active',[*control['command'],'serve'])
    for attempt in range(60):
        if (control['folder']/'control.sock').exists():
            try:run(*control['command'],'users','list','--output','json');break
            except subprocess.SubprocessError:pass
        time.sleep(.25)
    with Path('/etc/hosts').open('a') as stream:stream.write('\n'+control['address']+' '+control['hostname']+'\n')
    from local_node import apply_manifest
    from setup_contracts import local_ownership
    manifest={'kind':'local-node','schema_version':1,'institution_id':'ci','node_name':'backup','headscale_hostname':control['hostname'],'node_tag':'tag:backup'}
    path=ROOT/'backup-node.json';path.write_text(json.dumps(manifest));path.chmod(0o600)
    assert apply_manifest(manifest,path,confirm_fn=lambda _:'yes')['status']=='installed'
    auth=ROOT/'one-use-auth.key';auth.write_text(approved_key(control,'tag:backup'));auth.chmod(0o600)
    try:run('/usr/local/bin/tailscale','up','--login-server=https://'+control['hostname'],'--hostname=backup',
        '--auth-key=file:'+str(auth),'--accept-dns=false','--accept-routes=false','--ssh=false','--timeout=60s')
    finally:auth.unlink(missing_ok=True)
    from backup_target import prepare,authorize
    endpoint=prepare(manifest)
    hostname='matrix.home.ci.test' if package=='matrix' else 'files.home.ci.test'
    import ci_matrix_services as tls
    tls.MATRIX=hostname;tls.ELEMENT='chat.home.ci.test'
    cert,key=tls.certificates();cert_copy=ROOT/'service.crt';key_copy=ROOT/'service.key'
    shutil.copy2(cert,cert_copy);shutil.copy2(key,key_copy)
    archive=ROOT/'source.tar';subprocess.run(['git','archive','HEAD','--output',str(archive)],cwd=network.SOURCE,check=True)
    manifest=dict(manifest,node_name='home-services',node_tag='tag:home-services')
    password=secrets.token_urlsafe(24)
    profile={'kind':'matrix-services' if package=='matrix' else 'nextcloud-services','schema_version':1,'institution_id':'ci','node_name':'home-services',
        'tls_mode':'supplied','tls_certificate':'/root/service.crt','tls_private_key':'/root/service.key'}
    if package=='matrix':profile.update(matrix_hostname=hostname,element_hostname='chat.home.ci.test')
    else:profile.update(nextcloud_hostname=hostname)
    backup_profile={'kind':'backup-profile','schema_version':1,'institution_id':'ci','node_name':'home-services','role':'peer',
        **{k:endpoint[k] for k in ('backup_host','backup_port','backup_host_key')}}
    data={'manifest':manifest,'package':package,'profile':profile,'hostname':hostname,'password':password,'backup_profile':backup_profile}
    first=prepare_guest('original-home',22222,control,archive,cert_copy,key_copy)
    identity=guest_phase(first,'network',dict(data,auth_key=approved_key(control,'tag:home-services')))
    original=guest_phase(first,'services',data)
    with Path('/etc/hosts').open('a') as stream:stream.write('\n'+identity['address']+' '+hostname+' chat.home.ci.test\n')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    token=None
    def request(method,path,payload=None):
        headers={};body=None
        if package=='nextcloud':headers['Authorization']='Basic '+base64.b64encode(('cialice:'+password).encode()).decode()
        elif token:headers['Authorization']='Bearer '+token
        if payload is not None:
            body=payload if isinstance(payload,bytes) else json.dumps(payload).encode()
            headers['Content-Type']='application/octet-stream' if isinstance(payload,bytes) else 'application/json'
        with opener.open(urllib.request.Request('https://'+hostname+path,data=body,method=method,headers=headers),timeout=45) as response:
            raw=response.read(1024*1024);return json.loads(raw) if package=='matrix' else raw
    def login():
        return request('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cialice'},'password':password})['access_token']
    if package=='matrix':
        token=login();room=request('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}})['room_id']
        proof_path='/_matrix/client/v3/rooms/'+urllib.parse.quote(room,safe='')+'/state/rdc.home.proof/'
        request('PUT',proof_path,{'value':'personal-recovery-proof'})
    else:
        proof_path='/remote.php/dav/files/cialice/home-proof.txt';request('PUT',proof_path,b'personal-recovery-proof')
    guest_phase(first,'backup-configure',data)
    public=ROOT/'writer.pub';public.write_bytes(first.get('/etc/rdc-backup/ssh_key.pub'));authorize(public)
    for source,destination in (('password','recovery-password'),('ssh_key','recovery-key')):
        path=ROOT/destination;path.write_bytes(first.get('/etc/rdc-backup/'+source));path.chmod(0o600)
    snapshot=guest_phase(first,'snapshot',data);identifier=snapshot['snapshot_id']
    assert snapshot['network']==identity and snapshot['application_identity']==original['application_identity']
    first.stop();assert first.process.poll() is not None
    started=time.monotonic()
    replacement=prepare_guest('replacement-home',22223,control,archive,cert_copy,key_copy)
    temporary=guest_phase(replacement,'network',dict(data,auth_key=approved_key(control,'tag:home-services')))
    assert temporary['public_key']!=identity['public_key']
    for name in ('recovery-password','recovery-key'):replacement.put(ROOT/name,'/root/'+name)
    recovery=dict(data,snapshot=identifier,old_guest_fenced=True)
    assert guest_phase(replacement,'bootstrap',recovery)==identity
    guest_phase(replacement,'services',recovery)
    restored=guest_phase(replacement,'restore',recovery)
    assert restored==original
    if package=='matrix':token=login();assert request('GET',proof_path)['value']=='personal-recovery-proof'
    else:assert request('GET',proof_path)==b'personal-recovery-proof'
    print(package+': fresh Ubuntu local install behind NAT, matching-manifest rerun, actual overlay login/data, encrypted offsite-fixture backup, original VM fencing, fresh-disk network bootstrap and full service restore PASS. Recovery including fresh guest preparation elapsed '+str(round(time.monotonic()-started,2))+' seconds. Physical sites, public DNS/issuance and beginner usability NOT RUN.',flush=True)


if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise ValueError('Choose matrix or nextcloud')
        main(sys.argv[1])
    except subprocess.CalledProcessError as failure:
        # No private input or successful stdout is printed. Errors remain in
        # the private disposable machine for bounded diagnostic investigation.
        print('Disposable command failed with exit code '+str(failure.returncode),flush=True)
        if failure.stderr:
            text=failure.stderr.decode(errors='replace') if isinstance(failure.stderr,bytes) else failure.stderr
            for line in text.splitlines()[-30:]:
                if not any(term in line.lower() for term in ('password','secret','token','auth-key','private key')):print(line[:500],flush=True)
        raise
    finally:
        for vm in reversed(GUESTS):vm.stop()
        network.cleanup()

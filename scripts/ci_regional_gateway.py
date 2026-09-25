#!/usr/bin/env python3
"""Actual proxy/firewall boundary fixtures; not evidence of VPN or federation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import gateway_contracts as contracts
import gateway_rendering as rendering
import regional_agreements as agreements

ROOT=Path('/var/lib/rdc-gateway-ci')
BASE=ROOT/'config'
PROCESSES=[]
APPROVAL_KEYS={}


def run(*args,**kwargs):return subprocess.run(list(args),check=True,text=True,capture_output=True,**kwargs).stdout


def namespace(name,host,remote,host_address,remote_address):
    run('ip','netns','add',name);run('ip','link','add',host,'type','veth','peer','name',remote)
    run('ip','link','set',remote,'netns',name)
    run('ip','address','add',host_address,'dev',host);run('ip','link','set',host,'up')
    run('ip','netns','exec',name,'ip','address','add',remote_address,'dev',remote)
    run('ip','netns','exec',name,'ip','link','set',remote,'up');run('ip','netns','exec',name,'ip','link','set','lo','up')


def certificates():
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(ROOT/'ca.key'),'-out',str(ROOT/'ca.crt'),'-days','30','-subj','/CN=Disposable Gateway CI CA')
    run('openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(BASE/'tls.key'),'-out',str(ROOT/'leaf.csr'),'-subj','/CN=north.matrix.ci.test')
    (ROOT/'extensions').write_text('subjectAltName=DNS:north.matrix.ci.test,DNS:south.matrix.ci.test\nextendedKeyUsage=serverAuth\n')
    run('openssl','x509','-req','-in',str(ROOT/'leaf.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),'-CAcreateserial','-out',str(BASE/'tls.crt'),'-days','30','-extfile',str(ROOT/'extensions'))
    Path('/usr/local/share/ca-certificates/rdc-gateway-ci.crt').write_bytes((ROOT/'ca.crt').read_bytes());run('update-ca-certificates')
    (BASE/'tls.key').chmod(0o600)


def documents():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    a,b=Ed25519PrivateKey.generate().private_bytes_raw(),Ed25519PrivateKey.generate().private_bytes_raw()
    APPROVAL_KEYS.update(north=a,south=b)
    def identity(key,name,address):return agreements.identity(key,institution_id=name,regional_controller='regional.ci.test',gateway_node=name+'-gateway',gateway_ipv4=address,services={'matrix':name+'.matrix.ci.test'})
    own,peer=identity(a,'north','100.64.0.10'),identity(b,'south','100.64.0.11');now=int(time.time())
    offered=agreements.offer(a,own,peer,['matrix'],expected_peer=agreements.fingerprint(peer),now=now-1,expires_at=now+1800)
    accepted=agreements.accept(b,offered,expected_peer=agreements.fingerprint(own),now=now)
    profile={'kind':'regional-gateway','schema_version':1,'institution_id':'north','node_name':'north-gateway','regional_controller':'regional.ci.test',
             'lan_address':'10.203.1.1','lan_subnet':'10.203.1.0/24','identity_file':'/root/identity.json','tls_certificate':str(BASE/'tls.crt'),'tls_private_key':str(BASE/'tls.key'),
             'upstreams':{'matrix':'10.203.1.10'}}
    return profile,own,contracts.peer_rules(own,[accepted],[],now=now),accepted


def curl(namespace_name,path,*,proxy=False,source=None,host=None,timeout=8,stream=None,proxy10=False):
    host=host or ('south.matrix.ci.test' if proxy else 'north.matrix.ci.test')
    args=['ip','netns','exec',namespace_name,'curl','--silent','--show-error','--max-time',str(timeout),'--noproxy','' if proxy else '*']
    if proxy:args+=['--proxy1.0' if proxy10 else '--proxy','http://10.203.1.1:3128']
    else:args+=['--resolve',host+':443:100.64.0.10']
    if source:args+=['--interface',source]
    args+=['https://'+host+path]
    if stream:
        args+=['--no-buffer','--output',str(stream)];return subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return subprocess.run(args,capture_output=True,text=True)


def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise SystemExit('Disposable GitHub-hosted Ubuntu 24.04 only')
    ROOT.mkdir(mode=0o700);BASE.mkdir(mode=0o700)
    namespace('rdc-peer','tailscale0','peer0','100.64.0.10/24','100.64.0.11/24')
    run('ip','netns','exec','rdc-peer','ip','address','add','100.64.0.12/24','dev','peer0')
    namespace('rdc-service','rdc-lan','service0','10.203.1.1/24','10.203.1.10/24')
    run('ip','netns','exec','rdc-service','ip','address','add','10.203.1.11/24','dev','service0')
    certificates();profile,own,peers,document=documents()
    (BASE/'tls/active').mkdir(parents=True,mode=0o700)
    for name in ('tls.crt','tls.key'):(BASE/'tls/active'/name).write_bytes((BASE/name).read_bytes())
    for name,address,port in [('rdc-peer','100.64.0.11',443),('rdc-service','10.203.1.10',8443)]:
        log=(ROOT/(name+'.log')).open('w')
        PROCESSES.append(subprocess.Popen(['ip','netns','exec',name,sys.executable,str(Path(__file__).with_name('ci_gateway_endpoint.py')),address,str(port),str(BASE/'tls.crt'),str(BASE/'tls.key')],stdout=log,stderr=log))
    (BASE/'envoy.json').write_text(json.dumps(rendering.envoy(profile,own,peers)))
    image=contracts.image_pins()['gateway']['image'];run('podman','pull',image)
    common=['--runtime','runc','--network','host','--read-only','--cap-drop','ALL','--cap-add','NET_BIND_SERVICE','--security-opt','no-new-privileges',
            '--user','0:0','--volume',str(BASE)+':/etc/rdc-gateway:ro','--volume','/etc/ssl/certs:/etc/ssl/certs:ro','--entrypoint','/usr/local/bin/envoy',image,'-c','/etc/rdc-gateway/envoy.json','--concurrency','2']
    run('podman','run','--rm',*common,'--mode','validate')
    run('nft','-f','-',input=rendering.firewall(profile,peers,lan_interface='rdc-lan',now=int(time.time()),replace=False))
    run('podman','run','--detach','--name','rdc-gateway-fixture',*common)
    for _ in range(40):
        result=curl('rdc-peer','/_matrix/federation/v1/version',timeout=2)
        if result.returncode==0 and result.stdout=='fixture:/_matrix/federation/v1/version':break
        time.sleep(.5)
    else:raise AssertionError('Regional ingress did not reach its verified TLS upstream: '+result.stderr+' '+result.stdout)
    for path in ('/_matrix/client/versions','/_synapse/admin/v1/users','/remote.php/dav/','/','/%2f_matrix/federation/v1/version'):
        result=curl('rdc-peer',path);assert not result.stdout.startswith('fixture:'),(path,result.stdout)
    result=curl('rdc-peer','/_matrix/federation/v1/version',source='100.64.0.12',timeout=2);assert result.returncode!=0
    result=curl('rdc-service','/_matrix/federation/v1/version',proxy=True)
    assert result.returncode==0 and result.stdout=='fixture:/_matrix/federation/v1/version',(result.returncode,result.stdout,result.stderr)
    legacy=curl('rdc-service','/_matrix/federation/v1/version',proxy=True,proxy10=True)
    assert legacy.returncode==0 and legacy.stdout=='fixture:/_matrix/federation/v1/version',(legacy.returncode,legacy.stdout,legacy.stderr)
    assert curl('rdc-service','/',proxy=True,proxy10=True,host='unapproved.ci.test').returncode!=0
    for host in ('unapproved.ci.test','169.254.169.254','10.203.1.10','100.64.0.11'):
        assert curl('rdc-service','/',proxy=True,host=host).returncode!=0
    assert curl('rdc-service','/',proxy=True,source='10.203.1.11',timeout=2).returncode!=0
    original=json.loads((BASE/'envoy.json').read_text())
    changed=json.loads(json.dumps(original))
    changed['static_resources']['clusters'][0]['transport_socket']['typed_config']['common_tls_context']['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact']='wrong-upstream.ci.test'
    (BASE/'envoy.json').write_text(json.dumps(changed));run('podman','restart','rdc-gateway-fixture');time.sleep(1)
    result=curl('rdc-peer','/_matrix/federation/v1/version')
    assert result.returncode==0 and 'fixture:' not in result.stdout and 'upstream' in result.stdout,result.stdout
    (BASE/'envoy.json').write_text(json.dumps(original));run('podman','restart','rdc-gateway-fixture');time.sleep(1)
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    print('Actual gateway rejects an upstream certificate whose DNS identity differs from its fixed approved hostname PASS.',flush=True)
    print('Actual Envoy: native configuration validation, trusted upstream HTTPS, approved Matrix paths, denied client/admin paths, denied peer/source and fixed CONNECT destinations PASS. Namespace transport is a fixture, not a VPN.',flush=True)
    for mode in ('revocation','expiry'):
        current=[dict(peer,expires_at=int(time.time())+(5 if mode=='expiry' else 1800)) for peer in peers]
        run('nft','-f','-',input=rendering.firewall(profile,current,lan_interface='rdc-lan',now=int(time.time()),replace=True))
        downloads=[]
        for name,proxy in [('rdc-peer',False),('rdc-service',True)]:
            target=ROOT/(mode+'-'+name+'.stream');process=curl(name,'/_matrix/federation/v1/stream',proxy=proxy,timeout=15,stream=target)
            PROCESSES.append(process);downloads.append((process,target))
        deadline=time.monotonic()+4
        while not all(target.exists() and target.stat().st_size>0 for _,target in downloads):
            if time.monotonic()>deadline:raise AssertionError('Streams did not start before denial test')
            time.sleep(.1)
        if mode=='revocation':run('nft','-f','-',input=rendering.firewall(profile,[],lan_interface='rdc-lan',now=int(time.time()),replace=True))
        else:time.sleep(6)
        time.sleep(.5);sizes=[target.stat().st_size for _,target in downloads];time.sleep(2)
        assert sizes==[target.stat().st_size for _,target in downloads],mode+' allowed an established connection to keep receiving bytes'
        for process,_ in downloads:process.terminate();process.wait(timeout=5)
        assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
        assert curl('rdc-service','/',proxy=True,timeout=2).returncode!=0
        print('Actual kernel '+mode+': both existing stream directions stop and new access is denied PASS.',flush=True)
    runtime_acceptance(profile,own,document)
    print('This run does not establish application federation or real Headscale memberships. The network status below is an explicit synthetic fixture.',flush=True)


def runtime_acceptance(profile,own,document):
    # Remove only the fixture resources created above; this is a fresh disposable
    # runner. Test the actual frozen runtime/installer with declared fake VPN facts.
    run('podman','stop','rdc-gateway-fixture');run('podman','rm','rdc-gateway-fixture')
    run('nft','delete','table','inet','rdc_gateway')
    network={'schema_version':2,'deployment_mode':'join','institution_id':'north','role':'peer',
             'controller_hostname':'regional.ci.test','node_name':'north-gateway','node_tag':'tag:gateway','install_method':'local'}
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps(network))
    status={'BackendState':'Running','Self':{'TailscaleIPs':['100.64.0.10']}}
    prefs={'ControlURL':'https://regional.ci.test','AdvertiseRoutes':[],'ExitNodeID':''}
    executable=Path('/usr/local/bin/tailscale')
    if executable.exists():raise ValueError('Synthetic gateway fixture requires no existing VPN client')
    executable.write_text('#!/usr/bin/python3\nimport json,sys\nprint(json.dumps('+repr(status)+' if sys.argv[1:]==["status","--json"] else '+repr(prefs)+'))\n');executable.chmod(0o755)
    Path('/etc/systemd/system/tailscaled.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    run('systemctl','daemon-reload');run('systemctl','start','tailscaled')
    import gateway_operations as operations
    import gateway_runtime as runtime
    import gateway_transition
    from gateway_store import Store
    assert operations.install(profile,own)['state']=='gateway-listeners-installed'
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    assert operations.change([document])['partners']==1
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    assert curl('rdc-service','/_matrix/federation/v1/version',proxy=True).stdout=='fixture:/_matrix/federation/v1/version'
    # Native systemd/container restart retains the exact approved installation.
    run('systemctl','restart',runtime.UNIT)
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    assert operations.install(profile,own)['partners']==1
    store=Store(runtime.BASE);identifier=document['offer']['payload']['agreement_id']
    certificate_acceptance(store)
    assert run('systemctl','is-active','rdc-regional-guard.timer').strip()=='active'
    from regional_workspace import private_write
    original_clock=(runtime.BASE/'clock.json').read_bytes()
    private_write(runtime.BASE/'clock.json',json.dumps({'schema_version':1,'latest_utc':int(time.time())+120}).encode(),replace=True)
    time.sleep(3)
    result=subprocess.run(['systemctl','start','rdc-regional-guard.service'],capture_output=True)
    assert result.returncode!=0
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    # Reset only the synthetic checkpoint created immediately above; the host
    # clock itself is never changed. Real operators must correct/synchronize UTC.
    private_write(runtime.BASE/'clock.json',original_clock,replace=True)
    time.sleep(3)
    run('systemctl','start','rdc-regional-guard.service')
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    with store.lock(wait_seconds=10):
        interrupted=store.candidate([document],[],now=int(time.time()));store.begin(interrupted)
    time.sleep(3)
    run('systemctl','start','rdc-regional-guard.service')
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    assert operations.change(resume=True)['partners']==1
    print('Actual scheduled gateway guard closes on backwards-clock evidence and an abandoned pending intent; explicit recovery restores only current approved peers PASS.',flush=True)
    class FailureAfterRestart(runtime.Runtime):
        def restart(self):super().restart();raise ValueError('Injected interruption after new policy installation')
    with store.lock(wait_seconds=10):
        candidate=store.candidate([document],[identifier],now=int(time.time()))
        try:gateway_transition.apply(store,FailureAfterRestart(store),candidate)
        except gateway_transition.TransitionError as error:assert error.closed
        else:raise AssertionError('Failed policy was reported as activated')
    assert store.pending()
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    # Restarting during the interrupted change must not reopen previous access.
    run('systemctl','restart',runtime.UNIT)
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    assert operations.change(resume=True)['partners']==0 and not store.pending()
    assert operations.change([document])['partners']==0
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    print('Actual gateway installer/frozen runtime: initially closed, approved policy, repeated installation, systemd restart, interrupted revocation, closed restart, explicit resume and replay denial PASS. VPN identity remains a synthetic fixture.',flush=True)
    recovery_boundary_acceptance(store,document)


def recovery_boundary_acceptance(store,document):
    import gateway_operations as operations
    import gateway_runtime as runtime
    import gateway_recovery
    import gateway_certificates
    def issued(now):
        own=store.identity();peer=document['offer']['payload']['recipient']
        offered=agreements.offer(APPROVAL_KEYS['north'],own,peer,['matrix'],now=now,expires_at=now+1800,expected_peer=agreements.fingerprint(peer))
        return agreements.accept(APPROVAL_KEYS['south'],offered,now=now,expected_peer=agreements.fingerprint(own))
    old=issued(int(time.time())-2)
    assert operations.change([old])['partners']==1
    history=store.state()['revoked_ids']
    with store.lock(wait_seconds=10):gateway_recovery.suspend(store,'a'*32,now=int(time.time()))
    run('systemctl','restart',runtime.UNIT)
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    try:operations.change([old])
    except ValueError as error:assert 'recovery' in str(error)
    else:raise AssertionError('Pre-recovery agreement reopened the gateway')
    # Certificate maintenance is independent of permission to share.
    active=store.base/'tls/active'
    inputs=ROOT/'recovery-maintenance-tls';inputs.mkdir(mode=0o700)
    for name in ('tls.crt','tls.key'):(inputs/name).write_bytes((active/name).read_bytes());(inputs/name).chmod(0o600)
    gateway_certificates.replace(inputs/'tls.crt',inputs/'tls.key')
    assert store.recovery_pending()
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    current=issued(int(time.time()))
    assert operations.change([current])['partners']==1
    assert not store.recovery_pending() and store.state()['revoked_ids']==history
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    try:operations.change([old])
    except ValueError as error:assert 'recovery' in str(error)
    else:raise AssertionError('Reviewed recovery forgot its historical approval floor')
    print('Actual gateway recovery boundary: old approvals remain closed across restart and TLS maintenance; fresh bilateral approval reopens, revocations and replay floor remain retained PASS. Encrypted gateway restore is tested separately.',flush=True)


def certificate_acceptance(store):
    import hashlib
    import gateway_certificates as certificates
    import gateway_runtime as runtime
    from certificate_lifecycle import ActivationError
    from regional_workspace import private_write
    before=(store.base/'state.json').read_bytes()
    names=sorted(store.identity()['payload']['services'].values())
    def issued(label):
        folder=ROOT/label;folder.mkdir(mode=0o700)
        run('openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(folder/'tls.key'),'-out',str(folder/'request.csr'),'-subj','/CN='+names[0])
        (folder/'extensions').write_text('subjectAltName='+','.join('DNS:'+name for name in names)+'\nextendedKeyUsage=serverAuth\n')
        run('openssl','x509','-req','-in',str(folder/'request.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),'-CAcreateserial','-out',str(folder/'tls.crt'),'-days','30','-extfile',str(folder/'extensions'))
        (folder/'tls.key').chmod(0o600)
        return folder
    def remote_fingerprint():
        code=('import ssl,socket,hashlib;'
              's=ssl.create_default_context().wrap_socket(socket.create_connection(("100.64.0.10",443),timeout=5),server_hostname='+repr(names[0])+');'
              'print(hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest());s.close()')
        return run('ip','netns','exec','rdc-peer',sys.executable,'-c',code).strip()
    original=remote_fingerprint();replacement=issued('replacement-certificate')
    result=certificates.replace(replacement/'tls.crt',replacement/'tls.key')
    assert result['state']=='active' and result['fingerprint']!=original
    assert remote_fingerprint()==result['fingerprint']
    assert certificates.status(store)['serving_certificate_verified']
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    local=run('curl','--silent','--show-error','--noproxy','*','--resolve',names[0]+':9443:127.0.0.1','--output','/dev/null','--write-out','%{http_code}','https://'+names[0]+':9443/')
    assert local=='403'
    for namespace_name,address in (('rdc-peer','100.64.0.10'),('rdc-service','10.203.1.1')):
        result_probe=subprocess.run(['ip','netns','exec',namespace_name,'curl','--silent','--max-time','2','--noproxy','*','--resolve',names[0]+':9443:'+address,'https://'+names[0]+':9443/'],capture_output=True)
        assert result_probe.returncode!=0,'TLS check listener is reachable outside loopback'
    candidate=issued('failed-certificate')
    class Failure(certificates.Runtime):
        def __init__(self,store):super().__init__(store);self.fail=True
        def verify(self,hostname,fingerprint):
            super().verify(hostname,fingerprint)
            if self.fail:self.fail=False;raise ValueError('Injected failure after actual TLS replacement')
    with store.lock(wait_seconds=10):
        try:certificates.activate_certificate(store,(candidate/'tls.crt').read_bytes(),(candidate/'tls.key').read_bytes(),runtime=Failure(store))
        except ActivationError as error:assert error.recovered
        else:raise AssertionError('Failed gateway TLS activation was reported as successful')
    assert remote_fingerprint()==result['fingerprint']
    assert not certificates.pending(store)
    cert,key=certificates.managed_material(store)
    with store.lock(wait_seconds=10):
        private_write(store.base/certificates.MARKER,json.dumps({'schema_version':1,'material_digest':hashlib.sha256(cert+key).hexdigest()}).encode())
    run('systemctl','restart',runtime.UNIT)
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    resumed=certificates.replace(replacement/'tls.crt',replacement/'tls.key')
    assert resumed['state']=='active' and remote_fingerprint()==result['fingerprint']
    assert (store.base/'state.json').read_bytes()==before
    print('Actual gateway TLS: new served certificate, loopback-only deny-all verifier, verified rollback after injected failure, closed interrupted restart and exact resume without approval changes PASS.',flush=True)
    from ci_service_issuer import exercise as issuer_exercise
    def renewal_certificate():
        folder=issued('automatically-renewed-certificate')
        return folder/'tls.crt',folder/'tls.key'
    issuer_exercise(renewal_certificate,package='gateway')
    assert (store.base/'state.json').read_bytes()==before

if __name__=='__main__':
    try:main()
    finally:
        for process in PROCESSES:
            if process.poll() is None:process.terminate()

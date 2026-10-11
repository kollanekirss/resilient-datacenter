import importlib
import pytest
from appliance.contracts import ApplianceError


def test_console_code_transport_is_structured_and_cannot_inject_shell():
    module=importlib.import_module('appliance.lab_probe_guest')
    encoded=module.python_command('print(1)',{'x':"'; touch /bad; '"},'a'*32)
    assert 'touch /bad' not in encoded and encoded.startswith('python3 -c ')
    with pytest.raises(ApplianceError):module.python_command('print(1)',{},'wrong nonce')


def test_temporary_peer_requires_named_bridge_and_valid_available_address():
    module=importlib.import_module('appliance.lab_probe_guest')
    with pytest.raises(ApplianceError):module.peer_parameters({'networks':{'infrastructure':{'bridge':'eth0','cidr':'10.77.1.0/24','gateway':'10.77.1.1'}}},'infrastructure')
    plan={'networks':{'infrastructure':{'bridge':'vmbr2','cidr':'10.77.1.0/24','gateway':'10.77.1.1'}}}
    assert module.peer_parameters(plan,'infrastructure')['address']=='10.77.1.20'


def test_transport_executes_multiline_payload_without_interpolating_parameters():
    from appliance.lab_probe_guest import python_command
    import subprocess,shlex,sys
    command=python_command("result=[]\nfor n in range(2):\n result.append(p['x']+str(n))\nprint(json.dumps(result))",{'x':'$(`hi`)'},'a'*32)
    argv=shlex.split(command);argv[0]=sys.executable
    result=subprocess.run(argv,capture_output=True,text=True,check=True)
    assert result.stdout=='["$(`hi`)0", "$(`hi`)1"]\n'


def test_stopped_probe_receipt_uses_fresh_workload_peer(monkeypatch,tmp_path):
    from appliance import lab_probe_guest as module
    from contextlib import contextmanager
    monkeypatch.setattr(module.probe,'_read',lambda *a:{'connected':True})
    monkeypatch.setattr(module.proxmox,'observe_vm',lambda *a:{'running':False})
    seen=[]
    @contextmanager
    def peer(*args,**kwargs):
        seen.append('new-peer');yield 'namespace',{'address':'10.77.3.20'}
    monkeypatch.setattr(module,'peer_namespace',peer)
    with module.source_client({'vms':{'probe':{'vmid':9001}}},'workload',object(),tmp_path) as (_,address):
        assert address=='10.77.3.20'
    assert seen==['new-peer']


def test_persistent_flow_uses_verified_signed_leaf_and_same_live_connection(tmp_path):
    from appliance.lab_probe_guest import FLOW_PROGRAM
    import hashlib,json,os,socket,ssl,subprocess,sys,tempfile,threading,time
    ca,key,cert,csr,leafkey=[tmp_path/name for name in ('ca.pem','ca.key','leaf.pem','leaf.csr','leaf.key')]
    def openssl(*args):subprocess.run(['/usr/bin/openssl',*map(str,args)],check=True,capture_output=True,timeout=15)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',ca,'-days','1','-subj','/CN=Acceptance CA')
    openssl('req','-newkey','rsa:2048','-nodes','-keyout',leafkey,'-out',csr,'-subj','/CN=lab.invalid')
    extensions=tmp_path/'extensions';extensions.write_text('subjectAltName=DNS:lab.invalid\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',key,'-CAcreateserial','-out',cert,'-days','1','-extfile',extensions)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,leafkey)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
    endpoint=listener.getsockname();observed=[];errors=[]
    def serve():
        try:
            connection,_=listener.accept()
            with context.wrap_socket(connection,server_side=True) as stream:
                for _ in range(2):
                    raw=stream.recv(1024);observed.append(raw);stream.sendall(raw[8:])
        except Exception as error:errors.append(error)
        finally:listener.close()
    thread=threading.Thread(target=serve);thread.start()
    with tempfile.TemporaryDirectory(prefix='rdc-flow-',dir='/tmp') as directory:
        path=directory+'/control'
        child=subprocess.Popen([sys.executable,'-c',FLOW_PROGRAM,path,endpoint[0],str(endpoint[1]),'a'*32,str(ca)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+10
            while not os.path.exists(path):
                assert time.monotonic()<deadline and child.poll() is None
                time.sleep(.02)
            def request(value):
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(5);client.connect(path);client.sendall(json.dumps(value).encode());return json.loads(client.recv(65536))
            before=request({'action':'before'});after=request({'action':'check','nonce':'b'*32})
            assert before['before']['returncode']==after['after']['returncode']==0
            assert before['source']==after['source'] and before['destination']==after['destination']==list(endpoint)
            assert after['after']['stdout']=='b'*32
            stdout,stderr=child.communicate(timeout=5);assert child.returncode==0 and not stderr
        finally:
            if child.poll() is None:child.kill();child.wait()
            thread.join(timeout=10)
    assert not errors and observed==[b'RDCFLOW '+b'a'*32+b'\n',b'RDCFLOW '+b'b'*32+b'\n']

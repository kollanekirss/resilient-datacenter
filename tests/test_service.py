import importlib.util
import json
from pathlib import Path
import threading
import urllib.request
import pytest

def service():
    p=Path(__file__).resolve().parents[1]/'roles/test_service/files/test_service.py'
    assert p.exists(),'HTTPS service not implemented'
    s=importlib.util.spec_from_file_location('health_service',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

@pytest.mark.parametrize('address',['0.0.0.0','127.0.0.1','192.168.1.1','::','1.1.1.1'])
def test_refuses_non_overlay_address(address):
    with pytest.raises(ValueError): service().overlay_address(address)

def test_accepts_overlay_address():
    assert service().overlay_address('100.64.0.1')=='100.64.0.1'

def test_health_response_and_no_file_browsing():
    m=service(); server=m.HTTPServer(('127.0.0.1',0),m.handler_for('server-a'))
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        base='http://127.0.0.1:'+str(server.server_port)
        with urllib.request.urlopen(base+'/health') as response:
            assert json.load(response)=={'status':'ok','server':'server-a'}
        with pytest.raises(urllib.error.HTTPError) as e: urllib.request.urlopen(base+'/etc/passwd')
        assert e.value.code==404
    finally:
        server.shutdown(); server.server_close(); thread.join()

from test_tls import certs

def test_tls_handshake_verifies_trust_and_hostname(certs):
    import ssl
    import socket
    cp,kp=certs
    m=service(); server=m.HTTPServer(('127.0.0.1',0),m.handler_for('server-b'))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cp,kp)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    client=ssl.create_default_context(cafile=str(cp))
    try:
        with socket.create_connection(('127.0.0.1',server.server_port),timeout=3) as raw:
            with client.wrap_socket(raw,server_hostname='a.pilot.test') as tls:
                tls.sendall(b'GET /health HTTP/1.0\r\nHost: a.pilot.test\r\n\r\n')
                response=b''
                while chunk:=tls.recv(4096): response+=chunk
                assert json.loads(response.split(b'\r\n\r\n',1)[1])=={'status':'ok','server':'server-b'}
        with socket.create_connection(('127.0.0.1',server.server_port),timeout=3) as raw:
            with pytest.raises(ssl.SSLCertVerificationError): client.wrap_socket(raw,server_hostname='wrong.pilot.test')
    finally:
        server.shutdown(); server.server_close(); thread.join()

def test_profile_node_identity_accepts_safe_arbitrary_name():
    assert service().node_identity('north-services-2')=='north-services-2'

@pytest.mark.parametrize('identity',['','bad name','../other','{{ value }}','A-B','-flag'])
def test_profile_node_identity_rejects_unsafe_values(identity):
    with pytest.raises(ValueError): service().node_identity(identity)

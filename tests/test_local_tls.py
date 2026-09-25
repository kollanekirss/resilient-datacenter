import importlib
import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
from test_tls import certs
from test_setup_contracts import ROOT

@pytest.fixture
def tls_server(certs):
    cert,key=certs
    server=HTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try: yield server,ssl.create_default_context(cafile=str(cert))
    finally: server.shutdown(); server.server_close(); thread.join()

def test_local_tls_check_accepts_trusted_matching_certificate(tls_server):
    server,context=tls_server
    from local_checks import tls_errors
    assert tls_errors('a.pilot.test',connect_address=('127.0.0.1',server.server_port),context=context)==[]

def test_local_tls_check_rejects_wrong_hostname(tls_server):
    server,context=tls_server
    from local_checks import tls_errors
    assert tls_errors('other.pilot.test',connect_address=('127.0.0.1',server.server_port),context=context)

def test_local_tls_check_rejects_untrusted_certificate(tls_server):
    server,_=tls_server
    from local_checks import tls_errors
    assert tls_errors('a.pilot.test',connect_address=('127.0.0.1',server.server_port))

def test_local_tls_check_rejects_expired_certificate(certs):
    from test_tls import test_expired_certificate as expire
    from local_checks import tls_errors
    expire(certs)
    cert,key=certs
    server=HTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        assert tls_errors('a.pilot.test',connect_address=('127.0.0.1',server.server_port),context=ssl.create_default_context(cafile=str(cert)))
    finally: server.shutdown(); server.server_close(); thread.join()

"""HTTPS fixture backend used only inside disposable gateway network namespaces."""
import http.server
import os
from pathlib import Path
import ssl
import sys
import time


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('Disposable CI only')
    address,port,certificate,key=sys.argv[1:]
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def do_GET(self):
            if self.path.endswith('/stream'):
                self.send_response(200);self.send_header('Content-Length','100000');self.end_headers()
                try:
                    for _ in range(1000):self.wfile.write(b'fixture-stream\n');self.wfile.flush();time.sleep(.1)
                except (BrokenPipeError,ConnectionResetError):pass
            else:
                data=('fixture:'+self.path).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer((address,int(port)),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
    server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()

if __name__=='__main__':main()

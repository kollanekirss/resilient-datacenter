#!/usr/bin/env python3
"""Minimal pilot endpoint. Production CLI accepts only an overlay IPv4 address."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import re
import ssl


def overlay_address(value):
    address=ipaddress.ip_address(value)
    if address not in ipaddress.ip_network('100.64.0.0/10'): raise ValueError('Must bind an overlay IPv4 address')
    return str(address)


def node_identity(value):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value):
        raise ValueError('Expected a lowercase inventory node identifier')
    return value


def handler_for(identity):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/health': self.send_error(404); return
            body=json.dumps({'status':'ok','server':identity}).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self,*args): pass
    return Handler


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--bind',required=True,type=overlay_address)
    p.add_argument('--port',type=int,default=8443,choices=[8443,8444])
    p.add_argument('--identity',required=True,type=node_identity)
    p.add_argument('--cert',required=True); p.add_argument('--key',required=True)
    args=p.parse_args()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert,args.key)
    server=HTTPServer((args.bind,args.port),handler_for(args.identity))
    server.timeout=10
    server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()

if __name__=='__main__': main()

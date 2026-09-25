#!/usr/bin/python3
"""Owned NGINX startup and read-only health checks; no downloads or enrollment."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import time
if __name__=='__main__':sys.path.insert(0,'/usr/local/lib/rdc-frontend')
import portable_frontend as contract

BASE=Path('/etc/rdc-frontend')
INSTALLED=Path('/usr/local/lib/rdc-frontend')
UNIT='rdc-frontend.service'


def read(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>262144:raise ValueError('Unsafe frontend configuration')
    return path.read_bytes()


def settings():
    if sys.platform!='linux' or os.geteuid()!=0:raise ValueError('Use the intended managed Linux frontend')
    c=contract.validate(json.loads(read(BASE/'configuration.json')))
    if read(BASE/'nginx.conf').decode()!=contract.nginx(c):raise ValueError('Frontend configuration drift requires review')
    manifest=json.loads(read(INSTALLED/'manifest.json'))
    expected={'portable_frontend.py','portable_frontend_runtime.py','application_access.py'}
    if set(manifest)!={'schema_version','files'} or manifest['schema_version']!=1 or set(manifest['files'])!=expected:raise ValueError('Unexpected frontend runtime manifest')
    for name in expected:
        if hashlib.sha256(read(INSTALLED/name)).hexdigest()!=manifest['files'][name]:raise ValueError('Frontend runtime differs from its installation')
    return c


def nft(*args,input=None):
    result=subprocess.run(['/usr/sbin/nft',*args],input=input,capture_output=True,text=True,check=True,timeout=15)
    return json.loads(result.stdout) if result.stdout.strip() else None


def normalize(value):
    if isinstance(value,dict):return {k:normalize(v) for k,v in value.items() if k!='handle'}
    if isinstance(value,list):return [normalize(v) for v in value]
    return value


def ingress(c,*,create=False):
    wanted=contract.firewall(c)
    tables=nft('-j','list','tables')
    exists=any(item.get('table',{}).get('name')=='rdc_frontend' and item['table'].get('family')=='inet' for item in tables['nftables'])
    if not exists:
        if not create:raise ValueError('Frontend firewall is missing')
        nft('-j','-f','-',input=json.dumps({'nftables':[{'create':wanted[0]},*({'add':item} for item in wanted[1:])]}))
    actual=nft('-j','list','table','inet','rdc_frontend')
    actual=[normalize(item) for item in actual['nftables'] if 'metainfo' not in item]
    if actual!=wanted:raise ValueError('Frontend firewall differs; no rules were overwritten')


def verify(c):
    context=ssl.create_default_context()
    for role,item in c['services'].items():
        host=item['hostname'];path={'chat':'/_matrix/client/versions','element':'/config.json','files':'/status.php'}[role]
        conn=http.client.HTTPSConnection(c['address'],443,context=context,timeout=5)
        try:
            raw=socket.create_connection((c['address'],443),timeout=5)
            conn.sock=context.wrap_socket(raw,server_hostname=host)
            conn.request('GET',path,headers={'Host':host})
            response=conn.getresponse();body=response.read(1048576)
            if response.status!=200:raise ValueError('Local application frontend is not ready')
            data=json.loads(body)
            if role=='chat' and not data.get('versions'):raise ValueError('Matrix frontend response is invalid')
            if role=='element' and data.get('default_server_config',{}).get('m.homeserver',{}).get('base_url')!='https://'+c['services']['chat']['hostname']:raise ValueError('Element points to a different homeserver')
            if role=='files' and (data.get('installed') is not True or data.get('maintenance') or data.get('needsDbUpgrade')):raise ValueError('Files frontend is not ready')
        finally:conn.close()



def verify_tls(c):
    # A failed backend must not prevent access to healthy applications.
    # Startup verifies this listener; status separately verifies applications.
    context=ssl.create_default_context()
    for item in c['services'].values():
        with socket.create_connection((c['address'],443),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname=item['hostname']):pass


def main(action):
    c=settings()
    if action=='prepare':
        from application_access import verify_assigned
        verify_assigned(c['address'])
        ingress(c,create=True)
        return
    if action not in ('ready','status'):raise ValueError('Unsupported frontend operation')
    ingress(c)
    for attempt in range(12 if action=='ready' else 1):
        try:
            (verify_tls if action=='ready' else verify)(c)
            return
        except (OSError,ValueError,http.client.HTTPException):
            if action=='status' or attempt==11:raise
            time.sleep(2)


if __name__=='__main__':
    try:main(sys.argv[1])
    except (IndexError,OSError,ValueError,subprocess.SubprocessError,http.client.HTTPException):
        print('Frontend check failed; inspect local configuration and service health. Private details withheld.',file=sys.stderr)
        raise SystemExit(1)

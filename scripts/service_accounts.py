"""Local, hidden-input Matrix account bootstrap; no credentials in process arguments."""
import getpass
import hashlib
import hmac
import http.client
import json
import re
import sys
import service_runtime as runtime


def registration_payload(nonce,username,password,shared_secret,*,admin):
    if not isinstance(username,str) or not re.fullmatch('[a-z][a-z0-9._-]{0,63}',username): raise ValueError('Use a lowercase account name with letters, digits, dots, hyphens or underscores')
    if not isinstance(password,str) or not 12<=len(password)<=256 or any(c in password for c in ('\x00','\r','\n')): raise ValueError('Use a password of 12–256 characters without line breaks')
    if not isinstance(nonce,str) or not 1<=len(nonce)<=256 or '\x00' in nonce or type(admin) is not bool or not isinstance(shared_secret,str) or not re.fullmatch('[a-f0-9]{64}',shared_secret):
        raise ValueError('Invalid account registration context')
    message='\x00'.join((nonce,username,password,'admin' if admin else 'notadmin')).encode()
    return {'nonce':nonce,'username':username,'password':password,'admin':admin,'inhibit_login':True,
            'mac':hmac.new(shared_secret.encode(),message,hashlib.sha1).hexdigest()}


def local_request(method,path,data=None):
    connection=http.client.HTTPConnection('127.0.0.1',8008,timeout=30)
    try:
        connection.request(method,path,body=json.dumps(data) if data is not None else None,headers={'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read(65536)
        if response.status!=200: raise ValueError('Account creation failed; inspect the existing account name and local service status before retrying')
        return json.loads(body)
    finally:connection.close()


def create(username,password,*,admin=False):
    settings=runtime.read_settings();runtime.ready('synapse',settings)
    private=runtime.root_json(runtime.BASE/'secrets.json')
    nonce=local_request('GET','/_synapse/admin/v1/register').get('nonce')
    payload=registration_payload(nonce,username,password,private['registration_secret'],admin=admin)
    result=local_request('POST','/_synapse/admin/v1/register',payload)
    expected='@'+username+':'+settings['ownership']['matrix_hostname']
    if result.get('user_id')!=expected or 'access_token' in result: raise ValueError('Account response needs local review; do not assume a retry is safe')
    return {'state':'account-created','user_id':expected,'administrator':admin,'login_test':'not-run'}


def interactive(*,admin=False):
    if not sys.stdin.isatty(): raise ValueError('Account creation requires an interactive terminal for hidden password entry')
    runtime.read_settings()
    username=input('New Matrix account name (lowercase): ').strip()
    password=getpass.getpass('New password (at least 12 characters): ')
    if password!=getpass.getpass('Repeat password: '):raise ValueError('Passwords differ; no account was created')
    return create(username,password,admin=admin)

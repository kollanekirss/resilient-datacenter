"""Bounded, TLS-verified Proxmox API transport. Never log credentials or responses."""
import json
import http.client
import os
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from portable_plan import fields, require


def credentials(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_mode & 0o077 == 0 and info.st_size <= 4096,
                    'API credentials must be an owned regular file with mode 0600, at most 4 KiB.')
            record = json.load(stream)
        fields(record, 'token_id token_secret')
        require(type(record['token_id']) is str and re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+',record['token_id'])
                and type(record['token_secret']) is str and re.fullmatch(r'[A-Za-z0-9-]{1,256}',record['token_secret']),
                'Invalid API credential format.')
        return record
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Cannot read private Proxmox API credentials.') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, endpoint, auth, ca_file=None):
        try:
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        except (OSError, ssl.SSLError):
            raise ValueError('Cannot load the Proxmox CA trust file.') from None
        self.endpoint = endpoint.rstrip('/') + '/api2/json'
        self.authorization = 'PVEAPIToken=' + auth['token_id'] + '=' + auth['token_secret']
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=context))

    def request(self, method, path, data=None):
        require(method in ('GET','POST') and path.startswith('/') and not path.startswith('//'), 'Unsupported Proxmox request.')
        encoded = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(self.endpoint + path, data=encoded, method=method,
                                        headers={'Authorization':self.authorization, 'Accept':'application/json'})
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(2*1024*1024+1)
            require(len(raw) <= 2*1024*1024, 'Proxmox response exceeded the size limit.')
            record = json.loads(raw)
            require(type(record) is dict and 'data' in record and not record.get('errors'), 'Unexpected Proxmox response.')
            return record['data']
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException, RecursionError):
            # A failed POST may already have reached the server. Never automatically repeat it.
            raise ValueError('Proxmox request failed. Check TLS, permissions and task state before retrying; no automatic retry was made.') from None

    def upload(self, node, storage, filename, stream, size, sha256):
        """Stream ISO multipart data with an explicit server-side checksum."""
        import uuid
        require(all(re.fullmatch(r'[a-z][a-z0-9-]{0,62}',s) for s in (node,storage))
                and re.fullmatch(r'rdc-[a-f0-9-]+\.iso',filename)
                and type(size) is int and size>0 and re.fullmatch('[a-f0-9]{64}',sha256), 'Invalid media upload parameters.')
        boundary='rdc'+uuid.uuid4().hex
        fields={'content':'iso','checksum':sha256,'checksum-algorithm':'sha256'}
        prefix=''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n' for key,value in fields.items())
        prefix+=(f'--{boundary}\r\nContent-Disposition: form-data; name="filename"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n')
        prefix=prefix.encode();suffix=('\r\n--'+boundary+'--\r\n').encode()
        def chunks():
            yield prefix
            remaining=size
            while remaining:
                data=stream.read(min(4*1024*1024,remaining))
                require(bool(data),'Media ended during upload.')
                remaining-=len(data);yield data
            require(not stream.read(1),'Media grew during upload.')
            yield suffix
        request=urllib.request.Request(self.endpoint+f'/nodes/{node}/storage/{storage}/upload', data=chunks(),method='POST',
                  headers={'Authorization':self.authorization,'Content-Type':'multipart/form-data; boundary='+boundary,
                           'Content-Length':str(len(prefix)+size+len(suffix)),'Accept':'application/json'})
        try:
            with self.opener.open(request,timeout=120) as response:raw=response.read(65537)
            require(len(raw)<=65536,'Upload response exceeded its size limit.')
            record=json.loads(raw)
            require(type(record) is dict and type(record.get('data')) is str and record['data'].startswith('UPID:') and not record.get('errors'),
                    'Upload task could not be identified.')
            return record['data']
        except (OSError,ValueError,urllib.error.URLError,http.client.HTTPException,RecursionError):
            raise ValueError('Upload outcome is uncertain. Inspect Proxmox tasks; this request will not be automatically repeated.') from None

"""Bounded, TLS-verified Proxmox API transport. Never log credentials or responses."""
import json
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
        except (OSError, ValueError, urllib.error.URLError, RecursionError):
            # A failed POST may already have reached the server. Never automatically repeat it.
            raise ValueError('Proxmox request failed. Check TLS, permissions and task state before retrying; no automatic retry was made.') from None

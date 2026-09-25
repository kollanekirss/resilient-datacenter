"""Explicit portable application identity; no discovery, mutation or enrollment.

This small contract is also suitable for installation beside the managed runtime.
Only standard-library dependencies are permitted here.
"""
import copy
import ipaddress
import re

ACCESS_FIELDS = {'mode', 'site', 'site_sha256', 'backend_address', 'frontend_address'}
OWNER_FIELDS = {'schema_version', 'role', 'institution_id', 'node_name', 'access'}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def _name(value):
    return type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value) is not None


def _private_address(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError('Portable access requires canonical RFC1918 IPv4 addresses') from None
    if type(value) is not str or address.version != 4 or str(address) != value or not any(address in net for net in PRIVATE):
        raise ValueError('Portable access requires canonical RFC1918 IPv4 addresses')
    return value


def validate_access(access):
    if type(access) is not dict or set(access) != ACCESS_FIELDS:
        raise ValueError('Unexpected portable access fields')
    if (access['mode'] != 'portable-lan' or not _name(access['site'])
            or type(access['site_sha256']) is not str
            or re.fullmatch(r'[a-f0-9]{64}', access['site_sha256']) is None):
        raise ValueError('Invalid portable access identity')
    backend = _private_address(access['backend_address'])
    frontend = _private_address(access['frontend_address'])
    if backend == frontend:
        raise ValueError('Frontend and application require separate VM addresses')
    return copy.deepcopy(access)


def portable_owner(profile):
    if type(profile) is not dict:
        raise ValueError('Application profile must be an object')
    owner = {'schema_version': 1, 'role': 'portable',
             'institution_id': profile.get('institution_id'), 'node_name': profile.get('node_name'),
             'access': validate_access(profile.get('access'))}
    return validate_portable_owner(owner)


def validate_portable_owner(owner):
    if type(owner) is not dict or set(owner) != OWNER_FIELDS:
        raise ValueError('Unexpected portable ownership fields')
    if (type(owner['schema_version']) is not int or owner['schema_version'] != 1
            or owner['role'] != 'portable'
            or not all(_name(owner[key]) for key in ('institution_id', 'node_name'))):
        raise ValueError('Invalid portable ownership identity')
    validate_access(owner['access'])
    return copy.deepcopy(owner)


def bind_address(owner):
    return validate_portable_owner(owner)['access']['backend_address']


def frontend_address(owner):
    return validate_portable_owner(owner)['access']['frontend_address']


def validate_binding(owner, address):
    if type(owner) is not dict:
        raise ValueError('Invalid application network identity')
    if owner.get('role') == 'portable':
        if address != bind_address(owner):
            raise ValueError('Portable backend address differs from installed ownership')
        return
    if owner.get('role') != 'peer':
        raise ValueError('Unsupported application network role')
    try:
        value = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        raise ValueError('Invalid application overlay address') from None
    if type(address) is not str or value.version != 4 or value not in ipaddress.ip_network('100.64.0.0/10'):
        raise ValueError('Invalid application overlay address')


def access_profile(application):
    network=application.get('network',{})
    if network.get('role')!='portable':return {}
    return {'access':validate_portable_owner(network)['access']}


def portable_proxy(profile,address,package):
    """LAN TLS adapter, with one authenticated-by-network forwarding source."""
    access=validate_access(profile['access'])
    if address!=access['backend_address']:raise ValueError('Portable proxy address differs from profile')
    common='    bind '+address+'\n    tls /tls/tls.crt /tls/tls.key\n    header X-Content-Type-Options nosniff\n'
    headers=('            header_up X-Forwarded-For {http.vars.client_ip}\n'
             '            header_up X-Real-IP {http.vars.client_ip}\n'
             '            header_up X-Forwarded-Proto https\n'
             '            header_up -Forwarded\n')
    def upstream(port):
        return '        reverse_proxy 127.0.0.1:'+str(port)+' {\n'+headers+'        }\n'
    text=('{\n    admin off\n    auto_https off\n    servers {\n        protocols h1 h2\n'
          '        trusted_proxies static '+access['frontend_address']+'\n'
          '        trusted_proxies_strict\n    }\n}\n')
    if package=='matrix':
        import json
        discovery=json.dumps({'m.homeserver':{'base_url':'https://'+profile['matrix_hostname']}},separators=(',',':'))
        text+='https://'+profile['matrix_hostname']+' {\n'+common
        text+='    handle /.well-known/matrix/client {\n        header Content-Type application/json\n        header Access-Control-Allow-Origin *\n        respond `'+discovery+'`\n    }\n'
        for path in ('/_matrix/client/*','/_matrix/media/*'):
            text+='    handle '+path+' {\n'+upstream(8008)+'    }\n'
        text+='    handle {\n        respond "Not exposed" 404\n    }\n}\n'
        text+='https://'+profile['element_hostname']+' {\n'+common+upstream(8082)+'}\n'
    elif package=='nextcloud':
        text+='https://'+profile['nextcloud_hostname']+' {\n'+common
        text+='    header Strict-Transport-Security "max-age=15552000"\n    redir /.well-known/carddav /remote.php/dav/ 301\n    redir /.well-known/caldav /remote.php/dav/ 301\n'
        text+=upstream(8083)+'}\n'
    else:raise ValueError('Unknown portable application package')
    return text


def verify_local_address(owner):
    return verify_assigned(bind_address(owner))


def verify_assigned(address):
    import json
    import subprocess
    _private_address(address)
    result=subprocess.run(['/usr/sbin/ip','-j','-4','address','show'],check=True,capture_output=True,text=True,timeout=15)
    records=json.loads(result.stdout)
    if not any(record.get('ifname')!='lo' and 'UP' in record.get('flags',[]) and
               any(item.get('local')==address for item in record.get('addr_info',[])) for record in records):
        raise ValueError('The intended portable backend IPv4 is not assigned to an active local interface')
    return address

"""Optional Matrix regional connector, independent of its backed-up home identity.

Only the root installer writes this reviewed, fixed-shape configuration. Signing
and approval verification happen before installation. This runtime uses stdlib
only; a restore disables the connector until a fresh explicit review.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

BASE=Path('/etc/rdc-service-regional')
RESTORE=Path('/etc/rdc-restore-pending.json')
FIELDS={'schema_version','package','application_owner','gateway_fingerprint','gateway_lan_address','service_lan_address','lan_subnet','peers'}
PRIVATE=tuple(ipaddress.ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def hostname(value):
    return isinstance(value,str) and len(value)<254 and '.' in value and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.'))


def validate(config,settings):
    if not isinstance(config,dict) or set(config)!=FIELDS or type(config['schema_version']) is not int or config['schema_version']!=1 or config['package']!='matrix':raise ValueError('Unsupported regional application connector')
    if config['application_owner']!=settings['ownership'] or settings['ownership'].get('packages')!=['matrix'] or not hostname(settings['ownership'].get('matrix_hostname')):raise ValueError('Connector belongs to another application installation')
    if not isinstance(config['gateway_fingerprint'],str) or not re.fullmatch('[a-f0-9]{64}',config['gateway_fingerprint']):raise ValueError('Invalid approved gateway fingerprint')
    subnet=ipaddress.ip_network(config['lan_subnet'],strict=True)
    if subnet.version!=4 or not 24<=subnet.prefixlen<=30 or not any(subnet.subnet_of(block) for block in PRIVATE):raise ValueError('Connector needs its dedicated private LAN')
    addresses=[ipaddress.ip_address(config[field]) for field in ('gateway_lan_address','service_lan_address')]
    if len(set(addresses))!=2 or any(value not in subnet or value in (subnet.network_address,subnet.broadcast_address) for value in addresses):raise ValueError('Use distinct usable private gateway and service addresses')
    peers=config['peers'];seen=set()
    if not isinstance(peers,list) or len(peers)>8:raise ValueError('Unsupported connector peer count')
    for peer in peers:
        if not isinstance(peer,dict) or set(peer)!={'hostname','expires_at'} or not hostname(peer['hostname']) or peer['hostname'] in seen or peer['hostname']==settings['ownership']['matrix_hostname'] or type(peer['expires_at']) is not int or not 0<=peer['expires_at']<=253402300799:raise ValueError('Invalid connector peer identity or lifetime')
        seen.add(peer['hostname'])


def synapse(config,*,now):
    return json.dumps({'federation_domain_whitelist':sorted(peer['hostname'] for peer in config['peers'] if now<peer['expires_at']),
        'http_proxy':'http://'+config['gateway_lan_address']+':3128','https_proxy':'http://'+config['gateway_lan_address']+':3128',
        'no_proxy_hosts':[],'federation_verify_certificates':True,'federation_custom_ca_list':['/etc/ssl/certs/ca-certificates.crt']},sort_keys=True)+'\n'


def proxy(original,config):
    return original+'\nhttps://'+config['application_owner']['matrix_hostname']+':8443 {\n    bind '+config['service_lan_address']+'\n    tls /tls/tls.crt /tls/tls.key\n'+\
        '    @regional {\n        remote_ip '+config['gateway_lan_address']+'\n        path /_matrix/federation/* /_matrix/key/*\n    }\n'+\
        '    handle @regional {\n        reverse_proxy 127.0.0.1:8008\n    }\n    handle {\n        respond "Regional endpoint not exposed" 403\n    }\n}\n'


def read(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022 or info.st_size>65536:raise ValueError('Unsafe regional connector file')
    return path.read_bytes()


def write(path,raw,*,mode=0o644):
    if isinstance(raw,str):raw=raw.encode()
    if path.exists() or path.is_symlink():read(path)
    descriptor,temporary=tempfile.mkstemp(prefix='.rdc-regional-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,mode);os.replace(temporary,path)
        descriptor=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def directory_exists():
    if not (BASE.exists() or BASE.is_symlink()):return False
    info=BASE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise ValueError('Unsafe regional connector directory')
    return True


def configured(settings):
    if not directory_exists():return None
    path=BASE/'configuration.json'
    # A crash immediately after first mkdir has not installed a connector.
    # Preserve internal service operation and allow explicit attach to resume.
    if not (path.exists() or path.is_symlink()):return None
    config=json.loads(read(path));validate(config,settings);return config


def active(settings):
    if not directory_exists():return None
    if any(path.exists() or path.is_symlink() for path in (BASE/'disabled.json',BASE/'pending.json',RESTORE)):return None
    return configured(settings)


def materialize(settings,original_proxy):
    if not directory_exists():return
    if RESTORE.exists() or RESTORE.is_symlink():
        write(BASE/'disabled.json',json.dumps({'reason':'application-restore-requires-current-partner-review'}),mode=0o600)
    config=active(settings)
    if config is None:return
    write(BASE/'synapse.json',synapse(config,now=int(time.time())))
    write(BASE/'Caddyfile',proxy(original_proxy,config))

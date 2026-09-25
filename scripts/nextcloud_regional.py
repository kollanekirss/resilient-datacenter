"""Private file-service connector; original application identity remains separate."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
from service_regional import read,write,hostname,PRIVATE,FIELDS
from regional_http import NEXTCLOUD_ROUTES

BASE=Path('/etc/rdc-nextcloud-regional')
RESTORE=Path('/etc/rdc-restore-pending.json')
UPGRADE=Path('/etc/rdc-upgrade-pending.json')


def validate(config,settings):
    if settings.get('ownership',{}).get('network',{}).get('role')=='portable':
        raise ValueError('Portable partner connectivity requires its separate relocation and federation acceptance phase')
    if not isinstance(config,dict) or set(config)!=FIELDS or type(config['schema_version']) is not int or config['schema_version']!=1 or config['package']!='nextcloud':raise ValueError('Unsupported regional file connector')
    owner=settings['ownership']
    if config['application_owner']!=owner or owner.get('packages')!=['nextcloud'] or not hostname(owner.get('nextcloud_hostname')):raise ValueError('Connector belongs to another file installation')
    if not isinstance(config['gateway_fingerprint'],str) or not re.fullmatch('[a-f0-9]{64}',config['gateway_fingerprint']):raise ValueError('Invalid institution fingerprint')
    subnet=ipaddress.ip_network(config['lan_subnet'],strict=True)
    if subnet.version!=4 or not 24<=subnet.prefixlen<=30 or not any(subnet.subnet_of(block) for block in PRIVATE):raise ValueError('Use a dedicated private LAN')
    addresses=[ipaddress.ip_address(config[field]) for field in ('gateway_lan_address','service_lan_address')]
    if len(set(addresses))!=2 or any(value not in subnet or value in (subnet.network_address,subnet.broadcast_address) for value in addresses):raise ValueError('Use distinct usable LAN addresses')
    peers=config['peers'];seen=set()
    if not isinstance(peers,list) or len(peers)>8:raise ValueError('Unsupported peer count')
    for peer in peers:
        if not isinstance(peer,dict) or set(peer)!={'hostname','expires_at'} or not hostname(peer['hostname']) or peer['hostname'] in seen or peer['hostname']==owner['nextcloud_hostname'] or type(peer['expires_at']) is not int or not 0<=peer['expires_at']<=253402300799:raise ValueError('Invalid file partner identity or lifetime')
        seen.add(peer['hostname'])


def php_overlay(config):
    values={'proxy':'http://'+config['gateway_lan_address']+':3128' if config else 'http://127.0.0.1:9',
            'proxyexclude':[],'sharing.federation.allowSelfSignedCertificates':False,'allow_local_remote_servers':False,
            # The proxy pins approved DNS identities to signed addresses without
            # resolving them. Nextcloud's separate DNS middleware runs before
            # CONNECT and rejects this intentionally private destination space.
            # Keep hostname/literal-address checks and end-to-end TLS enabled.
            'dns_pinning':config is None}
    encoded=base64.b64encode(json.dumps(values,sort_keys=True).encode()).decode()
    return '<?php\n$CONFIG = json_decode(base64_decode("'+encoded+'"), true, 512, JSON_THROW_ON_ERROR);\n'


def proxy(original,config):
    text=original+'\nhttps://'+config['application_owner']['nextcloud_hostname']+':8443 {\n    bind '+config['service_lan_address']+'\n    tls /tls/tls.crt /tls/tls.key\n'
    for index,(methods,pattern) in enumerate(NEXTCLOUD_ROUTES):
        name='regional_files_'+str(index)
        text+='    @'+name+' {\n        remote_ip '+config['gateway_lan_address']+'\n        method '+' '.join(methods)+'\n        path_regexp '+name+' `'+pattern+'`\n    }\n'
        text+='    handle @'+name+' {\n        reverse_proxy 127.0.0.1:8083 {\n            header_up X-Real-IP {remote_host}\n        }\n    }\n'
    return text+'    handle {\n        respond "Regional endpoint not exposed" 403\n    }\n}\n'


def directory_exists():
    if not (BASE.exists() or BASE.is_symlink()):return False
    info=BASE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise ValueError('Unsafe file connector directory')
    return True


def configured(settings):
    if not directory_exists():return None
    path=BASE/'configuration.json'
    if not (path.exists() or path.is_symlink()):return None
    config=json.loads(read(path));validate(config,settings);return config


def active(settings):
    if not directory_exists():return None
    if any(path.exists() or path.is_symlink() for path in (BASE/'disabled.json',BASE/'pending.json',RESTORE,UPGRADE)):return None
    config=configured(settings)
    if config is None or not any(int(time.time())<peer['expires_at'] for peer in config['peers']):return None
    return config


def materialize(settings,original,application_config=None):
    if not directory_exists():
        BASE.mkdir(mode=0o750);BASE.chmod(0o750)
        if os.geteuid()==0:os.chown(BASE,0,33)
    if RESTORE.exists() or RESTORE.is_symlink() or UPGRADE.exists() or UPGRADE.is_symlink():write(BASE/'disabled.json',json.dumps({'reason':'application-restore-requires-current-partner-review'}),mode=0o600)
    config=active(settings)
    directory=BASE/'runtime-config'
    if not directory.exists():directory.mkdir(mode=0o750);directory.chmod(0o750)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise ValueError('Unsafe generated file configuration')
    if any(item.name not in ('config.php','zz-regional.config.php') for item in directory.iterdir()):raise ValueError('Unreviewed generated file configuration')
    if os.geteuid()==0:os.chown(directory,0,33)
    write(directory/'zz-regional.config.php',php_overlay(config),mode=0o640)
    if application_config is not None:
        # Nextcloud's CLI requires config.php to belong to the application UID.
        # The parent remains root-owned and the container mount remains read-only.
        uid=33 if os.geteuid()==0 else os.geteuid()
        write(directory/'config.php',application_config,mode=0o400,owner=uid,gid=33 if os.geteuid()==0 else None)
    if os.geteuid()==0:
        os.chown(directory/'zz-regional.config.php',0,33)
    write(BASE/'Caddyfile',proxy(original,config) if config else original)


FEDERATION_CONTROLS=('outgoing_server2server_share_enabled','incoming_server2server_share_enabled',
                     'outgoing_server2server_group_share_enabled','incoming_server2server_group_share_enabled',
                     'lookupServerEnabled','lookupServerUploadEnabled','federatedTrustedShareAutoAccept')


def controls(config):
    values={name:'no' for name in FEDERATION_CONTROLS}
    if config:
        for name in ('outgoing_server2server_share_enabled','incoming_server2server_share_enabled'):values[name]='yes'
    return values

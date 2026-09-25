"""Non-executable backup settings and the fixed set of owned persistent resources."""
import base64
from dataclasses import dataclass
import ipaddress
import re
from profile_config import _safe_values,_identifier
from validate_inventory import hostname

FIELDS={'kind','schema_version','institution_id','node_name','role','backup_host','backup_port','backup_host_key'}
RESTIC_VERSION='0.19.1'
RESTIC_SHA256='f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c'


def valid_host_key(value):
    if not isinstance(value,str): return False
    parts=value.split(' ')
    if len(parts)!=2 or parts[0]!='ssh-ed25519': return False
    try:
        raw=base64.b64decode(parts[1],validate=True)
        return len(raw)==51 and raw[:4]==(11).to_bytes(4,'big') and raw[4:15]==b'ssh-ed25519' and raw[15:19]==(32).to_bytes(4,'big')
    except (ValueError,TypeError): return False


def validate(data):
    if not isinstance(data,dict) or set(data)!=FIELDS or not _safe_values(data): return ['Use only the documented backup-profile fields; secrets and commands are forbidden.']
    errors=[]
    if data['kind']!='backup-profile' or type(data['schema_version']) is not int or data['schema_version']!=1: errors.append('Unsupported backup profile.')
    if not all(_identifier(data[k]) for k in ('institution_id','node_name')): errors.append('Invalid institution/node identifier.')
    if data['role'] not in ('controller','relay','peer'): errors.append('Unsupported backup role.')
    host=data['backup_host']
    try:
        address=ipaddress.ip_address(host)
        valid=address.version==4 and not any((address.is_loopback,address.is_unspecified,address.is_multicast,address.is_link_local,address.is_reserved))
    except (ValueError,TypeError): valid=hostname(host)
    if not valid: errors.append('Provide a remote IPv4 or DNS backup host.')
    if type(data['backup_port']) is not int or not 1<=data['backup_port']<=65535: errors.append('Invalid backup SSH port.')
    if not valid_host_key(data['backup_host_key']): errors.append('Provide the independently verified Ed25519 SSH host public key.')
    return errors


def repository(data):
    if validate(data): raise ValueError('Invalid backup profile')
    return 'sftp:rdc-backup@'+data['backup_host']+':/data/'+data['institution_id']+'-'+data['node_name']


@dataclass(frozen=True)
class Resources:
    paths: tuple[str,...]
    services: tuple[str,...]


def resources(owner):
    if isinstance(owner,dict) and 'applications' in owner:
        from backup_scope import validate as validate_scope
        validate_scope(owner)
    catalogue={'controller':(('etc/headscale','var/lib/headscale'),('headscale',)),
               'relay':(('etc/sc-derp','var/lib/sc-derp'),('sc-derp',)),
               'peer':(('var/lib/tailscale',),('tailscaled',))}
    if not isinstance(owner,dict) or owner.get('role') not in catalogue: raise ValueError('Unknown ownership role')
    paths,services=catalogue[owner['role']]
    paths+=('etc/server-connectivity-profile.json',)
    if 'applications' in owner:
        from backup_scope import package
        if package(owner['applications'])=='nextcloud':
            paths+=('etc/rdc-nextcloud','var/lib/rdc-nextcloud')
            services=('rdc-nextcloud-cron.timer','rdc-nextcloud-proxy','rdc-nextcloud','rdc-nextcloud-postgres')+services
        else:
            paths+=('etc/rdc-services','var/lib/rdc-services')
            services=('rdc-service-proxy','rdc-element','rdc-synapse','rdc-postgres')+services
    if owner.get('tls_mode')=='managed-acme': paths+=('etc/rdc-tls','etc/letsencrypt')
    elif 'tls_mode' in owner: raise ValueError('Unknown certificate ownership mode')
    return Resources(paths,services)


def binary_paths(owner):
    catalogue={'controller':('usr/bin/headscale',),'relay':('usr/local/bin/sc-derper',),
               'peer':('usr/local/bin/tailscale','usr/local/bin/tailscaled')}
    resources(owner)
    paths=catalogue[owner['role']]
    if 'applications' in owner:
        from backup_scope import package
        if package(owner['applications'])=='nextcloud':
            paths+=tuple('usr/local/lib/rdc-nextcloud/'+n for n in ('nextcloud_runtime.py','nextcloud_cron.py','nextcloud_images.json','service_runtime.py','nextcloud_regional.py','service_regional.py','regional_http.py'))
            paths+=tuple('etc/systemd/system/'+n for n in ('rdc-nextcloud.service','rdc-nextcloud-postgres.service','rdc-nextcloud-proxy.service','rdc-nextcloud-cron.service','rdc-nextcloud-cron.timer'))
        else:paths+=('usr/local/lib/rdc-services/service_runtime.py','usr/local/lib/rdc-services/service_images.json','usr/local/lib/rdc-services/service_regional.py')
    return paths

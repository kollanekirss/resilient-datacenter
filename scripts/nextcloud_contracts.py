"""Fixed Nextcloud identity and inputs; independent of the Matrix package."""
import json
from pathlib import Path
import re
from profile_config import _safe_values,_identifier
from service_contracts import network_manifest,validate_network
from validate_inventory import hostname
from application_access import access_profile

FIELDS={'kind','schema_version','institution_id','node_name','nextcloud_hostname','tls_mode','tls_certificate','tls_private_key'}
NAMESPACES={'nextcloud':'docker.io/library/nextcloud','postgres':'docker.io/library/postgres','proxy':'docker.io/library/caddy'}


def image_pins():
    data=json.loads(Path(__file__).with_name('nextcloud_images.json').read_text())
    if set(data)!={'schema_version','components'} or data['schema_version']!=1 or set(data['components'])!=set(NAMESPACES):raise ValueError('Unknown Nextcloud component catalogue')
    for name,item in data['components'].items():
        if (set(item)!={'version','image','platform','config_digest'} or item['platform']!='linux/amd64' or
            not re.fullmatch(re.escape(NAMESPACES[name])+r'@sha256:[a-f0-9]{64}',item['image']) or
            not re.fullmatch(r'sha256:[a-f0-9]{64}',item['config_digest']) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?',item['version'])):
            raise ValueError('Nextcloud images require fixed reviewed upstream identities')
    return data['components']


def validate(data):
    if not isinstance(data,dict) or set(data) not in (FIELDS,FIELDS|{'access'}) or not _safe_values(data):return ['Use only the documented Nextcloud fields; secrets and execution overrides are forbidden.']
    errors=[]
    if 'access' in data:
        from application_access import validate_access
        try:validate_access(data['access'])
        except ValueError:errors.append('Invalid portable access identity.')
    if data['kind']!='nextcloud-services' or type(data['schema_version']) is not int or data['schema_version']!=1:errors.append('Unsupported Nextcloud profile.')
    if not all(_identifier(data[k]) for k in ('institution_id','node_name')):errors.append('Invalid institution or node identity.')
    if not hostname(data['nextcloud_hostname']):errors.append('Provide the permanent Nextcloud DNS name.')
    if data['tls_mode']!='supplied':errors.append('Use the supported certificate-file interface.')
    for key in ('tls_certificate','tls_private_key'):
        if not isinstance(data[key],str) or not Path(data[key]).is_absolute():errors.append('Certificate paths must be absolute on the intended server.')
    if data['tls_certificate']==data['tls_private_key']:errors.append('Use separate certificate and private-key files.')
    return errors


def ownership(profile,network):
    if validate(profile):raise ValueError('Invalid Nextcloud profile')
    validate_network(profile,network)
    if any(profile[k]!=network[k] for k in ('institution_id','node_name')):raise ValueError('File-service identity differs from this enrolled node')
    return {'schema_version':1,'role':'services','institution_id':profile['institution_id'],'node_name':profile['node_name'],
            'network':network,'packages':['nextcloud'],'nextcloud_hostname':profile['nextcloud_hostname'],'tls_mode':'supplied',
            'images':{k:v['image'] for k,v in image_pins().items()}}


def from_owner(owner):
    return {**access_profile(owner), 'kind':'nextcloud-services','schema_version':1,**{k:owner.get(k) for k in ('institution_id','node_name','nextcloud_hostname','tls_mode')},
            'tls_certificate':'/etc/rdc-nextcloud-tls/active/tls.crt','tls_private_key':'/etc/rdc-nextcloud-tls/active/tls.key'}

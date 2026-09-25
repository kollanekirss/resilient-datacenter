"""Strict Matrix package identity; no executable user configuration or image overrides."""
import json
from pathlib import Path
import re
from profile_config import _safe_values,_identifier
from setup_contracts import validate_local_manifest,local_ownership
from validate_inventory import hostname

FIELDS={'kind','schema_version','institution_id','node_name','matrix_hostname','element_hostname','tls_mode','tls_certificate','tls_private_key'}
NAMESPACES={'synapse':'ghcr.io/element-hq/synapse','element':'docker.io/vectorim/element-web',
            'postgres':'docker.io/library/postgres','proxy':'docker.io/library/caddy'}


def image_pins():
    data=json.loads(Path(__file__).with_name('service_images.json').read_text())
    if set(data)!={'schema_version','components'} or data['schema_version']!=1 or set(data['components'])!=set(NAMESPACES):
        raise ValueError('Unknown application component catalogue')
    for name,item in data['components'].items():
        if (set(item)!={'version','image','platform','config_digest'} or item['platform']!='linux/amd64' or
            not re.fullmatch(re.escape(NAMESPACES[name])+r'@sha256:[a-f0-9]{64}',item['image']) or
            not re.fullmatch(r'sha256:[a-f0-9]{64}',item['config_digest']) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?',item['version'])):
            raise ValueError('Application images require reviewed fixed upstream digests')
    return data['components']


def validate(data):
    if not isinstance(data,dict) or set(data) not in (FIELDS,FIELDS|{'access'}) or not _safe_values(data): return ['Use only the documented Matrix profile fields; commands, image overrides and secrets are forbidden.']
    errors=[]
    if 'access' in data:
        from application_access import validate_access
        try:validate_access(data['access'])
        except ValueError:errors.append('Invalid portable access identity.')
    if data['kind']!='matrix-services' or type(data['schema_version']) is not int or data['schema_version']!=1: errors.append('Unsupported service profile.')
    if not all(_identifier(data[k]) for k in ('institution_id','node_name')): errors.append('Invalid institution or node name.')
    if not all(hostname(data[k]) for k in ('matrix_hostname','element_hostname')): errors.append('Provide actual Matrix and Element DNS names.')
    if data['matrix_hostname']==data['element_hostname']: errors.append('Matrix and Element require separate browser origins.')
    if data['tls_mode']!='supplied': errors.append('Use the supplied certificate-file interface; the optional service issuer can provide and renew those files.')
    for name in ('tls_certificate','tls_private_key'):
        if not isinstance(data[name],str) or not Path(data[name]).is_absolute(): errors.append('TLS input paths must be absolute local paths on the service node.')
    if data['tls_certificate']==data['tls_private_key']: errors.append('Certificate and private key must be separate files.')
    return errors


def network_manifest(network):
    if not isinstance(network,dict): raise ValueError('Service installation needs an owned local node')
    manifest={'kind':'local-node','schema_version':1,'institution_id':network.get('institution_id'),'node_name':network.get('node_name'),
              'headscale_hostname':network.get('controller_hostname'),'node_tag':network.get('node_tag')}
    if validate_local_manifest(manifest) or local_ownership(manifest)!=network: raise ValueError('Service installation requires the current local-node ownership contract')
    return manifest


def ownership(profile,network):
    if validate(profile): raise ValueError('Invalid Matrix profile')
    validate_network(profile,network)
    if any(profile[k]!=network[k] for k in ('institution_id','node_name')): raise ValueError('Service profile differs from the enrolled node identity')
    return {'schema_version':1,'role':'services','institution_id':profile['institution_id'],'node_name':profile['node_name'],
            'network':network,'packages':['matrix'],'matrix_hostname':profile['matrix_hostname'],'element_hostname':profile['element_hostname'],
            'tls_mode':profile['tls_mode'],'images':{k:v['image'] for k,v in image_pins().items()}}


def same_installation(profile,network,existing):
    try:return ownership(profile,network)==existing
    except ValueError:return False


def validate_network(profile,network):
    if 'access' in profile:
        from application_access import portable_owner
        if network!=portable_owner(profile):raise ValueError('Portable access differs from installed network identity')
    else:network_manifest(network)

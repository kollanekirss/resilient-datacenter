"""Explicit application backup scope, separate from immutable network ownership."""
import json
from pathlib import Path
from service_contracts import ownership


def network_owner(owner):
    if not isinstance(owner,dict): raise ValueError('Invalid backup identity')
    return {k:v for k,v in owner.items() if k!='applications'}


def application_profile(application):
    return {'kind':'matrix-services','schema_version':1,
            **{k:application.get(k) for k in ('institution_id','node_name','matrix_hostname','element_hostname','tls_mode')},
            'tls_certificate':'/etc/rdc-service-tls/active/tls.crt','tls_private_key':'/etc/rdc-service-tls/active/tls.key'}


def include(network,application):
    if not isinstance(application,dict) or ownership(application_profile(application),network)!=application:
        raise ValueError('Application backup scope differs from the supported installation')
    return dict(network,applications=application)


def validate(owner):
    if not isinstance(owner,dict): raise ValueError('Invalid backup scope')
    if 'applications' in owner and include(network_owner(owner),owner['applications'])!=owner:
        raise ValueError('Invalid application backup scope')


def verify_installed(root,owner):
    validate(owner);root=Path(root)
    if json.loads((root/'etc/server-connectivity-profile.json').read_text())!=network_owner(owner):
        raise ValueError('Backup network identity changed')
    if 'applications' in owner:
        if json.loads((root/'etc/rdc-services/ownership.json').read_text())!=owner['applications']:
            raise ValueError('Backup application identity changed')


def tag(owner):
    validate(owner)
    return 'matrix' if 'applications' in owner else 'network'

"""Explicit application backup scope, separate from immutable network ownership."""
import json
from pathlib import Path
from service_contracts import ownership


def network_owner(owner):
    if not isinstance(owner,dict): raise ValueError('Invalid backup identity')
    return {k:v for k,v in owner.items() if k!='applications'}


def package(application):
    if not isinstance(application,dict) or application.get('packages') not in (['matrix'],['nextcloud']):raise ValueError('Unknown application backup package')
    return application['packages'][0]


def application_profile(application):
    if package(application)=='nextcloud':
        from nextcloud_contracts import from_owner
        return from_owner(application)
    return {'kind':'matrix-services','schema_version':1,
            **{k:application.get(k) for k in ('institution_id','node_name','matrix_hostname','element_hostname','tls_mode')},
            'tls_certificate':'/etc/rdc-service-tls/active/tls.crt','tls_private_key':'/etc/rdc-service-tls/active/tls.key'}


def include(network,application):
    if package(application)=='nextcloud':
        from nextcloud_contracts import ownership as expected_owner
    else:expected_owner=ownership
    if expected_owner(application_profile(application),network)!=application:
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
        base='etc/rdc-nextcloud' if package(owner['applications'])=='nextcloud' else 'etc/rdc-services'
        if json.loads((root/base/'ownership.json').read_text())!=owner['applications']:
            raise ValueError('Backup application identity changed')


def tag(owner):
    validate(owner)
    return package(owner['applications']) if 'applications' in owner else 'network'


def application_runtime(application):
    if package(application)=='nextcloud':
        import nextcloud_runtime
        return nextcloud_runtime
    import service_runtime
    return service_runtime


def application_backup(application):
    if package(application)=='nextcloud':
        import nextcloud_backup
        return nextcloud_backup
    import service_backup
    return service_backup


def installed_application(root=Path('/')):
    markers=[Path(root)/base/'ownership.json' for base in ('etc/rdc-services','etc/rdc-nextcloud')]
    present=[p for p in markers if p.exists() or p.is_symlink()]
    if len(present)>1:raise ValueError('Multiple application packages on one node require an unsupported scope migration')
    if not present:return None
    from service_runtime import root_json
    result=root_json(present[0]);package(result)
    return result

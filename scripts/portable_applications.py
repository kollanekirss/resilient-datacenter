"""Plan-derived portable application profiles. No infrastructure mutation."""
from portable_plan import validate
from portable_network import fingerprint


def profiles(plan):
    plan=validate(plan)
    result={}
    for role in ('chat','files'):
        profile={'kind':'matrix-services' if role=='chat' else 'nextcloud-services',
                 'schema_version':1,'institution_id':plan['site'],'node_name':role,
                 'tls_mode':'supplied','tls_certificate':'/etc/rdc-prepared/'+role+'.crt',
                 'tls_private_key':'/etc/rdc-prepared/'+role+'.key',
                 'access':{'mode':'portable-lan','site':plan['site'],'site_sha256':fingerprint(plan),
                           'backend_address':plan['vms'][role]['address'],
                           'frontend_address':plan['vms']['nginx']['address']}}
        if role=='chat':profile.update(matrix_hostname=plan['domains']['chat'],element_hostname=plan['domains']['element'])
        else:profile['nextcloud_hostname']=plan['domains']['files']
        result[role]=profile
    return result

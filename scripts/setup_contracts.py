"""Contracts for infrastructure-only setup and non-executable local manifests."""
from profile_config import _validate_managed_inventory, _safe_values, _identifier, RESERVED
from validate_inventory import hostname

MANIFEST_FIELDS={'kind','schema_version','institution_id','node_name','headscale_hostname','node_tag'}

def validate_local_manifest(data: dict) -> list[str]:
    if not isinstance(data,dict) or set(data)!=MANIFEST_FIELDS or not _safe_values(data):
        return ['Local manifest must contain only the six documented fields; commands and inventory settings are forbidden']
    errors=[]
    if data['kind']!='local-node' or type(data['schema_version']) is not int or data['schema_version']!=1:
        errors.append('Unsupported local manifest kind/version')
    for field in ['institution_id','node_name']:
        if not _identifier(data[field]) or data[field] in RESERVED: errors.append('Invalid '+field)
    tag=data['node_tag']
    if not isinstance(tag,str) or not tag.startswith('tag:') or not _identifier(tag[4:]): errors.append('Invalid node_tag')
    if not hostname(data['headscale_hostname']): errors.append('Invalid or placeholder controller hostname')
    return errors


def validate_infrastructure(data: dict, *, check_files: bool = True) -> list[str]:
    errors=_validate_managed_inventory(data,check_files=check_files,infrastructure_only=True)
    if errors: return errors
    v=data['all']['vars']; groups=data['all']['children']; nodes=v['enrollment_nodes']
    if not isinstance(nodes,list) or not nodes: return ['enrollment_nodes must contain at least one node request']
    names=[]; tags=[]; managed={n for section in groups.values() for n in section['hosts']}
    for node in nodes:
        if not isinstance(node,dict) or set(node)!={'name','node_tag'}:
            errors.append('Each enrollment request requires only name and node_tag'); continue
        manifest={'kind':'local-node','schema_version':1,'institution_id':v['institution_id'],'headscale_hostname':v['headscale_hostname'],'node_name':node['name'],'node_tag':node['node_tag']}
        problems=validate_local_manifest(manifest)
        errors.extend(problems)
        if not problems:
            names.append(node['name']); tags.append(node['node_tag'])
    if len(names)!=len(set(names)) or len(tags)!=len(set(tags)) or set(names)&managed:
        errors.append('Planned node names/tags must be unique and distinct from managed infrastructure names')
    return errors


def normalize_infrastructure(data: dict) -> dict:
    if validate_infrastructure(data,check_files=False): raise ValueError('Invalid infrastructure input')
    v=data['all']['vars']; groups=data['all']['children']
    roles={name:group for group,section in groups.items() for name in section['hosts']}
    return {'mode':'independent','institution_id':v['institution_id'],'controller_hostname':v['headscale_hostname'],
            'controller_host':next(iter(groups['controller']['hosts'])),'relay_host':next(iter(groups['relay']['hosts'])),
            'roles':roles,'peer_names':[],'test_pair':[],
            'policy':{'tagOwners':{n['node_tag']:[v['enrollment_admin']+'@'] for n in v['enrollment_nodes']},'grants':[]},
            'enrollment_requests':v['enrollment_nodes'],
            'ownership':{name:{'schema_version':v['schema_version'],**({'tls_mode':'managed-acme','certificate_hostname':v['headscale_hostname' if role=='controller' else 'derp_hostname']} if v['schema_version']==3 else {}),'deployment_mode':'independent','institution_id':v['institution_id'],'role':role,'controller_hostname':v['headscale_hostname']} for name,role in roles.items()}}


def local_ownership(manifest: dict) -> dict:
    if validate_local_manifest(manifest): raise ValueError('Invalid local manifest')
    return {'schema_version':2,'deployment_mode':'join','institution_id':manifest['institution_id'],'role':'peer','controller_hostname':manifest['headscale_hostname'],'node_name':manifest['node_name'],'node_tag':manifest['node_tag'],'install_method':'local'}

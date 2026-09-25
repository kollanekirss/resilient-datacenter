"""Pure, strict configuration contract for opt-in versioned deployment profiles."""
import hashlib
import ipaddress
import re
from pathlib import Path
import yaml
from validate_inventory import hostname
from validate_tls import validate_certificate

BASE_VARS = {'schema_version', 'deployment_mode', 'institution_id', 'headscale_hostname'}
INDEPENDENT_VARS = {'derp_hostname', 'enrollment_admin', 'derper_artifact', 'derper_sha256'}
HOST_BASE = {'ansible_host', 'ansible_user', 'ansible_port', 'ansible_connection'}
TLS_FIELDS = {'tls_certificate', 'tls_private_key'}
TEST_FIELDS = TLS_FIELDS | {'test_dns_name'}
RESERVED = {'all', 'ungrouped', 'localhost', 'controller', 'relay', 'peers', 'profile-test-peers'}
IDENTIFIER = re.compile(r'[a-z][a-z0-9-]{0,62}')

class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('YAML aliases are not supported')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError('Inventory requires unique string keys')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_profile(path: str) -> dict:
    try:
        with Path(path).open() as stream:
            return yaml.load(stream, Loader=StrictLoader)
    except Exception:
        raise ValueError('Cannot read profile: check file, YAML structure and unique keys; values omitted') from None


def _identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _safe_values(value, depth=0):
    if depth > 15:
        return False
    if isinstance(value, str):
        return not any(token in value for token in ('{{', '{%', '{#', '\x00', '\r', '\n'))
    if isinstance(value, dict):
        return all(isinstance(k, str) and _safe_values(k, depth+1) and _safe_values(v, depth+1) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe_values(v, depth+1) for v in value)
    return value is None or type(value) in (int, bool)


def validate_profile(data: dict, *, check_files: bool = True) -> list[str]:
    return _validate_managed_inventory(data, check_files=check_files)


def _validate_managed_inventory(data: dict, *, check_files: bool, infrastructure_only: bool = False) -> list[str]:
    errors = []
    if not isinstance(data, dict) or set(data) != {'all'} or not _safe_values(data):
        return ['Expected a plain static inventory; expressions, aliases and unsafe values are not supported']
    root = data['all']
    if not isinstance(root, dict) or set(root) != {'vars', 'children'}:
        return ['all must contain only vars and children']
    v, groups = root['vars'], root['children']
    if not isinstance(v, dict) or not isinstance(groups, dict):
        return ['vars and children must be mappings']
    mode = v.get('deployment_mode')
    if mode not in ('independent', 'join'):
        return ['deployment_mode must be independent or join']
    if infrastructure_only and mode != 'independent':
        return ['Infrastructure setup requires independent mode']
    required = BASE_VARS | (INDEPENDENT_VARS if mode == 'independent' else set())
    managed_acme=infrastructure_only and type(v.get('schema_version')) is int and v['schema_version']==3
    if managed_acme:
        required |= {'tls_mode','acme_email','acme_terms_accepted'}
        if v.get('tls_mode')!='managed-acme': errors.append('Schema 3 requires explicit managed-acme certificate mode')
        if v.get('acme_terms_accepted') is not True: errors.append('Review and explicitly accept the ACME issuer terms before deployment')
        email=v.get('acme_email')
        if not isinstance(email,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._+%-]{0,63}@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,63}',email):
            errors.append('A valid ACME account email is required')
    if infrastructure_only:
        required |= {'enrollment_nodes'}
    if not required <= set(v) or set(v) - required - ({'service_access'} if infrastructure_only else {'connectivity_test'}):
        errors.append('Missing or unsupported profile variables; join cannot contain controller/relay management settings')
    if type(v.get('schema_version')) is not int or v['schema_version'] != (3 if managed_acme else 2 if infrastructure_only else 1):
        errors.append('Unsupported inventory schema_version for this entry point')
    if not _identifier(v.get('institution_id')):
        errors.append('Invalid institution_id')
    if not hostname(v.get('headscale_hostname')):
        errors.append('Invalid or placeholder headscale_hostname')
    expected_groups = {'peers', 'controller', 'relay'} if mode == 'independent' else {'peers'}
    if infrastructure_only:
        expected_groups = {'controller', 'relay'}
    if set(groups) != expected_groups:
        errors.append('Incorrect groups for deployment_mode; join permits peers only')
    test = v.get('connectivity_test')
    pair = []
    paths = []
    if 'connectivity_test' in v:
        if not isinstance(test, dict) or set(test) != {'nodes', 'ca_certificate'}:
            errors.append('connectivity_test requires only nodes and ca_certificate')
        else:
            nodes = test['nodes']
            if not isinstance(nodes, list) or len(nodes) != 2 or not all(_identifier(n) for n in nodes) or len(set(nodes)) != 2:
                errors.append('connectivity_test requires exactly two distinct node names')
            else:
                pair = nodes
            paths.append(('test CA', test['ca_certificate']))
    if mode == 'independent':
        if not hostname(v.get('derp_hostname')) or v.get('derp_hostname') == v.get('headscale_hostname'):
            errors.append('derp_hostname must be a distinct non-placeholder hostname')
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', str(v.get('enrollment_admin', ''))):
            errors.append('Invalid enrollment_admin')
        if not isinstance(v.get('derper_sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', v['derper_sha256']):
            errors.append('Invalid derper_sha256')
        paths.append(('DERP artifact', v.get('derper_artifact')))
    names, addresses, tags, peers, certificates = [], [], [], set(), []
    for group in expected_groups:
        section = groups.get(group)
        if not isinstance(section, dict) or set(section) != {'hosts'} or not isinstance(section['hosts'], dict):
            errors.append('Each managed group requires a hosts mapping')
            continue
        hosts = section['hosts']
        if not hosts or (group != 'peers' and len(hosts) != 1):
            errors.append('Require one controller/relay and one or more peers')
        for name, h in hosts.items():
            if not _identifier(name) or name in RESERVED:
                errors.append('Invalid or reserved inventory node name')
            names.append(name)
            if not isinstance(h, dict):
                errors.append('Host must be a mapping')
                continue
            required_host = {'ansible_host', 'ansible_user'} | ({'node_tag'} if group == 'peers' else set() if managed_acme else TLS_FIELDS)
            allowed_host = HOST_BASE | ({'node_tag'} if group == 'peers' else set() if managed_acme else TLS_FIELDS)
            if name in pair and group == 'peers':
                required_host |= TEST_FIELDS
                allowed_host |= TEST_FIELDS
            if not required_host <= set(h) or set(h) - allowed_host:
                errors.append('Missing or unsupported host fields; peer TLS is only for selected test nodes')
            try:
                if not isinstance(h.get('ansible_host'), str):
                    raise ValueError()
                address = ipaddress.ip_address(h['ansible_host'])
                if address.version != 4 or not address.is_global:
                    raise ValueError()
                addresses.append(str(address))
            except (ValueError, TypeError):
                errors.append('Require a public IPv4 management address')
            if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', str(h.get('ansible_user', ''))):
                errors.append('Invalid SSH user')
            port = h.get('ansible_port', 22)
            if type(port) is not int or not 1 <= port <= 65535:
                errors.append('Invalid SSH port')
            if h.get('ansible_connection', 'ssh') != 'ssh':
                errors.append('Only SSH management is supported by these profiles')
            if group == 'peers':
                peers.add(name)
                tag = h.get('node_tag')
                if not isinstance(tag, str) or not tag.startswith('tag:') or not _identifier(tag[4:]):
                    errors.append('Invalid node_tag')
                else:
                    tags.append(tag)
            if (group != 'peers' or name in pair) and not managed_acme:
                for key in TLS_FIELDS:
                    paths.append(('TLS file', h.get(key)))
                dns = h.get('test_dns_name') if group == 'peers' else v.get('headscale_hostname' if group == 'controller' else 'derp_hostname')
                if not hostname(dns):
                    errors.append('Invalid certificate hostname')
                certificates.append((h, dns, test.get('ca_certificate') if group == 'peers' and isinstance(test, dict) else None))
    if len(names) != len(set(names)) or len(addresses) != len(set(addresses)) or len(tags) != len(set(tags)):
        errors.append('Node names, management addresses and peer tags must be distinct')
    if set(pair) - peers:
        errors.append('Test pair must name managed peers')
    for label, path in paths:
        if not isinstance(path, str) or not Path(path).is_absolute():
            errors.append(label + ' requires an absolute local path')
        elif check_files and not Path(path).is_file():
            errors.append(label + ' is missing or not a file')
    if check_files and not errors:
        try:
            if mode == 'independent':
                with Path(v['derper_artifact']).open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                if digest != v['derper_sha256']:
                    errors.append('DERP artifact sha256 mismatch')
            for h, dns, ca in certificates:
                errors.extend(validate_certificate(h['tls_certificate'], h['tls_private_key'], dns, ca))
        except Exception:
            errors.append('Could not verify deployment files; values omitted')
    return errors


def normalize_profile(data: dict) -> dict:
    if validate_profile(data, check_files=False):
        raise ValueError('Invalid profile; validate and correct inputs before normalization')
    v, g = data['all']['vars'], data['all']['children']
    independent = v['deployment_mode'] == 'independent'
    peers = g['peers']['hosts']
    pair = v.get('connectivity_test', {}).get('nodes', [])
    grants = []
    if pair:
        a, b = (peers[n]['node_tag'] for n in pair)
        grants = [{'src':[a], 'dst':[b], 'ip':['tcp:8443']}, {'src':[b], 'dst':[a], 'ip':['tcp:8443']}]
    roles = {name: ('peer' if group == 'peers' else group) for group, section in g.items() for name in section['hosts']}
    return {
        'mode': v['deployment_mode'], 'institution_id': v['institution_id'],
        'controller_hostname': v['headscale_hostname'],
        'controller_host': next(iter(g['controller']['hosts'])) if independent else None,
        'relay_host': next(iter(g['relay']['hosts'])) if independent else None,
        'peer_names': list(peers), 'roles': roles, 'test_pair': pair,
        'policy': {'tagOwners': {h['node_tag']:[v['enrollment_admin']+'@'] for h in peers.values()}, 'grants':grants} if independent else None,
        'requested_grants': grants,
        'enrollment_requests': [{'name': n, 'tag': h['node_tag']} for n,h in peers.items()],
    }


def expected_ownership(profile: dict, host_name: str) -> dict:
    if host_name not in profile['roles']:
        raise ValueError('Node is not managed by this profile')
    return {'schema_version':1, 'deployment_mode':profile['mode'], 'institution_id':profile['institution_id'], 'role':profile['roles'][host_name], 'controller_hostname':profile['controller_hostname']}

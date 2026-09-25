#!/usr/bin/env python3
"""Validate the deliberately small, static four-host lab inventory; never connect."""
import argparse
import hashlib
import ipaddress
import re
from pathlib import Path
import yaml

GROUPS = {'controller': ['control-01'], 'relay': ['relay-01'], 'peers': ['server-a', 'server-b']}
TAGS = {'server-a': 'tag:institution-a-server', 'server-b': 'tag:institution-b-server'}
COMMON = {'ansible_host', 'ansible_user', 'ansible_port', 'ansible_connection', 'tls_certificate', 'tls_private_key'}
VARS = {'headscale_hostname', 'derp_hostname', 'enrollment_admin', 'derper_artifact', 'derper_sha256', 'test_ca_certificate'}

def hostname(value):
    return isinstance(value, str) and len(value) < 254 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')) and '.' in value and not any(value == s or value.endswith('.'+s) for s in ['example.com', 'example.net', 'example.org', 'invalid'])

def validate_inventory(data, check_files=True):
    errors=[]
    if not isinstance(data, dict) or set(data) != {'all'} or not isinstance(data.get('all'), dict):
        return ['Expected a static inventory with an all mapping']
    root=data['all']; variables=root.get('vars', {}); groups=root.get('children', {})
    if set(root) != {'vars', 'children'} or not isinstance(variables, dict) or not isinstance(groups, dict):
        return ['all must contain only vars and children mappings']
    if set(variables) != VARS:
        errors.append('Unexpected or missing inventory variables; credentials and arbitrary Ansible overrides are not accepted')
    for name in ['headscale_hostname', 'derp_hostname']:
        if not hostname(variables.get(name)): errors.append(name+' must be a non-placeholder hostname')
    if variables.get('headscale_hostname') == variables.get('derp_hostname'): errors.append('Control and relay hostname must be distinct')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', str(variables.get('enrollment_admin', ''))): errors.append('Invalid enrollment_admin')
    digest=variables.get('derper_sha256', '')
    if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest): errors.append('Invalid derper_sha256')
    paths=[('derper_artifact', variables.get('derper_artifact')), ('test_ca_certificate', variables.get('test_ca_certificate'))]
    seen=[]; certificate_sets=[]
    if set(groups) != set(GROUPS): errors.append('Expected controller, relay and peers groups')
    for group,names in GROUPS.items():
        entry=groups.get(group,{})
        if not isinstance(entry,dict) or set(entry) != {'hosts'} or not isinstance(entry.get('hosts'),dict):
            errors.append(group+' requires hosts'); continue
        hosts=entry['hosts']
        if set(hosts) != set(names): errors.append(group+' has incorrect host names/count')
        for name,host in hosts.items():
            if not isinstance(host,dict): errors.append(group+' host must be a mapping'); continue
            allowed=COMMON | ({'node_tag','peer_name','test_dns_name'} if group=='peers' else set())
            if set(host)-allowed: errors.append(group+' contains unsupported host options')
            if host.get('ansible_connection','ssh') != 'ssh': errors.append('Only ssh connection is allowed')
            try:
                address=ipaddress.ip_address(host.get('ansible_host',''))
                if address.version != 4 or not address.is_global: raise ValueError()
                seen.append(str(address))
            except ValueError: errors.append(group+' requires a public IPv4 management address')
            if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',str(host.get('ansible_user',''))): errors.append(group+' requires a valid ansible_user')
            port=host.get('ansible_port',22)
            if not isinstance(port,int) or isinstance(port,bool) or not 1<=port<=65535: errors.append(group+' has invalid SSH port')
            for key in ['tls_certificate','tls_private_key']: paths.append((group+' '+key,host.get(key)))
            dns=variables.get('headscale_hostname' if group=='controller' else 'derp_hostname')
            if group=='peers':
                dns=host.get('test_dns_name')
                if not hostname(dns): errors.append('Invalid test hostname')
                if host.get('node_tag') != TAGS.get(name): errors.append('Incorrect peer tag')
                if host.get('peer_name') != {'server-a':'server-b','server-b':'server-a'}.get(name): errors.append('Incorrect peer_name')
            certificate_sets.append((group,host,dns))
    if len(seen)!=len(set(seen)): errors.append('All four management addresses must be distinct')
    for label,path in paths:
        if not isinstance(path,str) or not Path(path).is_absolute() or any(c in path for c in '\n\r\x00'):
            errors.append(label+' requires an absolute local file path')
        elif check_files and not Path(path).is_file(): errors.append(label+' file is missing')
    if check_files and not errors:
        if hashlib.sha256(Path(variables['derper_artifact']).read_bytes()).hexdigest()!=digest: errors.append('DERP artifact sha256 does not match')
        from validate_tls import validate_certificate
        for group,host,dns in certificate_sets:
            errors.extend(group+': '+e for e in validate_certificate(host['tls_certificate'],host['tls_private_key'],dns,variables['test_ca_certificate'] if group=='peers' else None))
    return errors

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory'); parser.add_argument('--structure-only',action='store_true')
    args=parser.parse_args()
    try:
        data=yaml.safe_load(Path(args.inventory).read_text())
        errors=validate_inventory(data,not args.structure_only)
    except Exception:
        errors=['Could not read or validate inventory; check YAML, files and local dependencies (values omitted)']
    for error in errors: print('ERROR: '+error)
    if not errors: print('Inventory checks passed'+(' (structure only)' if args.structure_only else ''))
    return bool(errors)

if __name__=='__main__': raise SystemExit(main())

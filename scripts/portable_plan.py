"""Pure portable-site planning. No API calls, commands, discovery or writes."""
import copy
import ipaddress
import json
import re
from urllib.parse import urlsplit

ZONES = ('management', 'staff', 'frontend', 'applications', 'partner')
MODULES = {'edge': ('management', 3072), 'dns': ('frontend', 1024),
           'nginx': ('frontend', 1024), 'chat': ('applications', 4096),
           'files': ('applications', 4096), 'partner': ('partner', 2048)}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()),
            'Unexpected or missing fields. Use the documented schema; do not include credentials.')


def name(value):
    return type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value) is not None


def domain(value):
    return (type(value) is str and len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in value.split('.'))
            and not value.replace('.', '').isdigit())


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate(plan):
    fields(plan, 'schema_version site recovery_site proxmox networks vms domains offline_days certificate_margin_days')
    require(type(plan['schema_version']) is int and plan['schema_version'] == 1, 'Unsupported site-plan schema.')
    require(name(plan['site']) and name(plan['recovery_site']) and plan['site'] != plan['recovery_site'],
            'Use distinct site and recovery-site identifiers; physical independence still needs verification.')
    require(integer(plan['offline_days'], 1, 3650) and integer(plan['certificate_margin_days'], 1, 365),
            'Specify an offline duration of 1–3650 days and a certificate margin of 1–365 days.')
    p = plan['proxmox']
    fields(p, 'endpoint node storage wan_bridge')
    try:
        endpoint = urlsplit(p['endpoint'])
        endpoint_ok = (type(p['endpoint']) is str and not any(c.isspace() for c in p['endpoint']) and endpoint.scheme == 'https' and domain(endpoint.hostname)
                       and endpoint.port in (None, 443, 8006) and not endpoint.username
                       and not endpoint.password and endpoint.path in ('', '/')
                       and not endpoint.query and not endpoint.fragment)
    except (ValueError, TypeError, AttributeError):
        endpoint_ok = False
    require(endpoint_ok, 'Use a credential-free HTTPS Proxmox hostname, optionally on port 8006.')
    require(all(name(p[k]) for k in ('node', 'storage', 'wan_bridge')), 'Invalid Proxmox resource identifier.')
    fields(plan['networks'], ' '.join(ZONES))
    nets, bridges = {}, {p['wan_bridge']}
    for zone in ZONES:
        net = plan['networks'][zone]
        fields(net, 'cidr bridge gateway')
        require(type(net['cidr']) is str and type(net['gateway']) is str, 'Network fields must be strings.')
        try:
            subnet = ipaddress.ip_network(net['cidr'], strict=True)
            gateway = ipaddress.ip_address(net['gateway'])
        except (ValueError, TypeError):
            raise ValueError('Networks require canonical IPv4 CIDRs and usable gateway addresses.') from None
        require(subnet.version == 4 and 16 <= subnet.prefixlen <= 28
                and any(subnet.subnet_of(block) for block in PRIVATE),
                'Use RFC1918 IPv4 subnets between /16 and /28; overlay ranges are reserved.')
        require(gateway in subnet and gateway not in (subnet.network_address, subnet.broadcast_address),
                'Gateway must be a usable address in its subnet.')
        require(not any(subnet.overlaps(previous) for previous in nets.values()), 'Site subnets overlap.')
        require(name(net['bridge']) and net['bridge'] not in bridges, 'Each zone and WAN needs a distinct bridge.')
        nets[zone] = subnet
        bridges.add(net['bridge'])
    fields(plan['vms'], ' '.join(MODULES))
    ids, addresses = set(), {n['gateway'] for n in plan['networks'].values()}
    for role, (zone, minimum_memory) in MODULES.items():
        vm = plan['vms'][role]
        fields(vm, 'id cpu memory_mib disk_gib address')
        require(integer(vm['id'], 100, 999999999) and vm['id'] not in ids, 'VM IDs must be unique integers from 100 to 999999999.')
        require(integer(vm['cpu'], 1, 256) and integer(vm['memory_mib'], minimum_memory, 1048576)
                and integer(vm['disk_gib'], 20, 1048576), 'VM resources are below planning minimums or outside supported bounds.')
        try:
            address = ipaddress.ip_address(vm['address'])
        except (ValueError, TypeError):
            raise ValueError('VM address must be a usable IPv4 address.') from None
        require(type(vm['address']) is str and address.version == 4 and address in nets[zone]
                and address not in (nets[zone].network_address, nets[zone].broadcast_address)
                and vm['address'] not in addresses, 'VM addresses must be unique usable addresses in their assigned zone, excluding gateways.')
        ids.add(vm['id']); addresses.add(vm['address'])
    fields(plan['domains'], 'chat element files')
    require(all(domain(d) for d in plan['domains'].values()) and len(set(plan['domains'].values())) == 3,
            'Use three distinct lowercase service hostnames, without schemes or paths.')
    return copy.deepcopy(plan)


def preview(plan):
    plan = validate(plan)
    return {'schema_version': 1, 'state': 'plan-valid', 'deployment': 'not-performed',
            'infrastructure_verification': 'not-performed', 'site': plan['site'],
            'proxmox': plan['proxmox'], 'networks': plan['networks'],
            'vms': [{'role': role, 'zone': zone, 'os': 'OPNsense' if role == 'edge' else 'Ubuntu 24.04 amd64',
                     **plan['vms'][role]} for role, (zone, _) in MODULES.items()],
            'dns_records': {host: plan['vms']['nginx']['address'] for host in plan['domains'].values()},
            'startup_groups': [['edge'], ['dns'], ['chat', 'files'], ['nginx'], ['partner']],
            'firewall_intent': ['default-deny between zones', 'staff -> dns: TCP/UDP 53',
                                'staff -> nginx: TCP 443', 'nginx -> declared application HTTPS backends only',
                                'partner -> declared federation endpoints only',
                                'no partner/staff access to management or databases'],
            'recovery_site': plan['recovery_site'],
            'required_certificate_coverage_days': plan['offline_days'] + plan['certificate_margin_days'],
            'unverified': ['Proxmox compatibility, API access, bridges, storage capacity and free VM IDs',
                           'Physical recovery-site independence and uplink/remote-site subnet overlap',
                           'Certificate validity, client trust, local time and offline application login',
                           'Independent management access when OPNsense is stopped',
                           'Offline restore, physical relocation and domestic bootstrap reachability'],
            'notice': 'No servers were changed. This preview does not install VMs or establish crisis readiness.'}


def render(result):
    lines = [result['notice'], '', 'Site: ' + result['site'], 'Proposed VMs:']
    lines.extend(f"  {v['id']} {v['role']}: {v['cpu']} CPU, {v['memory_mib']} MiB RAM, {v['disk_gib']} GiB disk; {v['zone']} {v['address']}" for v in result['vms'])
    lines += ['', 'Startup: ' + ' -> '.join(' + '.join(group) for group in result['startup_groups']),
              '', 'Network paths: staff -> OPNsense -> NGINX -> chat/files',
              'Partner path: connector -> OPNsense -> existing WAN -> domestic/partner network',
              '', 'Local DNS:']
    lines.extend(f'  {host} -> {address}' for host, address in result['dns_records'].items())
    lines += ['', 'Firewall intent:'] + ['  ' + s for s in result['firewall_intent']]
    lines += ['', 'Still unverified:'] + ['  ' + s for s in result['unverified']]
    return '\n'.join(lines)


def load(path):
    try:
        require(path.stat().st_size <= 65536, 'Site plan exceeds the 64 KiB size limit.')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'Duplicate JSON fields are not allowed.')
                result[key] = value
            return result
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Cannot read site plan. Supply a readable UTF-8 JSON file using the documented schema.') from None

"""Strict local network settings; derive policy without touching infrastructure."""
import hashlib
import ipaddress
import json
import re
from portable_plan import validate, fields, require, MODULES, ZONES

LINUX_ROLES = tuple(role for role in MODULES if role != 'edge')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def usable(value, cidr):
    try:
        address = ipaddress.ip_address(value)
        net = ipaddress.ip_network(cidr)
        require(type(value) is str and address.version == 4 and address in net
                and address not in (net.network_address, net.broadcast_address),
                'Use a usable IPv4 address in the assigned subnet.')
        return address
    except (TypeError, ValueError):
        raise ValueError('Use a usable IPv4 address in the assigned subnet.') from None


def derive(plan, settings):
    plan = validate(plan)
    fields(settings, 'schema_version administrator_address proxmox_address linux_interfaces dhcp clock')
    require(type(settings['schema_version']) is int and settings['schema_version'] == 1, 'Unsupported network settings schema.')
    occupied = {vm['address'] for vm in plan['vms'].values()} | {net['gateway'] for net in plan['networks'].values()}
    management = plan['networks']['management']['cidr']
    for key in ('administrator_address', 'proxmox_address'):
        usable(settings[key], management)
        require(settings[key] not in occupied, 'Management addresses must be distinct and exclude planned VMs and gateways.')
        occupied.add(settings[key])
    fields(settings['linux_interfaces'], ' '.join(LINUX_ROLES))
    require(all(type(v) is str and re.fullmatch(r'[a-z][a-z0-9]{0,14}', v)
                and v != 'lo' for v in settings['linux_interfaces'].values()),
            'Use the observed Linux Ethernet interface name for each VM, such as ens18.')
    fields(settings['dhcp'], 'start end')
    start, end = (usable(settings['dhcp'][key], plan['networks']['staff']['cidr']) for key in ('start', 'end'))
    require(start <= end and not any(start <= ipaddress.ip_address(ip) <= end for ip in occupied),
            'DHCP range must be ordered and exclude every static address and gateway.')
    clock = settings['clock']
    fields(clock, 'mode source')
    require(clock['mode'] in ('host-rtc', 'local-source'), 'Select host-rtc or local-source clock mode.')
    if clock['mode'] == 'host-rtc':
        require(clock['source'] is None, 'Host RTC mode does not accept an upstream clock.')
    else:
        usable(clock['source'], management)
        require(clock['source'] not in occupied, 'Time source must be an independent local management device.')
    domains = list(plan['domains'].values())
    require(not any(a.endswith('.' + b) for a in domains for b in domains if a != b),
            'Service names must not be nested beneath another service name.')
    for host in domains:
        require(not host.endswith(('.localhost', '.local', '.invalid')) and host not in ('localhost',),
                'Use institution-controlled service names, not multicast or reserved local suffixes.')
    dns = plan['vms']['dns']['address']
    rules = []
    def allow(zone, source, destination, protocol, port, purpose):
        rules.append(dict(interface=zone, source=source, destination=destination,
                          protocol=protocol, port=port, purpose=purpose))
    for zone in ZONES:
        # Frontend peer enforcement is also needed on the DNS VM: the edge
        # cannot filter frames that stay on its bridge.
        for protocol, port, purpose in (('tcp/udp', 53, 'local DNS'), ('udp', 123, 'local time')):
            allow(zone, plan['networks'][zone]['cidr'], dns, protocol, port, purpose)
    allow('staff', plan['networks']['staff']['cidr'], plan['vms']['nginx']['address'], 'tcp', 443, 'future local HTTPS frontend')
    allow('management', settings['administrator_address'], plan['vms']['edge']['address'], 'tcp', 443, 'edge administration')
    for role in LINUX_ROLES:
        allow('management', settings['administrator_address'], plan['vms'][role]['address'], 'tcp', 22, role + ' SSH administration')
    if clock['mode'] == 'local-source':
        allow('frontend', dns, clock['source'], 'udp', 123, 'independent local clock')
    interfaces = {'wan': {'device': 'vtnet0', 'address': 'disconnected', 'bridge': plan['proxmox']['wan_bridge']}}
    for index, zone in enumerate(ZONES, 1):
        net = plan['networks'][zone]
        address = plan['vms']['edge']['address'] if zone == 'management' else net['gateway']
        interfaces[zone] = {'device': 'vtnet' + str(index), 'address': address + '/' + net['cidr'].split('/')[1], 'bridge': net['bridge']}
    return {'schema_version': 1, 'site_sha256': fingerprint(plan), 'settings_sha256': fingerprint(settings),
            'edge_interfaces': interfaces, 'default_policy': 'deny', 'rules': rules,
            'dns_records': {host: plan['vms']['nginx']['address'] for host in domains},
            'dhcp': dict(settings['dhcp'], router=plan['networks']['staff']['gateway'], dns=[dns], ntp=[dns]),
            'clock': dict(clock, utc_verified=False), 'network_verified': False}

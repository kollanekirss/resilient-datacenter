"""Render a local-only DNS/time module and console-applied VM addressing."""
import json
import yaml
from portable_plan import MODULES
from portable_network import derive, LINUX_ROLES


def unbound(plan):
    address = plan['vms']['dns']['address']
    lines = ['server:', '    interface: ' + address, '    interface: 127.0.0.1',
             '    do-ip6: no', '    username: unbound', '    chroot: ""',
             '    directory: "/etc/unbound"', '    pidfile: ""',
             '    hide-identity: yes', '    hide-version: yes', '    log-queries: no',
             '    access-control: 0.0.0.0/0 refuse', '    access-control: 127.0.0.0/8 allow',
             '    local-zone: "." refuse']
    for net in plan['networks'].values():
        lines.append('    access-control: ' + net['cidr'] + ' allow')
    for host in plan['domains'].values():
        lines += ['    local-zone: "' + host + '." static',
                  '    local-data: "' + host + '. 60 IN A ' + plan['vms']['nginx']['address'] + '"']
    return '\n'.join(lines) + '\n'


def chrony(plan, settings, role='dns'):
    lines = ['# Local time is not independent evidence of correct UTC.',
             'driftfile /var/lib/chrony/rdc-portable.drift', 'rtcsync', 'makestep 1.0 3', 'cmdport 0']
    dns = plan['vms']['dns']['address']
    if role == 'dns':
        lines.append('bindaddress ' + dns)
        lines += ['allow ' + net['cidr'] for net in plan['networks'].values()]
        if settings['clock']['mode'] == 'host-rtc':
            lines += ['# Explicit host-RTC reference; verify UTC through the console before use.', 'local stratum 10']
        else:
            lines.append('server ' + settings['clock']['source'] + ' iburst')
    else:
        lines += ['port 0', 'server ' + dns + ' iburst']
    return '\n'.join(lines) + '\n'


def firewall(plan, settings):
    nets = ', '.join(n['cidr'] for n in plan['networks'].values())
    source = settings['clock']['source']
    upstream = '        ip daddr ' + source + ' udp dport 123 accept\n' if source else ''
    return '''# Atomic replacement of only this dedicated table; requires nftables >= 1.0.9.
destroy table inet rdc_dns
table inet rdc_dns {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip saddr { ''' + nets + ''' } tcp dport 53 accept
        ip saddr { ''' + nets + ''' } udp dport { 53, 123 } accept
        ip saddr ''' + settings['administrator_address'] + ''' tcp dport 22 accept
        ip saddr { ''' + nets + ''' } ip protocol icmp accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
''' + upstream + '''        ip daddr { ''' + nets + ''' } ip protocol icmp accept
    }
}
'''


def artifacts(plan, settings):
    policy = derive(plan, settings)
    result = {'dns/unbound.conf': unbound(plan), 'dns/chrony.conf': chrony(plan, settings),
              'dns/firewall.nft': firewall(plan, settings)}
    for role in LINUX_ROLES:
        zone = MODULES[role][0]; net = plan['networks'][zone]
        interface = {'dhcp4': False, 'dhcp6': False, 'accept-ra': False, 'link-local': [], 'optional': True,
                     'addresses': [plan['vms'][role]['address'] + '/' + net['cidr'].split('/')[1]],
                     'routes': [{'to': 'default', 'via': net['gateway']}],
                     'nameservers': {'addresses': [plan['vms']['dns']['address']]}}
        result['netplan/' + role + '.yaml'] = yaml.safe_dump({'network': {'version': 2, 'renderer': 'networkd',
                      'ethernets': {settings['linux_interfaces'][role]: interface}}}, sort_keys=False)
        if role != 'dns': result['time/' + role + '.conf'] = chrony(plan, settings, role)
    result['policy.json'] = json.dumps(policy, indent=2) + '\n'
    binding = policy['site_sha256'] + ':' + policy['settings_sha256']
    result['role-consent.txt'] = binding + '\n'
    variables = {'rdc_network_binding': binding, 'rdc_dns_address': plan['vms']['dns']['address']}
    result['inventory.yml'] = yaml.safe_dump({'all': {'children': {'portable_dns': {'hosts': {
        'portable-dns': {'ansible_host': plan['vms']['dns']['address'], 'ansible_python_interpreter': '/usr/bin/python3',
                         **variables}}}}}}, sort_keys=False)
    from portable_network_guide import render
    result['START-HERE.md'] = render(plan, settings, policy)
    return result

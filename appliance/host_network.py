"""Render the two-port host boundary and audit observations without guessing."""
import ipaddress
import json
import os
from pathlib import Path
import platform
import re

from .contracts import ApplianceError, require

GUARD = "/etc/rdc-appliance/host-guard.nft"
SYSCTL = "/etc/sysctl.d/90-rdc-appliance.conf"


def _inputs(plan, ports):
    try:
        require(set(ports) == {"management", "wan"}, "port-mapping-invalid")
        require(all(type(x) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", x)
                    for x in ports.values()) and len(set(ports.values())) == 2, "port-name-invalid")
        require(not any(x in {"lo", "vmbr0", "vmbr1", "vmbr2", "vmbr3", "vmbr4"} for x in ports.values()), "port-name-invalid")
        management = plan["networks"]["management"]
        network = ipaddress.IPv4Network(management["cidr"], strict=True)
        for key in ("host_ip", "gateway", "admin_ip"):
            address = ipaddress.IPv4Address(management[key])
            require(address in network and address not in (network.network_address, network.broadcast_address), "management-address-invalid")
        require(len({management[k] for k in ("host_ip", "gateway", "admin_ip")}) == 3, "management-address-invalid")
        require(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", plan["site_id"]) is not None, "host-name-invalid")
        require(set(plan["networks"]) in ({"management", "infrastructure", "workload"}, {"management", "infrastructure", "workload", "relay"}), "host-zones-invalid")
        for zone, bridge in (("management", "vmbr0"), ("infrastructure", "vmbr2"), ("workload", "vmbr3"), ("relay", "vmbr4")):
            if zone in plan["networks"]:
                require(plan["networks"][zone]["bridge"] == bridge, "bridge-assignment")
                require(zone == "management" or "host_ip" not in plan["networks"][zone], "guest-host-address")
        return management, network
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ApplianceError):
            raise
        raise ApplianceError("host-input-invalid") from None


def resolve_ports(plan, observations):
    require(type(observations) is list, "port-observations-missing")
    found = {}
    for role in ("management", "wan"):
        expected = plan["ports"][role]
        matches = [item for item in observations if isinstance(item, dict)
                   and all(item.get(key) == expected.get(key) for key in ("permanent_mac", "pci_path", "driver"))]
        require(len(matches) == 1, "port-identity-unresolved")
        found[role] = matches[0].get("name")
    _inputs(plan, found)
    return found


def host_policy(plan):
    management = plan["networks"]["management"]
    return {"management_interface": "vmbr0", "management_address": management["host_ip"],
            "management_network": management["cidr"], "management_tcp_ports": [22, 8006],
            "reply_interface": "vmbr0", "dns_time_address": management["gateway"],
            "forwarding": False, "ipv6": False}


def render_host(plan, resolved_ports, *, management_only=False):
    management, network = _inputs(plan, resolved_ports)
    lines = ["# Owned by rdc-appliance; no inherited interface includes.", "auto lo", "iface lo inet loopback", ""]
    for name in (resolved_ports['management'], resolved_ports['wan']):
        lines += [f"iface {name} inet manual", ""]
    lines += ["auto vmbr0", "iface vmbr0 inet static", f"    address {management['host_ip']}/{network.prefixlen}"]
    if not management_only:
        lines.append(f"    gateway {management['gateway']}")
    lines += [f"    bridge-ports {resolved_ports['management']}", "    bridge-stp off", "    bridge-fd 0", ""]
    bridges = [("vmbr1", resolved_ports["wan"])] + [(v["bridge"], "none") for k, v in plan["networks"].items() if k != "management"]
    for bridge, member in sorted(bridges):
        # Post-PVE policy explicitly activates these; never early networking.
        lines += [f"iface {bridge} inet manual", f"    bridge-ports {member}", "    bridge-stp off", "    bridge-fd 0", ""]
    ip, subnet, gateway = management["host_ip"], management["cidr"], management["gateway"]
    guard = f'''add table inet rdc_host_guard
flush table inet rdc_host_guard
table inet rdc_host_guard {{
 chain input {{
  type filter hook input priority -300; policy drop;
  iifname "lo" accept
  meta nfproto ipv6 drop
  iifname != "vmbr0" drop
  ct state established,related accept
  ip saddr {subnet} ip daddr {ip} tcp dport {{ 22, 8006 }} accept
  ip saddr {subnet} ip daddr {ip} ip protocol icmp accept
 }}
 chain output {{
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  meta nfproto ipv6 drop
  oifname != "vmbr0" drop
  ct state established,related accept
  ip daddr {gateway} udp dport {{ 53, 123 }} accept
  ip daddr {gateway} tcp dport {{ 22, 53 }} accept
  tcp dport {{ 80, 443 }} accept
  ip daddr {subnet} ip protocol icmp accept
 }}
}}
'''
    sysctl = "\n".join([
        "# Host routing is forbidden; guests use OPNsense.", "net.ipv4.ip_forward=0",
        "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1", "net.ipv6.conf.all.accept_ra=0",
        "net.ipv6.conf.default.accept_ra=0", "net.ipv4.conf.all.send_redirects=0",
        *[f"net.ipv6.conf.{name}.disable_ipv6=1" for name in sorted(resolved_ports.values())], ""])
    hostname = plan["site_id"]
    return {"/etc/network/interfaces": ("\n".join(lines) + "\n").encode(),
            SYSCTL: sysctl.encode(), GUARD: guard.encode(),
            "/etc/hostname": (hostname + "\n").encode(),
            "/etc/hosts": f"127.0.0.1 localhost\n{ip} {hostname}\n".encode(),
            "/etc/resolv.conf": f"nameserver {gateway}\noptions timeout:2 attempts:2\n".encode()}


def safe_management_files(plan, resolved_ports):
    return render_host(plan, resolved_ports, management_only=True)


def render_pve_firewall(plan):
    management = plan["networks"]["management"]
    ip, subnet = management["host_ip"], management["cidr"]
    return f'''[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]
local_network {ip}

[RULES]
IN ACCEPT -i vmbr0 -source {subnet} -dest {ip} -p tcp -dport 22,8006
IN ACCEPT -i vmbr0 -source {subnet} -dest {ip} -p icmp
IN DROP
'''.encode()


def audit_host(plan, observed):
    """Missing observations are failures, never implied safe defaults."""
    errors = []
    try:
        ports = resolve_ports(plan, observed.get("ports"))
    except (ApplianceError, KeyError, TypeError):
        ports = observed.get("resolved_ports", {})
        errors.append("port-identity-unresolved")
    addresses = observed.get("addresses")
    addresses = addresses if isinstance(addresses, dict) else {}
    m = plan["networks"]["management"]
    expected_ip = f"{m['host_ip']}/{ipaddress.IPv4Network(m['cidr']).prefixlen}"
    if addresses.get("vmbr0") != [expected_ip]:
        errors.append("management-host-address")
    for name in ("vmbr1", ports.get("wan")):
        if name not in addresses or addresses[name] != []:
            errors.append("wan-host-address")
    for name in ("vmbr2", "vmbr3", *(["vmbr4"] if "relay" in plan["networks"] else []), ports.get("management")):
        if name not in addresses or addresses[name] != []:
            errors.append("unexpected-host-address")
    for name, values in addresses.items():
        if name != "lo" and any(":" in str(value) for value in values):
            errors.append("host-ipv6-address")
        if name not in ('lo','vmbr0') and values:
            errors.append('unexpected-host-address')
    if observed.get("default_routes") != [{"dev": "vmbr0", "gateway": m["gateway"]}]:
        errors.append("host-default-route")
    for field, required in (("forwarding", False), ("ipv6_disabled", True), ("firewall_active", True), ("management_ingress_only", True), ("nat_active", False)):
        if observed.get(field) is not required:
            errors.append("host-" + field.replace("_", "-"))
    members = observed.get("bridge_members", {})
    allowed = {"vmbr0": {ports.get("management")}, "vmbr1": {ports.get("wan")},
               **{v['bridge']: set() for k,v in plan['networks'].items() if k != 'management'}}
    from .proxmox import vm_spec
    for role in plan['vms']:
        vm = vm_spec(plan, role)
        for nic in vm['nics']:
            allowed[nic['bridge']].update({f"tap{vm['vmid']}i{nic['index']}", f"fwpr{vm['vmid']}p{nic['index']}"})
    for bridge, physical in (("vmbr0", ports.get("management")), ("vmbr1", ports.get("wan"))):
        if physical not in members.get(bridge, []) or not set(members.get(bridge, [])) <= allowed[bridge]:
            errors.append(("management" if bridge == "vmbr0" else "wan") + "-bridge-foreign-member")
    for zone in ("infrastructure", "workload", "relay"):
        if zone in plan['networks']:
            bridge = plan['networks'][zone]['bridge']
            if bridge not in members:
                errors.append('guest-bridge-unobserved')
            elif not set(members[bridge]) <= allowed[bridge]:
                errors.append('guest-bridge-foreign-member')
    return list(dict.fromkeys(errors))


def execution_target(root, runner):
    """A test filesystem must never dispatch to the real host's runner."""
    root = Path(root)
    require(root.is_absolute() and '..' not in root.parts, 'host-path-invalid')
    if root == Path('/'):
        require(platform.system() == 'Linux' and os.geteuid() == 0, 'linux-root-required')
    else:
        require(getattr(runner, 'target_root', None) == root.resolve(), 'runner-root-mismatch')
    return root


def _output(runner, argv):
    result = runner.run(argv, timeout_s=15)
    value = result.stdout
    return value.decode('utf-8') if type(value) is bytes else value


def guard_active(plan, ruleset):
    """Verify the complete owned input/output policy, including rule order."""
    def normalize(value):
        if isinstance(value,dict):
            if set(value) == {'prefix'}:
                return str(ipaddress.IPv4Network(f"{value['prefix']['addr']}/{value['prefix']['len']}"))
            if set(value) == {'set'}:
                return tuple(sorted(str(x) for x in value['set']))
            return tuple((k,normalize(v)) for k,v in sorted(value.items()))
        if isinstance(value,list):
            return tuple(sorted(str(x) for x in value))
        return value
    def m(left,right,op='=='):
        return (normalize(left),op,normalize(right))
    meta = lambda key: {'meta':{'key':key}}
    payload = lambda protocol,field: {'payload':{'protocol':protocol,'field':field}}
    management = plan['networks']['management']
    source = m(payload('ip','saddr'),management['cidr'])
    destination = m(payload('ip','daddr'),management['host_ip'])
    gateway = m(payload('ip','daddr'),management['gateway'])
    established = m({'ct':{'key':'state'}},{'set':['established','related']})
    ipv6 = m(meta('nfproto'),'ipv6')
    tcp = lambda values:m(payload('tcp','dport'),{'set':values} if isinstance(values,list) else values)
    udp = lambda values:m(payload('udp','dport'),{'set':values})
    expected = {
        'input': [([m(meta('iifname'),'lo')],'accept'),([ipv6],'drop'),([m(meta('iifname'),'vmbr0','!=')],'drop'),
                  ([established],'accept'),([source,destination,tcp([22,8006])],'accept'),
                  ([source,destination,m(payload('ip','protocol'),'icmp')],'accept')],
        'output': [([m(meta('oifname'),'lo')],'accept'),([ipv6],'drop'),([m(meta('oifname'),'vmbr0','!=')],'drop'),
                   ([established],'accept'),([gateway,udp([53,123])],'accept'),([gateway,tcp([22,53])],'accept'),
                   ([tcp([80,443])],'accept'),([m(payload('ip','daddr'),management['cidr']),m(payload('ip','protocol'),'icmp')],'accept')]
    }
    try:
        items = ruleset['nftables']
        tables = [x['table'] for x in items if x.get('table',{}).get('name') == 'rdc_host_guard'
                  and x['table'].get('family') == 'inet']
        if len(tables) != 1 or tables[0].get('flags'):
            return False
        chains = [x['chain'] for x in items if x.get('chain',{}).get('table') == 'rdc_host_guard'
                  and x['chain'].get('family') == 'inet']
        if len(chains) != 2 or {x['name'] for x in chains} != {'input','output'}:
            return False
        for chain in chains:
            name = chain['name']
            if not (chain.get('policy') == 'drop' and chain.get('hook') == name
                    and chain.get('prio') == (-300 if name == 'input' else 0) and chain.get('type') == 'filter'):
                return False
            actual = [x['rule']['expr'] for x in items if x.get('rule',{}).get('table') == 'rdc_host_guard'
                      and x['rule'].get('chain') == name and x['rule'].get('family') == 'inet']
            if len(actual) != len(expected[name]):
                return False
            for expr,(wanted,verdict) in zip(actual,expected[name]):
                if expr[-1] != {verdict:None}:
                    return False
                matches = []
                for part in expr[:-1]:
                    match = part['match']
                    left,right,op = match['left'],match['right'],match['op']
                    # nft may expose an implicit protocol dependency for payload access.
                    if left == meta('l4proto') and op == '==' and right in ('tcp','udp',6,17):
                        protocol = 'tcp' if right in ('tcp',6) else 'udp'
                        if not any(x.get('match',{}).get('left',{}).get('payload',{}).get('protocol') == protocol for x in expr[:-1]):
                            return False
                        continue
                    if left == meta('nfproto') and right == 10:
                        right = 'ipv6'
                    if left == payload('ip','protocol') and right == 1:
                        right = 'icmp'
                    if op == 'in':
                        op = '=='
                    matches.append(m(left,right,op))
                if matches != wanted:
                    return False
        return True
    except (KeyError,TypeError,ValueError,IndexError):
        return False


def collect_ports(root, runner):
    """Read permanent PCI Ethernet identity; virtual links are not candidates."""
    root = execution_target(root, runner)
    try:
        links = json.loads(_output(runner, ['/usr/sbin/ip', '-j', 'link', 'show']))
        require(type(links) is list and len(links) <= 1024, 'port-observations-missing')
        result = []
        for link in links:
            name = link.get('ifname', '')
            require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', name) is not None, 'port-name-invalid')
            device = root / 'sys/class/net' / name / 'device'
            if not device.is_symlink():
                continue
            pci = Path(os.readlink(device)).name
            if not re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', pci):
                continue
            details = dict(line.split(': ', 1) for line in _output(runner, ['/usr/sbin/ethtool', '-i', name]).splitlines() if ': ' in line)
            permanent = _output(runner, ['/usr/sbin/ethtool', '-P', name]).strip().removeprefix('Permanent address: ').lower()
            require(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', permanent) is not None
                    and details.get('bus-info') == pci and details.get('driver'), 'port-identity-unresolved')
            result.append({'name': name, 'permanent_mac': permanent, 'pci_path': pci, 'driver': details['driver']})
        return result
    except (OSError, ValueError, TypeError, KeyError):
        raise ApplianceError('port-observations-missing') from None


def collect_host(plan, root, runner):
    """Collect actual kernel/PVE observations. Unreadable evidence fails closed."""
    root = execution_target(root, runner)
    try:
        ports = collect_ports(root, runner)
        mapping = resolve_ports(plan, ports)
        addr = json.loads(_output(runner, ['/usr/sbin/ip', '-j', 'address', 'show']))
        links = json.loads(_output(runner, ['/usr/sbin/ip', '-j', '-d', 'link', 'show']))
        routes = json.loads(_output(runner, ['/usr/sbin/ip', '-j', 'route', 'show', 'default']))
        ruleset = json.loads(_output(runner, ['/usr/sbin/nft', '-j', 'list', 'ruleset']))
        firewall = _output(runner, ['/usr/sbin/pve-firewall', 'status']).lower()
        addresses = {item['ifname']: [f"{a['local']}/{a['prefixlen']}" for a in item.get('addr_info', [])] for item in addr}
        # ipv6.disable=1 prevents kernel registration of IPv6 sysctls/tables.
        # Missing keys alone never prove this: require the live module flag,
        # the absent sysctl tree, and no IPv6 addresses on any interface.
        try:
            with (root / 'sys/module/ipv6/parameters/disable').open() as stream:
                disabled_parameter = stream.read(8).strip() in ('1', 'Y')
        except OSError:
            disabled_parameter = False
        kernel_disabled = (disabled_parameter and not (root / 'proc/sys/net/ipv6').exists()
                           and not any(':' in value for values in addresses.values() for value in values))
        legacy_nat = [_output(runner,['/usr/sbin/iptables-save','-t','nat'])]
        v4 = _output(runner, ['/usr/sbin/sysctl', '-n', 'net.ipv4.ip_forward']).split()
        if kernel_disabled:
            v6 = ['0','1','1']
        else:
            legacy_nat.append(_output(runner,['/usr/sbin/ip6tables-save','-t','nat']))
            v6 = _output(runner, ['/usr/sbin/sysctl', '-n', 'net.ipv6.conf.all.forwarding',
                                  'net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6']).split()
        members = {item['ifname']: [] for item in links if item.get('linkinfo', {}).get('info_kind') == 'bridge'}
        for link in links:
            if link.get('master') in members:
                members[link['master']].append(link['ifname'])
        nat = any(any(key in expr for key in ('snat','dnat','masquerade','redirect'))
                  for item in ruleset['nftables'] for expr in [*item.get('rule', {}).get('expr', []), {}])
        nat = nat or any(line.startswith('-A ') for text in legacy_nat for line in text.splitlines())
        return {'ports': ports, 'resolved_ports': mapping, 'addresses': addresses,
                'default_routes': [{k:r.get(k) for k in ('dev','gateway')} for r in routes],
                'forwarding': None if len(v4) != 1 or len(v6) != 3 else (v4 + v6[:1]) != ['0','0'],
                'ipv6_disabled': v6[1:] == ['1','1'], 'bridge_members': members,
                'firewall_active': 'enabled/running' in firewall, 'management_ingress_only': guard_active(plan,ruleset),
                'nat_active': nat}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ApplianceError('host-audit-unproven') from None

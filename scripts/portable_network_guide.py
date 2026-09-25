"""Human console instructions derived from the same reviewed network policy."""
import ipaddress


def render(plan, settings, policy):
    dns = plan['vms']['dns']['address']; admin = settings['administrator_address']
    edge = plan['vms']['edge']['address']; pve = settings['proxmox_address']
    lines = ['# Local network setup: ' + plan['site'], '',
        'Prepared configuration, not deployment evidence. Keep this kit private with your operating records. '
        'This is stage 3: the HTTPS frontend and applications are not installed here.', '',
        '## 1. Keep an independent repair path', '',
        f'Use a console or directly attached administrator on {admin} with the management subnet mask. '
        f'Reach Proxmox at https://{pve}:8006 by its verified certificate identity (prepare a hosts entry for its existing hostname if needed). '
        'Do not disable certificate checks. The administrator needs no default route to reach Proxmox on this same link.',
        'Test this path with OPNsense powered off. Back up the Proxmox configuration and OPNsense configuration to encrypted offsite storage. '
        'Keep physical console credentials separately accessible. Never move host management onto the WAN bridge.', '',
        '## 2. Assign OPNsense interfaces through its console', '',
        'Keep WAN, staff and service links disconnected initially. Match Proxmox NIC numbers/MACs to guest devices; '
        'the vtnet names below are the planned order, not automatic hardware discovery. Enable only the management NIC first on the trusted, isolated management bridge.', '',
        '| Zone | Expected guest interface | Existing bridge | Address |', '|---|---|---|---|']
    for zone, item in policy['edge_interfaces'].items():
        lines.append(f"| {zone} | {item['device']} | {item['bridge']} | {item['address']} |")
    lines += ['', f'Assign management as LAN and the other local zones as separate optional interfaces. Management is {edge}, '
              f'not the legacy reserved management.gateway ({plan["networks"]["management"]["gateway"]}). '
              'Do not configure that reserved address as another edge IP. No upstream gateway belongs on a local interface.',
              'Use static IPv4 locally. Disable IPv6 configuration, router advertisements and DHCPv6 on all local zones. '
              'WAN may later use DHCP for relocation, but leave its Proxmox NIC disconnected for this stage. '
              'Do not select a WAN gateway on local firewall rules; local routing must not depend on gateway monitoring.', '',
              '## 3. Replace the fresh-install allow-all policy deliberately', '',
              'Open OPNsense through the trusted management path. Add the explicit administrator HTTPS rule first, '
              'verify a second management session, then remove the default LAN-to-any rule and disable the LAN anti-lockout rule. '
              'Keep the console open throughout. Review floating, interface-group, automatic, legacy and new/automation rules; '
              'one rule API cannot prove that all other rules are absent. Do not disable the firewall.',
              'On each listed ingress interface, add stateful IPv4 pass rules in the following table. '
              'Use no selected gateway and no NAT between local zones. Everything else is denied. '
              'Frontend-to-frontend traffic stays on its bridge; the DNS VM firewall enforces that path separately.', '',
              '| Ingress zone | Source | Destination | Protocol | Destination port | Purpose |', '|---|---|---|---|---|---|']
    for rule in policy['rules']:
        lines.append('| ' + ' | '.join(str(rule[k]) for k in ('interface','source','destination','protocol','port','purpose')) + ' |')
    lines += ['', 'The Proxmox management connection stays on the same bridge and is not an edge forwarding rule. '
              'No application backend, database or partner federation access is granted in this iteration. '
              'Clear old firewall states after removing broad rules, using the console for recovery if a management session drops. '
              'Confirm the management path again before connecting staff.', '',
              '## 4. Configure DHCP only on the staff interface', '',
              'Use Services → Dnsmasq DNS & DHCP (or the version-equivalent DHCP settings). '
              'Disable other DHCP servers on this segment, restrict DHCP to staff, disable router advertisements and disable Dnsmasq DNS listening (port 0). '
              'Set these options for the staff range explicitly; do not let DHCP advertise the router as a DNS fallback:', '',
              f'- Range: {settings["dhcp"]["start"]} – {settings["dhcp"]["end"]}',
              f'- Subnet mask: {ipaddress.ip_network(plan["networks"]["staff"]["cidr"]).netmask}',
              f'- Router, option 3: {policy["dhcp"]["router"]}',
              f'- DNS, option 6: {dns} only', f'- NTP, option 42: {dns}',
              '- Lease time: 12 hours; apply and verify the actual client lease.', '',
              'Inspect the automatically generated DHCP rules for staff UDP68→67 and replies. Do not open DHCP on WAN or other zones. '
              'Disable the edge Unbound/DNS forwarding service; the dedicated DNS VM owns name service. '
              'Disable edge NTP serving or restrict it to loopback so it does not become an accidental alternate clock.', '',
              '## 5. Prepare the DNS VM during normal operation', '',
              'Using the guest console and a separately reviewed temporary maintenance uplink, install Ubuntu packages '
              '`unbound chrony nftables openssh-server python3`. This is a connected preparation requirement; '
              'the playbook intentionally never downloads packages. Set up an individual SSH administrator with sudo and verified host keys. '
              'Verify Ubuntu 24.04 amd64 and nftables 1.0.9 or newer. Remove temporary DNS/uplink/firewall exceptions before offline acceptance.',
              'For each Linux guest, inspect `ip -br link` and confirm the kit interface name. Back up its existing `/etc/netplan` files; '
              'replace the active interface configuration with the matching `netplan/ROLE.yaml` at mode 0600. '
              'Do not leave conflicting installer/cloud-init configurations enabled. Use `netplan generate` and `netplan try --timeout 120` '
              'from the console; verify the address and route before confirming. Do not make this change over the only SSH connection.',
              'Enable only the edge management/staff/frontend NICs and DNS VM local NIC now, after reviewing the policy. '
              'Keep application and partner VM NICs disconnected until their host firewalls and services are installed in the later phase. '
              'Record intentional manual link changes: the older guest-install commands require disconnected NICs and must not be rerun after this transition.',
              'Verify the DNS VM identity and copy `role-consent.txt` through your trusted channel to '
              '`/etc/rdc-portable-dns-consent` owned by root, mode 0600. This explicit console step binds the role to this site/settings; '
              'do not place this file on Proxmox or another VM.',
              'From the reviewed repository, verify the kit, then apply the guarded playbook:', '', '```sh',
              './rdc portable network-verify /absolute/site/site.json --settings /absolute/site/network.json --output-dir /absolute/site/network-kit',
              '.venv/bin/ansible-playbook -i /absolute/site/network-kit/inventory.yml playbooks/portable-dns.yml --extra-vars \'{"rdc_network_kit":"/absolute/site/network-kit"}\' -u YOUR_ADMIN --ask-become-pass', '```', '',
              'Run from the management administrator address. SSH host checking stays enabled; inspect the guest host key through its console first. '
              'The playbook checks kit hashes, host address/OS, consent and existing ownership before changing services. '
              'It refuses unrelated active nftables rules. It retains stock configuration files and uses separate RDC units; '
              'it stops the stock Unbound/chrony daemons only after validation. A failed apply is not rolled back to an open firewall.', '',
              '## 6. Verify the local clock deliberately', '']
    if settings['clock']['mode'] == 'host-rtc':
        lines += ['This kit uses the DNS VM clock inherited from the Proxmox host as a local stratum-10 reference. '
                  'Before booting the kit, compare host RTC/UTC against an independent trusted clock. '
                  'A bad host clock will be served consistently to every client. NTP responses do not establish correct UTC. '
                  'Record the comparison and repeat after power loss; do not change time backwards on running application databases.']
    else:
        lines += [f'The only source is the independent local NTP device at {settings["clock"]["source"]}. '
                  'Verify that device and its power supply. When absent, this configuration has no local fallback; '
                  'check chrony tracking and treat unsynchronised replies as a failed prerequisite.']
    lines += ['Prepared staff devices must use this DNS/time server explicitly; DHCP NTP support varies by client. '
              'The `time/ROLE.conf` files are client configurations for the later service phase, not automatically installed here. '
              'Remove external browser encrypted-DNS overrides and prepare local application accounts/certificates before crisis use.', '',
              '## 7. Cold-start and recovery exercise', '',
              '1. Disconnect WAN physically or at the VM NIC; record that action. Reboot edge and DNS from disk.',
              '2. Renew a staff client lease; verify address, router and the single DNS address above.',
              '3. Run `rdc portable network-check site.json --settings network.json --json` from that client. '
              'The check sends literal-IP DNS UDP/TCP and NTP probes; it never modifies the client resolver.',
              '4. Verify prohibited staff access using a known listening test endpoint and firewall logs/counters. '
              'A TCP timeout or a closed application port alone does not prove firewall enforcement. '
              'Check staff cannot administer edge/Proxmox/SSH; verify same-bridge unauthorized SSH is blocked on DNS.',
              '5. Shut down OPNsense and prove direct administrator→Proxmox access still works; restore edge and repeat DNS checks.',
              '6. Save edge configuration export and this kit in encrypted offsite recovery storage with separate credentials.', '',
              'For repair: use the Proxmox console, inspect `journalctl -u rdc-portable-dns -u rdc-portable-time -u rdc-portable-firewall`, '
              '`nft list table inet rdc_dns`, and `ip address`. Disconnect staff/WAN before temporarily changing policy. '
              'Restore the saved Netplan or OPNsense configuration via console if necessary. Do not flush global firewalls or '
              'restart the installation media. DNS kit changes require a reviewed new kit and explicit role-consent update.', '',
              'Passing DNS/time probes is not HTTPS/application readiness, proof of correct UTC, physical isolation or disaster recovery. '
              'NGINX, Synapse/Element, Nextcloud, complete offline rebuild and relocation acceptance remain subsequent work.', '',
              'References: [OPNsense interfaces](https://docs.opnsense.org/manual/interfaces.html), '
              '[DHCP](https://docs.opnsense.org/manual/dnsmasq.html), '
              '[firewall API boundaries](https://docs.opnsense.org/manual/firewall_automation.html), '
              '[Netplan](https://netplan.readthedocs.io/en/stable/netplan-try/).', '']
    return '\n'.join(lines)

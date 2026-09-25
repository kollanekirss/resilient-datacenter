# Portable local network foundation

This implements roadmap stage 3 in the user's approved Proxmox direction. It does not fold application migration into network bring-up. Local access must survive loss of WAN, external DNS and overlays. OPNsense remains the router, a dedicated Ubuntu VM provides Unbound and chrony, and each application retains its own VM. The existing overlay installation is unchanged.

## Deliverable and boundaries

`rdc portable network-prepare site.json --settings network.json --output-dir KIT` creates a private, immutable preparation kit. A wizard menu collects settings and invokes the same implementation. Generation works without servers and never edits host networking. The kit contains a plan-bound manifest, a site-specific OPNsense guide and rule table, per-Linux-VM Netplan configurations, isolated DNS/time configuration, an inventory and a guarded Ansible playbook for the DNS VM. An operator uses the consoles to assign interfaces and enable selected local virtual links after policy is in place; WAN and partner links remain disconnected. The wizard does not infer safe firewall state from an API response.

A separate `network-check` command performs bounded DNS UDP/TCP and NTP client checks from a prepared staff device. Results are observations, not proof of physical isolation, firewall denial, clock correctness, DHCP, application availability or crisis readiness. Tests run real Unbound/chrony and packet filters only on disposable hosted Linux. No vendor servers execute on the preparation Mac.

## Inputs and trust

The unchanged site schema supplies static service identities and networks. Additional strict settings supply the directly attached management administrator IP, Proxmox management IP, observed Linux interface names, staff DHCP range and clock mode. All addresses must be usable and nonconflicting in their respective subnets. Clock modes: `host-rtc` (explicitly unverified local reference), or `local-source` with an independent local IPv4 NTP device in management. No automatic upstream pool, external resolver, certificate issuer or identity provider is involved.

The edge's management IP is the existing `vms.edge.address`; other edge interfaces use their network gateways. The schema's legacy management.gateway is reserved and is not configured as a second edge address or an administrator default route. Preserve existing plan bindings instead of mutating old plans. Management access is direct on the management bridge, independent of OPNsense.

## Policy and stages

IPv4 local-only stage; no IPv6 route advertisements/DHCPv6. Default deny routed traffic. Staff may reach Unbound TCP/UDP 53 and NTP UDP123, and future NGINX TCP443. Approved administrator may manage edge and SSH to guest IPs. Frontend/application/partner VMs may query the dedicated DNS/time server; partner has no general application or management grant. NGINX to application TLS and partner federation rules are deferred to the separately reviewed application profile. Same-bridge paths require host enforcement: DNS/time VM has its own dedicated nftables input and forwarding rules.

Unbound serves exact prepared names with local static zones, refuses unrelated names, restricts clients to site networks, and never recurses externally. Chrony binds the planned DNS/time IP. In local-source mode, it must remain unsynchronised when its source is absent (no local fallback). In host-RTC mode, it advertises an explicitly documented local stratum, which establishes agreement but does not verify UTC.

Package acquisition is a connected preparation step. The DNS playbook requires preinstalled packages so it can run without repository access. It verifies Ubuntu24.04, role address, a dedicated fresh-role consent flag and strict ownership before replacing its own files. It never applies Netplan remotely. Operator installs required packages and SSH access during preparation, backs up existing configuration and applies Netplan through the console with rollback. Playbook uses separate RDC systemd units/configuration; it checks syntax before activation and refuses unrelated existing listeners/firewall ownership. Credentials remain in normal SSH trust/agent/sudo mechanisms; no passwords in kit.

## Failure and recovery

Refuse nonempty output, symlinks, invalid inputs and changed kit files. A manifest hashes all artifacts and binds site/settings. Rerender to a new directory for changed settings. Partial kit generation never appears complete. Check failures return a nonzero code with per-probe results. Operator retains Proxmox console and config backups; never flush unrelated host firewalls or reconfigure the Proxmox bridge. Enabling NICs and firewall configuration are documented operator actions, not claimed automated verification.

## Acceptance

Unit tests cover malformed input, reserved/colliding addresses, invalid source clock, escaping, private atomic artifact output, probe parsing and failure exit semantics. Hosted Linux exercises generated configs with real DNS queries over UDP/TCP, exact local names, NXDOMAIN/REFUSED for other names, access restrictions, chrony response, firewall denial and cold restart with no external route. Actual OPNsense DHCP/firewall behavior, PVE bridge wiring and physical RTC/power acceptance remain NOT RUN without a disposable host. Stage4 (NGINX plus explicit portable application profiles), offline reconstruction and relocation remain subsequent work.

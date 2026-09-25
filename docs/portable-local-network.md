# Prepare the portable local network

The Proxmox wizard now includes **step 8: Local network**. This development iteration supplies a site-specific OPNsense setup guide, static Linux VM addressing, an Unbound/chrony module and client diagnostics. It does not yet supply the new NGINX application access profile or a complete offline crisis appliance.

You can prepare the kit before buying or connecting servers. Actual activation needs the planned Proxmox host, OPNsense guest, DNS guest, local switch/access point and a directly connected management computer. The [site plan](portable-site-plan.md) defines the six VMs. No additional VPS is needed for this preparation work.

## Guided preparation

From a reviewed checkout with the project's Python dependencies installed:

```sh
./rdc start --platform proxmox --resume /absolute/private/site/site.json
```

Choose **8 Local network**. Supply the existing Proxmox management IP, a static administrator IP on the same management subnet, the observed Ethernet interface names in the five Ubuntu guests, and the intended staff DHCP range. These inputs are not automatically discovered. They are saved privately in `network.json`; `network-kit/START-HERE.md` contains the exact site-specific procedure.

For scripted preparation, adapt [examples/portable-network.json](../examples/portable-network.json), then:

```sh
./rdc portable network-prepare /absolute/private/site/site.json \
  --settings /absolute/private/site/network.json \
  --output-dir /absolute/private/site/network-kit
./rdc portable network-verify /absolute/private/site/site.json \
  --settings /absolute/private/site/network.json \
  --output-dir /absolute/private/site/network-kit
```

Use an existing private parent directory with mode 0700 and a new kit directory. Existing kits are never overwritten. A manifest binds every generated artifact to the site and network settings. Verification compares files to the current renderer as well as their checksums; changed project versions may require a new kit. Checksums detect changed bytes, not approval by an independent authority. Protect the private operating records and the reviewed source checkout.

## What the kit contains

| Item | How it is used |
|---|---|
| `START-HERE.md` | Exact addresses, interface mapping, OPNsense rule table, DHCP options, preparation and repair steps |
| `netplan/*.yaml` | Static guest configuration applied from each guest console, with rollback; never applied remotely by the wizard |
| `dns/unbound.conf` | Explicit service-name records pointing at NGINX, restricted local clients, no external recursion |
| `dns/chrony.conf` | Selected local clock source; no external NTP pool |
| `dns/firewall.nft` | Dedicated DNS VM input/forward/output policy, including same-bridge enforcement |
| `time/*.conf` | Client time configurations for the later service phase; not installed automatically here |
| `inventory.yml`, `role-consent.txt` | Inputs to the guarded DNS/time playbook after console preparation |
| `site.json`, `network.json`, `policy.json`, `manifest.json` | Private configuration and integrity records; no passwords or keys |

## Activation sequence

1. **Prove direct management access with OPNsense stopped.** The administrator and Proxmox need static addresses on the same management link. Retain console access and back up current settings. Management must not depend on DNS or the edge VM.
2. **Configure OPNsense through its console and management interface.** Apply the kit's exact zone addresses and narrow pass rules; remove default broad access only after checking the explicit management rule. Inspect all rule categories, disable IPv6/RA for this IPv4 profile and keep WAN/partner disconnected. The kit is a guided procedure, not an automatic OPNsense configuration importer.
3. **Prepare the DNS guest while connected.** Install `unbound`, `chrony`, `nftables`, `openssh-server` and `python3` from the institution's approved Ubuntu sources. Prepare SSH host trust and administrator credentials. Package acquisition is not an offline recovery capability.
4. **Apply addressing from the console.** Back up existing Netplan files, remove conflicting interface definitions and use `netplan try` with a timeout. Enable the reviewed local links. Leave application/partner guests disconnected until their own service/firewall phase. After manual NIC activation, the earlier installation commands intentionally refuse the changed configuration.
5. **Install the DNS/time module.** Copy the kit's consent file to the DNS guest through the trusted console/management channel as explained in `START-HERE.md`. Run the repository's `playbooks/portable-dns.yml` with the kit inventory. It requires a matching Ubuntu 24.04 amd64 guest, prepared packages, explicit role consent and no unrelated firewall tables. It uses separate RDC units and configuration files, retains the stock daemon configurations, never edits Proxmox, and never downloads packages. A changed kit binding requires a reviewed migration rather than silent replacement.
6. **Verify from a prepared staff device.** Disconnect WAN, cold-start edge and DNS, renew the client DHCP lease and run the client checks below. Test prohibited paths using known listeners and firewall counters, then stop OPNsense and retest independent Proxmox access.

The management address configured on OPNsense is `vms.edge.address`. The earlier site schema's `networks.management.gateway` remains a reserved address; this module does not configure it as another edge address. Management clients need no default route for their direct Proxmox connection. To reach guest SSH, add explicit frontend/application/partner subnet routes via the edge management IP, as listed in the generated guide. A separate management NTP device likewise needs a return route to the frontend subnet via that IP. Other zones use their declared gateways.

Local DNS returns only the prepared chat, Element and files hostnames. Unrelated names are refused or absent. This gives predictable offline answers; it does not make external websites or software repositories available. During connected maintenance, use a separately reviewed temporary maintenance path, then remove it before the isolation test. Do not put an external resolver second in clients' DNS lists and call that offline operation.

## Time modes

- **`host-rtc`:** the DNS VM advertises its inherited clock as a local stratum-10 reference. It needs no outside source, but it can distribute an incorrect time. Check host UTC/RTC against an independent trusted clock before deployment and after power loss. This is local agreement, not independently verified UTC.
- **`local-source`:** specify an independent NTP device on the management subnet. The kit allows only that source and supplies no host-RTC fallback. If it is unavailable before synchronisation, the service remains unsynchronised and client checks fail. Keep that device and its power/recovery arrangements independent.

Client checks compare NTP with the checking computer and reject a difference over five seconds. Two incorrect clocks can agree. Client time preparation, certificate validity and measured clock drift remain acceptance requirements. DHCP option 42 support varies; prepare clients explicitly where needed.

## Client checks and remaining acceptance

```sh
./rdc portable network-check /absolute/private/site/site.json \
  --settings /absolute/private/site/network.json --json
```

Run on a prepared staff client with local IP connectivity. The command queries the literal DNS/time address, verifies all three service names over UDP and TCP, checks refusal/absence of an unrelated name and examines an NTP reply. It does not alter the client resolver or use public DNS. A missing, malformed, mismatched or unsynchronised response fails the check and returns a nonzero exit code.

A passing result deliberately leaves `utc_verified`, `wan_isolation_verified`, `firewall_enforcement_verified` and `applications_verified` false. Physical WAN disconnection, DHCP correctness, deny-rule enforcement, independent management and real chat/file operations cannot be inferred from DNS/NTP success.

Hosted acceptance uses real Unbound, chrony and nftables in Linux namespaces with no default routes. It checks local queries, denied source networks, same-bridge SSH access and service restarts. The clock fixture uses chrony's no-clock-control mode to avoid adjusting the runner clock. This is neither an OPNsense emulator nor a Proxmox installation test. The guarded Ansible deployment still needs live guest acceptance; its syntax is checked locally. See [validation status](validation-status.md).

Continue with the [local application kit](portable-local-applications.md) in wizard step 9 for the separate NGINX frontend and explicit portable application profile. That module adds backend TLS, trusted proxy settings, locally served Element assets and certificates. Preparing this network kit alone does not deploy applications.

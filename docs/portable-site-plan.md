# Preview a portable Proxmox site

This is the first implemented part of the [portable architecture](architecture/portable-proxmox.md). It validates an operator-supplied plan and prints a preview. It makes no network requests, changes no servers and writes no generated configuration. The separate [experimental Proxmox adapter](proxmox-provisioning.md) adds API checks and explicit blank VM shell allocation. The [guest wizard](portable-installation-wizard.md), [network kit](portable-local-network.md) and [local applications](portable-local-applications.md) provide subsequent guided stages; preview alone performs none of those deployments.

After preparing the project's normal Python dependencies:

```sh
./rdc portable preview examples/portable-site.json
./rdc portable preview examples/portable-site.json --json
```

Copy the example JSON into your own private working directory and edit it. Do not put credentials into the plan. The example is an illustrative layout, not discovered infrastructure and not a deployable configuration. Existing `rdc start` journeys remain unchanged; this command is a separate entry point while the portable platform is being built.

## Fields

- `schema_version`: exactly `1`.
- `site` and `recovery_site`: different lowercase site identifiers. The validator cannot verify that they describe physically independent locations.
- `proxmox`: HTTPS hostname endpoint (no credentials, query or fragment), node, storage and dedicated WAN bridge identifiers. The command does not contact the endpoint or establish that any resource exists.
- `networks`: exactly management, staff, frontend, applications and partner. Each has a canonical RFC1918 IPv4 CIDR from /16 through /28, a usable gateway and a distinct bridge. WAN must use another bridge. IPv6 and VLAN-backed profiles are not part of schema 1.
- `vms`: exactly edge, dns, nginx, chat, files and partner. Each declares a unique numeric VM ID, CPU count, memory in MiB, disk in GiB and a unique usable local address in its assigned zone. The edge address is an administration address; the network gateways separately describe OPNsense's routed interface addresses. The future adapter must implement these addresses explicitly.
- `domains`: distinct lowercase chat, element and files hostnames. All resolve locally to the proposed NGINX address. Owning the names and obtaining certificates are separate prerequisites.
- `offline_days` and `certificate_margin_days`: positive planning values. The preview reports their sum as required certificate coverage. It does not inspect certificates or promise that public issuers can provide that duration.

Minimum planning allowances are 3 GiB RAM for edge, 1 GiB each for DNS/NGINX, 4 GiB each for chat/files, 2 GiB for the connector, and 20 GiB disk per VM. These are validation floors, not capacity promises; size application disks for user data and restoration staging. The example's resource values do not reserve host overhead or backup capacity.

The preview includes VM placement, startup groups, DNS records, firewall intent and unverified requirements. The firewall entries are a policy outline, not executable rules: exact backend and federation listeners will be introduced with their respective modules. No arbitrary scripts or commands are accepted in the input.

Unknown/missing fields, duplicate JSON keys, overlapping subnets, addresses outside their assigned zone, duplicate VM IDs and embedded credential fields are rejected. Error messages do not echo input values. Plans are limited to 64 KiB. Valid output still contains institutional names and addressing: keep it private unless reviewed for sharing.

## What still needs verification

An operator must verify Proxmox version compatibility, actual free IDs, bridge assignments, storage/RAM capacity, uplink and other-site subnet conflicts, physical independence, client DNS/trust preparation, certificate validity, offline recovery and independent management access. A successful preview means only that the submitted plan passes this schema's checks.

# Experimental Proxmox VM shell allocation

This development feature is the infrastructure scaffold for the [portable reference architecture](architecture/portable-proxmox.md). It can inspect a Proxmox API and allocate six **stopped, disconnected VM shells with blank disks**. It does not install Proxmox, OPNsense, Ubuntu or any application. It does not download guest images, change bridges, configure IP addresses inside guests, enable networking, start VMs or provide a working crisis node.

**Acceptance boundary:** unit tests simulate the API, including partial allocation and refusal paths. Upstream API definitions were reviewed. No live Proxmox host or guest boot has been verified for this feature. Proxmox VE 9.x is the candidate API family; this is not a tested compatibility claim. Start with a disposable lab and independent console access.

## Prepare the host independently

Install and administer Proxmox separately. Create the WAN bridge and five distinct Linux bridges from the site plan. Configure the physical connections and an independent management path before using this command. The allocator will not change a working host's network configuration. It rejects a WAN bridge with a configured host address or gateway; it cannot prove that management is unreachable through another path.

Use active `lvmthin` or `zfspool` storage that permits VM images. Other storage types, VLAN-backed/OVS profiles, clusters spanning sites and guest migration are outside this initial adapter. Provide enough currently free RAM for all planned guests plus 2 GiB host reserve, and free disk capacity for missing disks plus 10 GiB reserve. These checks do not reserve capacity against concurrent administration or prove workload sizing.

Prepare and review your [site plan](portable-site-plan.md). Confirm the six VM IDs are available cluster-wide. The API may hide resources from insufficiently privileged users; a conflicting server-side create must fail, never overwrite. The tool does not claim that visibility or a successful read-only check proves create permissions.

## Credentials and trust

Create a dedicated, privilege-separated API token through Proxmox administration. Consult the upstream [API permission definitions](https://pve.proxmox.com/pve-docs/api-viewer/) and [access management documentation](https://pve.proxmox.com/pve-docs/chapter-pveum.html) for the selected version. Do not grant host network modification, guest deletion or administrator-wide rights solely for this command.

The adapter reads `/version`, `/cluster/resources?type=vm`, node network/status, storage status, and existing QEMU configuration/status. Allocation additionally calls `POST /nodes/{node}/qemu` and reads creation task status. Typical applicable privileges include `Sys.Audit`, `Datastore.Audit`, `VM.Audit`, `VM.Allocate` and `Datastore.AllocateSpace`, with additional per-property permissions determined by the create endpoint. Scope grants to the intended node, storage and VM IDs wherever the API permits. The exact minimal privilege set still requires live acceptance; do not respond to permission failures by automatically escalating to root.

Store credentials outside the repository in a regular file owned by your current user with mode `0600` (or stricter):

```json
{
  "token_id": "operator@pve!portable",
  "token_secret": "REPLACE-WITH-YOUR-TOKEN-SECRET"
}
```

The token is not a command-line argument or part of the site plan. Do not paste real credentials into issues, chat or commits. The client verifies certificate hostname and trust; there is no insecure mode. If the API uses a private CA, supply its trusted CA PEM through `--ca-file`, obtained and verified independently. Redirects and environment-configured HTTP proxies are disabled to avoid forwarding credentials to another endpoint.

## Inspect first

```sh
./rdc portable check /absolute/path/site.json \
  --token-file /absolute/private/path/proxmox-auth.json \
  --ca-file /absolute/private/path/proxmox-ca.pem --json
```

Omit `--ca-file` when the server chain is already trusted by the preparation computer. `check` sends GET requests only. It validates the plan, candidate version family, bridge presence, WAN host-address guard, visible VM IDs, existing shell ownership/configuration and available storage/RAM. Its success means only `ready-for-shell-allocation`, not service readiness.

## Explicitly allocate shells

```sh
./rdc portable allocate-shells /absolute/path/site.json \
  --token-file /absolute/private/path/proxmox-auth.json \
  --ca-file /absolute/private/path/proxmox-ca.pem --json
```

This action allocates disks and VM definitions. Each guest has autostart disabled and each virtual NIC has its link disconnected. Edge receives WAN plus the five planned zone interfaces in that order; each other guest receives its assigned zone interface. Addresses, DNS records and routing remain plan intent, not applied guest configuration.

The command checks the entire plan before its first creation request, waits for each server task and checks the resulting shell. It never updates or deletes an existing guest. A description marker binds each shell to a hash of the complete plan and module identity. This is an ownership/retry guard, not protection against a malicious Proxmox administrator.

Retrying the identical plan can skip matching stopped shells and allocate the remainder. A changed plan, unexpected NIC/disk, changed resources, locked VM, running VM or foreign ownership blocks the operation. After guest installation or intentional reconfiguration, this command is no longer an appropriate lifecycle manager; it refuses those differences rather than reverting them.

If a request or task fails, existing resources remain. A timed-out POST may have succeeded. Inspect the Proxmox task and guest state before retrying; do not repeatedly resubmit or delete disks blindly. Task polling is bounded. No rollback, guest deletion, VM start or host network mutation is performed automatically.

## Next implementation and live acceptance

The separate [guest-installation wizard](portable-installation-wizard.md) now adds pinned media preparation/upload and guided isolated console installation. Those operations are not delivered by empty-shell allocation itself. Complete offline recovery packaging and live Proxmox acceptance remain outstanding. Local networking and applications require their subsequent modules before links are enabled.

On a disposable real Proxmox host, acceptance must verify:

1. TLS and least-privilege access, including rejection of untrusted certificates and redirects.
2. Allocation of the six expected blank stopped guests, disks and disconnected NICs.
3. Unchanged management networking and no guest traffic.
4. Identical retry, partial allocation recovery, occupied IDs, permission denial and storage exhaustion.
5. Actual guest OS installation/boot in the later artifact stage.

Record the exact Proxmox version, storage backend, API permissions and evidence. Until these tests run, the implementation remains experimental API scaffolding.

Sources: [QEMU API implementation](https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu.pm), [storage status API implementation](https://github.com/proxmox/pve-storage/blob/master/src/PVE/API2/Storage/Status.pm), [Proxmox API viewer](https://pve.proxmox.com/pve-docs/api-viewer/).

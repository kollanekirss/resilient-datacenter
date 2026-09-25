# Portable crisis node: Proxmox reference architecture

Status: accepted project direction, proposed deployment profile; not implemented by the 0.3 installer. This document records the user's agreed modular topology and the engineering decisions needed to implement it. It extends the earlier Ubuntu service-product scope without changing existing deployments.

## Outcome

An institution prepares a portable node during normal operation, including applications, accounts, certificates, client trust and essential data. During a crisis, staff can cold-start it and work over its local network without contacting an external datacenter, DNS service, identity provider or software repository. When a usable route exists, the node reconnects to domestic infrastructure and exchanges approved services with partners. Changing its WAN address must not require changing application identities.

The first target is one independently bootable physical host per site, not a stretched cluster. Each site's essential VMs and data reside on local storage. An offsite encrypted backup and separately recoverable host address loss of the entire box. Moving the only running host entails interruption; no uninterrupted relocation or automatic failover is claimed.

## Platform and module boundaries

Proxmox is installed on the physical machine. OPNsense is its own guest operating system. The Linux service VMs initially retain the existing supported Ubuntu 24.04 amd64 baseline. Do not install the Ubuntu service package onto the Proxmox host.

| Module | Guest placement | Owns | Must not require for local startup |
|---|---|---|---|
| Edge | OPNsense VM | Routing, DHCP, network segmentation, WAN NAT and firewall policy | WAN availability, external DNS or Headscale |
| Naming | Unbound VM | Explicit local service records; optional recursion/forwarding when connected | A populated external DNS cache |
| Local access | NGINX VM | HTTPS entry points and certificate files; restricted forwarding to application backends | Public DNS, public certificate issuance or partner connector |
| Chat | Ubuntu VM | Synapse, its database/media and Element web assets | Regional partner availability or external SSO |
| Files | Ubuntu VM | Nextcloud, its database/files and required cache/background jobs | Regional partner availability or external SSO |
| Partner connector | Dedicated Ubuntu VM | One regional overlay identity and narrowly approved federation traffic | Local applications must not depend on this VM |
| Institutional applications | Separate VMs | Institution-specific services and their recovery contracts | Dependencies must be documented per application |
| Recovery | Separate physical location plus prepared offline media | Encrypted application-consistent backups and rebuild material | Primary site's credentials, storage or administration service |

Databases initially stay with their owning application. A shared database VM would add a cross-application dependency without a demonstrated need. Element belongs to the chat module even if a later packaging choice serves its static assets at the NGINX frontend. No general-purpose cross-site file/database merge is assumed.

Headscale controllers and DERP relays are infrastructure roles placed independently of the portable node. Institutions retain separate internal networks. Multiple DERPs are not multiple interchangeable Headscale controllers.

## Networks

Use distinct Proxmox bridges and OPNsense virtual NICs initially; VLAN-backed equivalents can follow after separate acceptance. A physical WAN port and physical LAN port are sufficient for this topology. Additional virtual interfaces do not require additional physical ports. A separate switch/access point supplies staff connectivity.

| Zone | Members | Policy |
|---|---|---|
| WAN | OPNsense WAN and physical uplink only | No Proxmox management address on the WAN bridge |
| Management | Proxmox management and designated administrator access | Locally reachable even with the OPNsense VM stopped; no partner access |
| Staff | Prepared laptops/phones and Wi-Fi access point | DNS to Unbound and HTTPS to local NGINX; deny application backend and management access |
| Frontend | Unbound and NGINX | Static local addresses; explicit routed rules to required backend services |
| Applications | Chat, files and institutional service VMs | Backend listeners accept only approved frontend/connector sources; databases remain private to their application |
| Partner transit | Regional connector | Only declared federation endpoints; no broad forwarding to staff or management |

OPNsense routes between zones with default-deny rules and explicit grants. Traffic within the same bridge can bypass its routing firewall: use guest firewall rules and, where needed, separate application bridges to enforce backend restrictions. Merely drawing different VM boxes does not isolate their traffic.

Choose and validate site-specific private subnets. Detect overlaps with the chosen uplink, other site plans and overlay address space before applying configuration. Keep the site's local addresses stable during relocation while the WAN uses the available upstream configuration. Do not treat globally identical preconfigured subnets as a safe default for interconnected institutions.

### Local request path

1. Staff obtain a local address and the Unbound resolver address from OPNsense DHCP.
2. Unbound answers the institution's explicit service records with the local NGINX address.
3. The browser validates the pre-provisioned certificate for the unchanged service hostname.
4. NGINX forwards to the matching backend using authenticated TLS with an explicitly trusted backend CA; it does not disable certificate verification.
5. The application authenticates locally and uses locally stored data.

The service plan must account for client-managed encrypted DNS that could bypass DHCP settings. Document and test device preparation rather than assuming every browser will use Unbound. Static management addressing remains available for repair if DNS or DHCP fails.

### Partner request path

The connector uses the same ordinary WAN uplink through OPNsense to reach coordination, peers and relays. It does not need a second WAN port or a fixed public IP on the portable host. A reachable domestic rendezvous/discovery path is still required.

Retain the existing regional gateway's restricted application federation model, bilateral approvals and expiry/revocation semantics. Give it access to declared federation endpoints only. NGINX is the local user frontend, not an unrestricted bridge between regional and internal users. Do not replace the existing gateway transport/proxy solely to standardize on NGINX.

Remote institutional user access remains a separate, approved internal-overlay path. Partners do not inherit staff access. Local startup must work with both overlays disabled.

## Prepared certificates, identity and time

Obtain public certificates and provision client trust during normal operation. Keep stable service domains and use local DNS answers; moving the WAN address does not change the certificate hostname. Local DNS provides application records, not public issuance authority.

Set an explicit target disconnected duration in the site plan. Before deployment, report whether all required certificates and credentials remain usable for that duration plus a configurable preparation margin. Report actual expiry dates; never hide expiry by disabling verification. This planning check does not extend certificate validity or establish access-revocation guarantees during isolation.

For longer isolation, a separately designed institutional CA profile must preinstall trust, control issuer keys, document renewal/revocation and test the intended client platforms. Public certificate renewal is not an offline recovery prerequisite when valid prepared certificates are available. If validity cannot cover the requirement, the public-certificate profile must report that requirement as unmet.

Prepare local application accounts, emergency administrator access, device software and Matrix encryption recovery material. External SSO may later be optional, but cannot be the only crisis login route. Preserve reliable local time with host RTC and a reviewed local time service; test boot with external time servers unreachable and detect material clock errors.

## Boot, failure and movement

Proxmox boots from local storage with local administrator credentials. Start edge networking first, then naming/time, then applications, then NGINX. Start the partner connector independently after local readiness. Use readiness checks and bounded retry, not sleep intervals alone. Unavailable WAN must never block reaching local-ready state.

Local-ready means a prepared client resolves names, validates TLS, signs in and performs real message/file operations. Partner-ready and recovery-ready are separate statuses. Failure of NGINX or Unbound affects local access and must be visible; VM modularity does not eliminate those single points of failure.

Relocation procedure: verify backup/recovery material; stop writers and shut down cleanly; transport host/router/power kit; connect local LAN and boot; verify local operations; attach the available uplink; verify domestic and partner reachability separately. Preserve one writable authority per service identity. Never start a cloned replacement concurrently with an unfenced original.

## Integration with current code

The current implementation uses per-application Caddy configuration, overlay-bound application access and ingress guards. Adding NGINX in front does not automatically allow LAN clients. Introduce a new explicit portable deployment profile; keep existing installations unchanged until a separately reviewed migration is available.

Relevant integration points:

- `scripts/product_journey.py`, `scripts/product_guide.py`: new platform choice and stage reporting.
- `scripts/service_access.py`, `scripts/service_rendering.py`, `scripts/nextcloud_rendering.py`: explicit frontend/backend contracts; preserve overlay-only defaults.
- `scripts/service_certificates.py`, `scripts/nextcloud_certificates.py`: separate frontend certificates and trusted backend identities.
- `scripts/service_backup.py`, `scripts/nextcloud_backup.py`, `scripts/restore_transaction.py`: include portable access/naming configuration in coordinated recovery without weakening application consistency.
- `scripts/gateway_*`, `scripts/service_link.py`, `scripts/nextcloud_link.py`: preserve narrow regional endpoint rules.

Begin with a fresh-install profile. Do not silently migrate existing Caddy/overlay deployments, reuse unowned VMs, reconfigure a running host's management uplink or overwrite OPNsense policy.

## Acceptance gates

| Gate | Required demonstration |
|---|---|
| Local cold start | Block WAN and external DNS before boot; prepared users perform new chat and file operations with valid TLS |
| Local enforcement | Staff cannot reach databases/management; unknown hostnames and unapproved partner requests are denied |
| Gateway failure | Stop OPNsense; an administrator can still reach Proxmox locally and repair it |
| Changed uplink | Move to a different upstream address; retain service names/data; prove local operation before partner reconnection |
| Offline restoration | Recover to replacement hardware without external repositories or certificate issuance; verify data and identities |
| Partition | Operate independently; reconnect approved federation; no simultaneous writable identity clones |
| Expiry and time | Exercise short certificate validity, expired credentials and clock error; report actionable failure without bypassing trust |
| Physical exercise | Measure whole-kit power runtime, shutdown, transport and recovery with a colleague following the runbook |

Virtual tests provide evidence about software only. Record user count, data volume, disconnected duration, backup age and measured interruption for each physical acceptance run. No capacity or availability promise follows from this architecture document.

## Sources and implementation sequence

Upstream references: [Proxmox networking](https://pve.proxmox.com/wiki/Network_Configuration), [OPNsense virtual installation](https://docs.opnsense.org/manual/virtuals.html), [OPNsense VLANs](https://docs.opnsense.org/manual/how-tos/vlan_and_lagg.html), [NGINX proxy configuration](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [Headscale DERP](https://headscale.net/stable/ref/derp/).

The [delivery roadmap](portable-proxmox-roadmap.md) divides this architecture into separately testable work. The first deliverable is a validated site plan, not an unreviewed script that changes a live Proxmox host.

# Resilient self-hosted services: product design

Date: 2026-09-25. Status: active product scope; implementation and acceptance remain in progress.

This document records the clarified end goal. It does not claim the features below are implemented. Consult README.md and validation-status.md for current implementation and evidence. Disposable Ubuntu service tests do not establish live institutional deployment.

## Product promise

A person with basic computer administration skills can follow the GitHub instructions to install selected self-hosted services, maintain a recovery copy in another location, and optionally connect approved services with partner organisations. They should not need to write Ansible inventories or network access policies for the supported installation paths.

The product must explain prerequisites and remaining dependencies in plain language. Self-hosting reduces dependence on a hosted application provider; it does not remove electricity, connectivity, DNS, certificate, hardware or maintenance dependencies. The product must not promise continuous service during every network partition or automatic recovery from every failure.

## Three installation journeys

### Personal

The user operates a publicly reachable offsite controller and relay, an active service node at home, and a recovery node at another location. Controller and relay are separate logical roles. The conservative tested deployment baseline keeps them on separate machines; a combined small-installation profile requires its own later validation and must disclose its shared failure domain.

The user selects services, names the two locations and chooses a backup destination. The installer provides local installation on each service machine, using outbound network enrollment. Public inbound management SSH is not required at home. It checks supported operating system, available disk, clock, DNS, connectivity and required privileges before changing the machine.

First-release service resilience is active service plus offsite backup and guided recovery, not two simultaneously writable copies. The user can see when backups last succeeded, which destination holds them, and when a restore was last tested. A second server without a verified recoverable copy does not count as protected.

### Institution

The institution deploys an independent network and selects the communications package: a Matrix homeserver with Element and Nextcloud, including their required databases and supporting services. Network membership does not itself create an application account or authorize access to documents and rooms.

The installer guides service domains, TLS, initial administrators, account onboarding, backup ownership and recovery access. Initial local application accounts are supported before optional institutional SSO. Existing identity-provider integration is a separately tested capability; an identity-provider outage must be included in acceptance before claiming resilient login.

The product includes certificate renewal, controlled upgrades, backup/restore workflows, health reporting and actionable errors. Raw successful container/service startup is not sufficient: application login and a real chat/file operation must be tested.

### Regional partner

An institution retains its internal Headscale network for its users. It deploys a dedicated gateway enrolled into the regional operator's Headscale network. The gateway exposes only approved application endpoints through a restricted application proxy to local services. Regional users do not receive unrestricted internal network access.

Baseline gateway design: a separate VM with one regional Tailscale identity, a restricted local connection to service endpoints and no general IP forwarding between networks. If services are reachable only through the institutional overlay, a separately isolated internal connector is needed; that topology is a later gateway sub-design. One ordinary client must not be treated as simultaneously active in both tailnets.

Both institutions approve the partner relationship. Regional network admission and local application permissions are separate. Disconnecting a partner blocks future access but cannot retract messages or files already delivered. The gateway is initially a single failure point and must be shown as such.

The regional network provides shared coordination with independently administered institutions. It is not federation between Headscale controllers and must not be described as fully decentralised control.

## Product structure

| Component | Owns | Must not silently own |
|---|---|---|
| Installer | Validated configuration, installation sequence and clear errors | Cloud purchases or unrelated existing deployments |
| Local network | Internal enrollment and network access policy | Application account permissions |
| Service package | Application identity, database, files and configuration | Another institution's data governance |
| Recovery package | Consistent backups, encryption, restore verification and promotion workflow | Automatic unsafe takeover of an unreachable primary |
| Regional gateway | Approved service transport across the institutional boundary | Full internal subnet routing |
| Status interface | Evidence of service, backup, certificate and partner health | Unsupported claims of protection or successful failover |

Use one reusable deployment engine behind guided installation and advanced configuration. Start with a command-line question-and-answer installer; a web status page follows. Do not require a custom ISO or Proxmox installation. Standard supported Ubuntu machines can run on physical hardware, existing virtualisation platforms or VPSs. Initial executable support remains Ubuntu 24.04 amd64; ARM support must be separately built and tested before advertising Raspberry Pi compatibility.

## Network foundation

Retain the approved independent and join profiles as the next implementation milestone. They establish authority boundaries and reusable configuration. The initial profile implementation can retain reachable SSH management; it must be labelled an advanced/operator path until local installation and the wizard exist.

Add local installation as a separate milestone: users execute the installer on their own machine, explicitly select the intended controller and approve outbound enrollment. Never enable arbitrary `ansible_connection: local` in downloaded inventories. A dedicated local-install entry point must identify the current machine, validate the selected role and use its own constrained execution path.

Private management addresses can be supported for operator-managed deployments once validation distinguishes routable private addresses from prohibited loopback, unspecified, multicast and documentation addresses. Private addresses only work when the operator can reach them; they do not solve remote bootstrap by themselves.

Additional relay locations and tested controller recovery are required before claiming regional resilience. A single offsite controller/relay location remains a dependency even when service data exists elsewhere.

## Service and recovery contract

Implement Matrix/Element first, then Nextcloud. Each package must define:

1. Supported version set and upgrade path.
2. Stable domain/service identity and certificate lifecycle.
3. Persistent data, database, configuration, signing/encryption secrets and media/files that belong in a consistent backup.
4. Backup mechanism, protected destination, retention policy and independent recovery credentials.
5. Restore procedure on a replacement node, including ownership, application schema and certificate checks.
6. A user-visible operation proving restoration, not just a running process.
7. Behaviour when the primary site, identity provider, regional network or internet is unavailable.

First release uses guided recovery with an operator confirming the old primary is fenced off before the replacement accepts writes. A failed ping is not sufficient evidence that promotion is safe. The recovery process must state which backup is being restored, its age and expected data loss window, and preserve the stable application identity where required.

Measure recovery time and recoverable backup age during tests. Do not publish numerical recovery guarantees before those results exist. Do not expose recovery keys to the regional operator by default. Loss of all recovery keys must be explained during setup; the product cannot promise to decrypt backups without them.

Federated application connections are tested separately from restoring a user's home service. Matrix room federation does not automatically migrate a user's account; Nextcloud federation is not automatic replication of the complete installation.

## Beginner-facing installation and operations

The guided flow asks for purpose, installation role, location, domains, account owner, selected services and backup destination. It discovers machine facts where possible, validates answers and shows the intended changes. Secret inputs must not appear in logs, generated public examples or shell history.

For partner setup, it shows the partner identity, requested services and approval status. Unknown or unapproved peers receive no access. Do not interpret an institution label as proof of identity.

Installation output distinguishes installed, awaiting enrollment, awaiting application setup, healthy, backup overdue and recovery untested. Errors include a corrective action that can be followed without understanding Ansible internals. A resume operation continues the same installation without recreating identities.

The repository must include a supported-hardware/software checklist, role diagrams, plain-language installation paths, troubleshooting, upgrade and recovery instructions, a license, contribution guidance, private vulnerability reporting instructions and versioned release checksums. Publication itself remains a separate external action.

## Acceptance scenarios

| Journey | Evidence required before claiming support |
|---|---|
| Personal | Service nodes behind home NAT, no public management SSH, successful install, real service use, encrypted offsite backup and replacement-node restore |
| Institution | Matrix/Element and Nextcloud login and real operations, isolated users, renewal, controlled upgrade, backup and recovery |
| Regional | Two independent institutions, distinct internal/regional memberships, approved service exchange, denied internal administration/subnets and partner revocation |
| Disconnected institution | Internal service operations tested without the regional controller/gateway; external sharing may be unavailable |
| Site loss | Old primary fenced, selected backup restored, identity retained, measured recovery time and data-loss window |
| Beginner usability | A colleague unfamiliar with the project follows only the released instructions and completes setup plus a recovery exercise |

Internet separation can delay partner delivery and offsite backups. Restoration cannot recover changes that never reached the surviving backup. Avoid a universal 'resilient' badge: report these dimensions separately.

## Delivery roadmap

1. Independent/join network profiles and compatibility with the existing pilot.
2. Local installation, home/private-network bootstrap and guided configuration.
3. Matrix/Element package with consistent backup and guided restore.
4. Nextcloud package with consistent backup and guided restore.
5. Regional gateway, bilateral approval and application federation tests.
6. Operator status, lifecycle automation and additional infrastructure resilience.
7. Public experimental release after installation tests; a supported release only after all advertised journeys pass usability and recovery acceptance.

Each service, local-install and gateway milestone needs its own implementation specification and tests. The original profile plan covered milestone 1. Subsequent plans cover guided installation, verified releases, certificate lifecycle and guarded backups/recovery. Matrix/Element, Nextcloud, regional gateways and all journey acceptance remain outstanding.

## Relationship to earlier documents

The 2026-09-25 deployment-profile design remains the technical scope of milestone 1. Its public-management-IP prerequisite is temporary and does not define the finished product's home-user requirements. Its optional HTTPS endpoint remains a networking test, not a substitute for Matrix/Nextcloud recovery tests.

The existing colleague plan and four-VPS kit remain useful background. Where earlier documents imply a complete product from network deployment alone, this document's explicit application and recovery acceptance boundaries take precedence.

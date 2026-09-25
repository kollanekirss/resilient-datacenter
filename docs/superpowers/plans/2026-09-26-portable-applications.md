# Portable applications implementation plan

> Execute inline with superpowers:executing-plans. No subagents in this side conversation.

**Goal:** prepared, separate NGINX/chat/files VMs support local use without an overlay or WAN.

**Architecture:** extend existing application contracts with explicit portable access identity; retain pinned containers and existing recovery safety. NGINX verifies the backend TLS identity at literal LAN addresses.

**Tech stack:** Python, Ubuntu 24.04, systemd, nftables, NGINX, Podman, Synapse/Element, Nextcloud, PostgreSQL.

**Spec:** ../specs/2026-09-26-portable-applications-design.md

## Global constraints

- No vendor server software executes on the preparation Mac.
- No changes to existing overlay defaults or implicit migration of installed nodes.
- No claim of real Proxmox/OPNsense or complete offline rebuild acceptance.
- No external authentication, DNS, certificate issuance or overlay dependency at local boot.
- Fresh dedicated VMs, explicit identity and ownership checks, no foreign firewall replacement.

## Review focus

- Changed LAN address/site fingerprint must reject retry and restored identity.
- An unexpected Host or forwarded header must not select an untrusted backend or client address.
- A reboot must restore ingress restrictions before application exposure.
- Wrong or expired certificates must fail closed, including frontend/backend hops.
- A backup containing portable application state must not revert to peer-only recovery semantics.

## Tasks

### 1. Explicit access contract

Files: new scripts/application_access.py; tests/test_application_access.py; service_contracts.py, nextcloud_contracts.py.

- [x] Define portable identity fields and strict validation, derive from validated site plan.
- [x] Test invalid schemas, unsafe/non-private addresses, equal frontend/backend addresses, changed identity, and preservation of overlay validation.
- [x] Implement profile-to-owner roundtrip without fake enrollment.
- [x] Run focused contract tests and the existing suite.

### 2. Backend rendering and runtime

Files: service_rendering.py, nextcloud_rendering.py, service_runtime.py, nextcloud_runtime.py, service_operations.py, nextcloud_operations.py.

- [x] Test LAN mode listener/source constraints and no tailscaled dependency; retain overlay tests.
- [x] Render Caddy TLS adapters trusting only the fixed frontend; sanitize forwarding headers.
- [x] Parameterize installed units and nft rules through validated access identity.
- [x] Check local address ownership and frontend DNS in installation preflight.
- [x] Refuse unknown resources and identity changes; include access helper in installed runtime manifests.

### 3. Recovery and controlled upgrades

Files: backup_contracts.py, backup_operations.py, backup_snapshot.py, backup_scope.py, service_backup.py, nextcloud_backup.py, restore_runtime.py, application upgrade modules.

- [x] Test portable resources omit Tailscale state/binaries and retain application data and identity.
- [x] Implement LAN restore isolation and local verification with no enrollment wait.
- [x] Include exact access/rendered-config identity in snapshot and upgrade validation.
- [x] Test tampered profile, conflicting identity and pending-restore startup guards.

### 4. Frontend preparation and deployment

Files: new portable application preparation/rendering/runtime modules, CLI routing, wizard integration, examples and operator guide.

- [x] Test plan-derived service profiles, strict local TLS inputs and reproducible output manifests.
- [x] Render dedicated NGINX with literal backend IP, verified TLS/SNI, fixed Host and replaced forwarding headers.
- [x] Add source-restricted host firewall, owned systemd unit and resumable installation.
- [x] Document exact OPNsense rules, local certificates/trust, local accounts and independent encrypted recovery material.
- [x] Exercise CLI/wizard failure output without leaking private key material.

### 5. Actual Linux acceptance and delivery

Files: new scripts/ci_portable_applications.py, workflow, release notes and README.

- [x] Start actual NGINX and pinned application containers on isolated endpoints with no WAN/overlay.
- [x] Verify local message exchange and file upload/download; repeat after cold restart.
- [x] Verify direct-backend, spoofed-header, wrong-Host, untrusted-backend and expired-frontend failures.
- [x] Review the whole diff inline and run the regression workflows; require green PR checks before merge.
- [x] Prepare publication with exact test evidence and remaining hardware acceptance limits.

## Execution record

2026-09-26: implementation uses the existing application modules with an explicit
portable access identity. Matrix and Nextcloud remain separate guests; Caddy is
the backend TLS adapter and NGINX the separate frontend. Module identity is bound
by the application package and derived chat/files node name. No fake enrollment
or Tailscale daemon is used. Portable regional federation remains blocked.

Implemented plan-derived private preparation, wizard step 9, guarded local
application/frontend installers, frontend certificate renewal, ownership/runtime
checks, LAN ingress guards, native restore handling and controlled-upgrade scope.
Startup verifies frontend certificates independently of backend availability;
application health and actual user operations remain separate checks.

Local checks and hosted tests are recorded in the iteration's release notes.
Acceptance exposed kernel firewall declaration ordering, an incorrect Caddy
client-address placeholder, and a restore verifier passing combined ownership to
a network-only contract. Regression tests cover the corrected boundaries. Review
also added full certificate-chain validation at the planned offline horizon and
resumable same-generation frontend renewal.

The hosted fixture runs each package separately with NGINX, staff and attacker
network namespaces. It is not a simultaneous whole-kit test. Its recovery test
uses a native local application snapshot and production restore transaction;
existing encrypted SFTP acceptance remains separate. Portable upgrade ownership
and rollback are tested locally; actual adjacent-version migration is covered by
the existing overlay upgrade workflow. No physical Proxmox/OPNsense host is
connected. Complete offline empty-host rebuild, relocation and partner-path
acceptance belong to the later roadmap stages. Review is inline by the author,
not independent security review.

Both portable component jobs passed at bba8ba8 (run 36195561861). The final local
suite passes 784 tests plus syntax/read-only checks. Publication retains this
exact source evidence; merging is gated on the final PR regression checks.

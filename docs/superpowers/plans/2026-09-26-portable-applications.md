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

- [ ] Define portable identity fields and strict validation, derive from validated site plan.
- [ ] Test invalid schemas, unsafe/non-private addresses, equal frontend/backend addresses, changed identity, and preservation of overlay validation.
- [ ] Implement profile-to-owner roundtrip without fake enrollment.
- [ ] Run focused contract tests and the existing suite.

### 2. Backend rendering and runtime

Files: service_rendering.py, nextcloud_rendering.py, service_runtime.py, nextcloud_runtime.py, service_operations.py, nextcloud_operations.py.

- [ ] Test LAN mode listener/source constraints and no tailscaled dependency; retain overlay tests.
- [ ] Render Caddy TLS adapters trusting only the fixed frontend; sanitize forwarding headers.
- [ ] Parameterize installed units and nft rules through validated access identity.
- [ ] Check local address ownership and frontend DNS in installation preflight.
- [ ] Refuse unknown resources and identity changes; include access helper in installed runtime manifests.

### 3. Recovery and controlled upgrades

Files: backup_contracts.py, backup_operations.py, backup_snapshot.py, backup_scope.py, service_backup.py, nextcloud_backup.py, restore_runtime.py, application upgrade modules.

- [ ] Test portable resources omit Tailscale state/binaries and retain application data and identity.
- [ ] Implement LAN restore isolation and local verification with no enrollment wait.
- [ ] Include exact access/rendered-config identity in snapshot and upgrade validation.
- [ ] Test tampered profile, conflicting identity and pending-restore startup guards.

### 4. Frontend preparation and deployment

Files: new portable application preparation/rendering/runtime modules, CLI routing, wizard integration, examples and operator guide.

- [ ] Test plan-derived service profiles, strict local TLS inputs and reproducible output manifests.
- [ ] Render dedicated NGINX with literal backend IP, verified TLS/SNI, fixed Host and replaced forwarding headers.
- [ ] Add source-restricted host firewall, owned systemd unit and resumable installation.
- [ ] Document exact OPNsense rules, local certificates/trust, local accounts and independent encrypted recovery material.
- [ ] Exercise CLI/wizard failure output without leaking private key material.

### 5. Actual Linux acceptance and delivery

Files: new scripts/ci_portable_applications.py, workflow, release notes and README.

- [ ] Start actual NGINX and pinned application containers on isolated endpoints with no WAN/overlay.
- [ ] Verify local message exchange and file upload/download; repeat after cold restart.
- [ ] Verify direct-backend, spoofed-header, wrong-Host, untrusted-backend and expired-frontend failures.
- [ ] Run existing regression workflows and review the whole diff inline.
- [ ] Publish only with accurate test evidence and remaining hardware acceptance limits.

## Execution record

2026-09-26: inspected current application, backup and restore contracts. Their enrolled-node/overlay dependencies are confirmed; frontend configuration alone cannot meet the spec. Created an isolated branch based on main 66d1e4e. No application runtime code changed yet.

Local checkpoint: the standalone access validator and its rejection tests are implemented. It is deliberately not wired into deployment, runtime, backup or upgrade yet. Task 1 remains incomplete until profile integration and plan-derived identity are implemented. Tasks 2–5 have not been implemented. No portable application deployment or release is claimed.

# Portable Proxmox profile: delivery roadmap

Status: staged engineering roadmap with implementation and acceptance boundaries. Implements the [reference architecture](portable-proxmox.md). Work proceeds in the listed order; each deliverable retains its own evidence and does not imply the later gates passed.

## 1. Site plan and preview

Initial schema validation and a separate CLI preview are implemented: see [usage and limitations](../portable-site-plan.md). Interactive collection and integration into the existing journey remain follow-up work.

Deliver a new optional platform profile without changing the existing Ubuntu journey. Build a pure plan validator and renderer before adding infrastructure mutations.

- Collect site identity, Proxmox endpoint, existing bridge/storage selections, reserved VM IDs, module resources, local subnets/addresses, permanent service domains, backup location, expected offline duration and certificate margin.
- Keep API credentials, certificate keys and recovery secrets out of the shared plan. Store private credential references separately and redact them from previews/support output.
- Validate unique IDs/addresses/domains, subnet boundaries/overlaps, adequate module resources and required modules. Distinguish administrator-provided values from discovered facts.
- Render the VM list, network diagram, firewall matrix, startup dependencies and unresolved prerequisites. A preview must explicitly say that it creates nothing.
- Use new focused modules under `scripts/portable_*` and tests under `tests/test_portable_*`; integrate CLI routing through `scripts/rdc.py` and journey selection only after inspecting their existing interfaces.
- Verify valid plans and rejection of overlaps, duplicate IDs, malformed hostnames, embedded secrets and unsupported schemas. Prove legacy journey output remains unchanged.

Exit: a colleague can describe their intended node and understand exactly what the installer would create. This does not establish Proxmox compatibility.

## 2. Proxmox provisioning adapter

An initial [API checker and stopped VM shell allocator](../proxmox-provisioning.md) is implemented with simulated API tests. It uses existing bridges, allocates blank disks and leaves every guest NIC disconnected. The [guided guest-installation phase](../portable-installation-wizard.md) now adds pinned vendor media, checksum-checked upload and isolated console installation with separate operator attestation. Real Proxmox acceptance and complete offline reconstruction remain outstanding; this stage is not accepted as a deployable crisis system.

Consume the validated plan. Select supported Proxmox/OPNsense versions and immutable installation artifacts at implementation time, verify upstream requirements and record an explicit compatibility matrix.

- Read host storage, bridges and VM allocation using certificate-verified API access with minimum documented privileges.
- Refuse occupied VM IDs, insufficient capacity, unexpected state and unowned resources. Never rewrite the active host management bridge automatically.
- Create only declared managed guests/networks from verified artifacts, persist ownership and progress, and support safe retry after partial failure.
- Produce a recovery inventory containing guest configurations and artifact identities, excluding secrets.
- Test API failures, partial guest creation, repeated runs and ownership conflicts in a disposable environment. Real virtualized guest boot is required beyond API mocks.

Exit: all planned guests boot on an accepted Proxmox version and a repeated apply makes no destructive changes. No services-ready claim yet.

## 3. Edge, DNS and local time

An initial [local network preparation kit](../portable-local-network.md) now provides guided OPNsense configuration, static guest addressing, a guarded separate Unbound/time playbook and client diagnostics. Activation still includes console steps; live OPNsense/Proxmox and full playbook acceptance remain outstanding.

Implement OPNsense configuration and separate Unbound deployment as distinct modules.

- Configure WAN, staff, frontend, application and partner zones with explicit DHCP/DNS/firewall rules. Preserve a locally reachable management path independent of the edge VM.
- Serve explicit local DNS records, restricted recursion and a documented time source. Do not wait for WAN to become usable.
- Back up edge/naming configuration and record the manual console repair procedure.
- Test complete boot with external DNS/time/WAN blocked; test denied cross-zone traffic and administration with OPNsense powered off.

Exit: prepared clients receive correct local addressing and DNS while prohibited paths remain denied.

## 4. NGINX and application backend profile

The [portable local application profile](../portable-local-applications.md) is implemented in development: separate NGINX, frontend-restricted TLS backends, local accounts, profile-bound recovery/upgrades and wizard preparation. Hosted component acceptance is recorded in the release notes. This does not establish combined Proxmox/OPNsense or physical-kit acceptance.

Add a new access profile to the existing application modules rather than weakening their current default.

- Provision NGINX service names and prepared certificate chains; reject unknown hosts and configure required application proxy headers and limits.
- Add authenticated TLS backend listeners limited to the frontend source. Configure Synapse and Nextcloud's trusted proxy/origin behaviour explicitly.
- Serve Element assets locally and remove reliance on external assets for tested user journeys.
- Keep regional federation endpoints distinct from local user access and database interfaces.
- Extend backup/restore and controlled-upgrade contracts to include the selected access profile, configuration and secret handling.
- Run real client operations through NGINX with overlays and WAN disabled. Verify spoofed forwarding headers, untrusted backend certificates, direct backend access and expired frontend certificates fail safely.

Exit: disconnected local cold-start chat/files acceptance passes. Existing overlay-only acceptance must still pass.

## 5. Offline bundle and recovery

- Build a manifest of every required guest image, package, application image, configuration schema and instruction; verify provenance/checksums and redistribution permissions.
- Package public software separately from encrypted private site configuration and backups. Keep recovery credentials independently accessible.
- Add a readiness report covering missing artifacts, backup age, certificate coverage and last successful recovery exercise.
- Restore an empty replacement with WAN denied, including edge/DNS/frontend and application state. Fence the original before activating restored identities.

Exit: complete reconstruction succeeds without external downloads, external sign-in or fresh public certificates. Record time and lost changes.

## 6. Relocation and domestic/partner reconnection

- Exercise moving the complete kit to a different LAN/uplink and validate local operation before enabling remote paths.
- Reuse the regional gateway agreement and endpoint restrictions; test revocation, expiry and partner unavailability with the new access profile.
- Separately design and test authenticated domestic bootstrap-address updates and controller recovery. Multiple relays alone do not complete this requirement.
- Record limitations on partitioned application updates; prohibit simultaneous writable clones of one identity.

Exit: changed-uplink, lost-relay/controller and partner-partition exercises pass within explicitly measured boundaries.

## 7. Operator release

- Provide a short preparation guide, physical wiring diagram, printable offline recovery runbook and versioned hardware planning profiles.
- Have a colleague perform installation, disconnected cold start, relocation and restoration without author assistance.
- Measure power runtime and real workload capacity; publish exact tested versions and failure boundaries.
- Release the portable profile as experimental until these gates have evidence. Keep earlier releases and their documented scope unchanged.

## First implementation boundary

Stages 1–4 have initial implementations with their evidence boundaries above. Stage 5, the offline software/recovery bundle, is the next implementation boundary. Later stages require their own detailed implementation plans because they modify different operational trust and recovery boundaries. Do not combine host provisioning, firewall changes and application migration into one opaque installer action.

No server software is to be executed on the preparation Mac. Linux deployment acceptance runs on disposable Ubuntu infrastructure; Proxmox/OPNsense acceptance needs a dedicated disposable virtualization environment. Unit tests and plan generation may run on the preparation computer.

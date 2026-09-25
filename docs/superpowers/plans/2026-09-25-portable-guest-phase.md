# Portable guest installation phase

Scope: implement the agreed Proxmox wizard through verified media preparation, upload, isolated console installation and observed disk boot. The user delegated the choice of unattended versus guided installation; use guided installation for both guest OS families in this first release. No unattended-install or application-readiness claim.

Implementation runs inline without subagents. Existing portable schema and shell allocation remain compatible. No downloaded guest software executes on the preparation Mac. Live Proxmox acceptance requires an actual test host and is distinct from simulated API coverage.

## Tasks and contracts

1. Media catalogue and preparation: pinned official Ubuntu/OPNsense HTTPS sources and SHA256 values; bounded streaming fetch, checked decompression, local re-verification, atomic private receipt. Reject incomplete or altered files. Tests use tiny substitute artefacts; GitHub-hosted verification downloads real media without executing it.
2. API upload: TLS-verified streaming multipart upload with server-side SHA256 checking; unique generated filename; explicit ISO storage and capacity checks; durable operation record with task ID. Never silently trust an unrelated pre-existing ISO.
3. Guest lifecycle: use existing owned shells, fixed NIC-down policy and config digest checks. Persist intent before mutations. Attach verified ISO, arm installer once, start separately, require operator installation attestation with guest powered off, detach installation media and select disk boot, observe running guest separately. A start request of uncertain outcome is not blindly replayed. No disk deletion, overwrite or network activation.
4. Wizard: `rdc start --platform proxmox` plus resumable portable menu and CLI actions. Prepare/edit site plan, check/allocate, fetch/upload media, select guest and installation action, show recorded and observed state. Credentials remain external private files. Mutating actions name the target and require explicit selection.
5. Evidence and documentation: test failure boundaries, complete local regression suite, real-media download verification in hosted Ubuntu, operator guide and exact limits. Live Proxmox and OS console installation remain NOT RUN without a host.

Shared interfaces: catalogue -> prepared media receipt binds SHA256/size/name; upload -> remote receipt binds endpoint/node/storage/volume/task; lifecycle -> wizard reports states without inferring OS identity from a running VM. Site plan hashes bind every saved journey and VM marker.

Review focus: uncertain POSTs and power loss; existing disks and foreign markers; credential disclosure/redirects; stale or corrupted receipts; claiming OS/application readiness from a running VM. Each is covered by refusal/state tests and explicit documentation.

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

## Execution evidence and review

Implemented tasks 1–5 as the guided console workflow selected after the user delegated the installation-method choice. Unit tests were run failing before each new module/CLI boundary and then passing. Final local verification: 703 tests and all Ansible syntax/read-only task checks passed. No live Proxmox host was available; the code is not represented as a live-accepted deployment.

Author review (subagents prohibited in this side conversation) found and fixed misleading no-change completion wording, malformed progress records and stale catalogue receipts. Each behaviour has a regression test observed failing before its fix. Other protective tests exercise uncertain start/upload responses, partial configuration response loss, network drift, foreign ownership and disk-only login attestation. A transient syntax error introduced during the review edits was caught and fixed before the final suite.

Ruling: use guided console installation for both OPNsense and Ubuntu rather than claim unsupported unattended provisioning. Cost: an operator must complete each installer and attest console login. This matches the user's delegated preference and is explicit throughout the UI and documentation.

Ruling: checksum trust is rooted in the reviewed repository catalogue sourced from official HTTPS metadata; vendor signature verification is not claimed. Cost: catalogue updates require review and a trusted project revision.

No unresolved important findings from the author review. Live platform acceptance, guest boot and the subsequent network/service phase are outstanding external/scope gates, not passing checks inferred from unit tests.

Final refusal-path review also caught implicit adoption of an attached installer when its local guest journal was missing. A failing regression reproduced that case; attachment now requires the matching previously recorded intent. This prevents a missing journal from reopening a prior installer session. The full suite passed 703 tests after the fix. Hosted real-media verification passed in run 36177734261; live Proxmox remains NOT RUN.

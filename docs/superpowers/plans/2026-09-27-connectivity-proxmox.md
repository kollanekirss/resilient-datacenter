# Connectivity Proxmox inspection and shell provisioning

**Goal:** connect the separate wizard to real Proxmox API operations while keeping guest installation/network activation outside this increment.

**Design:** use the approved connectivity plan, not the six-VM application layout. Create four base roles (edge, naming/time, partner gateway, test target), plus only coordinators/relays selected for local placement. Select a VM ID range and verify a declared independent Proxmox management address. All created guests are stopped, autostart-disabled and NIC-disconnected.

**Constraints:** preserve private schema-v1 planning records; separate runtime settings/evidence. No bridges, existing guests or services are modified. Do not download images, start installers or claim useful connectivity. Missing bridges on a clean host are a visible prerequisite, not something silently repaired. Every operation shows its target and effects. API token values remain outside records and output. Use TLS-verified transport and the lab-feedback permission diagnostics.

## Implementation

1. Add `connectivity_provision.py`: deterministic role-specific shell settings/payloads bound to the full plan; read-only prerequisites; reuse strict owned-shell checks and bounded task polling. Check Proxmox 9.x, all four visible active bridges, no host address on WAN, declared management address on its bridge, storage, free RAM and visible VM conflicts.
2. Add `connectivity_operations.py`: private provisioning settings, durable per-VM intent/task/observed records, workspace locking, explicit preview and confirmations. A POST with an unknown outcome remains blocked if the VM cannot be observed; do not automatically resubmit. A known task can be polled, and a complete owned stopped shell can be reconciled. Fresh preflight is required before each allocation run.
3. Integrate host-check/allocate/save-exit checkpoints into `connectivity_wizard.py` after planning and on resume. Startup still performs no remote action. Private credential paths are requested only after the user selects an operation; only an explicit allocation confirmation permits POSTs. Show timestamped historical evidence separately from fresh checks.
4. Reuse the bounded HTTP status/allowlisted-privilege diagnostics from PR #28. Do not pull in unrelated application workflow changes.
5. Update docs to distinguish available shell provisioning, remaining manual bridge prerequisites and missing OS/network adapters. Add tests for role selection, resource/routing boundaries, invalid API results, ownership conflicts, partial/uncertain allocation, stale settings, cancellation and no unrequested network access.

## Verification

Observe new tests failing before implementation. Run focused tests, then the full local-check command. Have an independent reviewer inspect the remote mutation boundary and resume behavior. Publish a stacked draft PR against the connectivity foundation branch. Real-host acceptance is not performed without an available authorized lab connection; simulated API tests must be labeled accordingly.

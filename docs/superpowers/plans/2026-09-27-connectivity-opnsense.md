# Guided OPNsense installation checkpoint

Continue the approved connectivity-first architecture (stage 2), following PR #30. Keep the existing private plan and allocation records. Add a separate guest journal under the same workspace lock; never translate the connectivity plan into the legacy application layout.

## Scope

Reuse pinned `guest_media` preparation and bounded verified Proxmox upload transport. Add a connectivity-bound upload receipt and an OPNsense-only state machine. Each action requires a preview and explicit confirmation: prepare media, upload, attach, start installer, finish installation, boot disk, attest console login. Read-only status remains available. Installation uses the vendor console installer; version and login are operator-attested, not automatically verified. All NICs stay disconnected, no services or Linux guests are installed here, and no certificate or network readiness is claimed.

## Safety and resume

Require the saved allocation settings and verified edge allocation record. Bind guest state to those settings and the pinned media. Write the journal before any remote mutation; retain task IDs. Poll known tasks before inspecting state. Unknown upload or start outcomes cannot be replayed. Unknown configuration updates may reconcile only when their intended exact configuration is observed, otherwise block. Use the server configuration digest when attaching/removing media. Never stop guests, delete volumes or repair unrelated state automatically. Missing/symlinked records fail closed. Once guest progress begins, the shell allocator directs the operator to the guest checkpoint instead of claiming blank shells.

## Steps

1. Test and implement bound upload preparation/receipts with durable uncertain-outcome handling.
2. Test and implement attachment, start, console completion, disk boot and login attestation. Inspect exact ownership, disconnected links, boot source and power state; keep truthful checkpoints.
3. Wire a separate `opnsense` submenu into the connectivity wizard, with instructions and explicit per-action confirmations. Preserve scope-first startup and save/exit behavior.
4. Update documentation and current capability text, run the complete local checks, obtain an independent review, fix findings, and publish a stacked draft PR against PR #30.

## Acceptance limits

Use simulated API regressions here. No lab server was provided. Production acceptance still needs a real Proxmox host and console installation. Linux roles, OPNsense policy, publicly trusted endpoint certificates, coordinator/relay configuration and activation of both overlays remain subsequent work.

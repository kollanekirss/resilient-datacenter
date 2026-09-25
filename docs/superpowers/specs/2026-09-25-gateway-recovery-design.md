# Encrypted gateway recovery design

Status: implementation contract under the existing goal mandate, not acceptance evidence. This refines the recovery section of the gateway lifecycle design.

## Owned backup scope

Treat the dedicated gateway as a third explicit backup package alongside chat and files. Its immutable backup owner binds the local network manifest, signed gateway identity and original private-LAN profile. Store an owned marker during gateway installation. A network-only backup must refuse to imply the installed gateway is protected; the operator explicitly adds the gateway with the existing `backup include-services` command.

The fixed resources are the existing network identity/state, `/etc/rdc-gateway`, and `/var/lib/rdc-gateway-recovery`. The recovery directory is root-only and is never mounted into Envoy. Consistent capture holds the backup lock and gateway lock, stops the periodic guard/proxy before the network daemon, preserves numeric ownership, and restarts before encrypted upload. Refuse capture during pending policy, TLS or disaster-recovery review.

Immediately before capture, refresh the separate recovery directory from the owned optional certificate issuer: its bounded configuration/credential files and Certbot account/lineage. Validate the issuer belongs to the same network, institution approval fingerprint and exact service names. If no issuer exists, record that fact. Do not copy arbitrary scripts, hooks or executable runtimes into a recoverable execution path. The archive is encrypted by the normal backup transport and is never automatically executed or installed. The institution approval signing key stays offline and is not part of gateway backup.

Use existing fixed runtime/component hashes for compatibility, extended with the gateway catalogue and unit/guard bytes. Include the gateway backup adapter in the frozen scheduled-backup runtime and test its isolated dependency closure.

## Promotion and retained settings

Reuse the existing snapshot selection, age display, explicit old-primary fencing, journaled directory replacement and guarded restore. The replacement must already have the same reviewed component versions, signed identity, private-LAN configuration and a currently verified certificate. Different gateway addresses or institution keys require a newly signed identity and agreements, not edits to old signatures.

Preserve the replacement's live TLS generation and active issuer/account configuration. A historical certificate may have expired or been revoked, and an old issuer account may no longer be authorized. Keep archived old issuer recovery material private and available for an explicit operator recovery step; it must not replace the running issuer silently. This follows the existing controller/application restore rule that verified replacement certificates are retained.

Before any restored service starts, write a durable recovery-review marker outside the replaced directories at `/etc/rdc-gateway-recovery.json`. It records the pinned fingerprint, restore transaction and a monotonically increasing approval time floor. Keep it through rollback and reboot. Merge any revocations known by the replacement into the restored catalogue, preserve increasing state generation and clock history, and discard derived proxy configuration so runtime rebuilds it from verified state.

The gateway may start behind closed transport for local TLS and ownership verification. The generic restore validation permit authorizes this verification only; it cannot authorize partner access. Startup, the periodic guard, policy changes, certificate activation and status must all honor the recovery-review boundary.

## Reopening a recovered gateway

An old backup cannot establish that no partner was revoked after it was captured. Until review, no regional traffic opens. Require newly issued and accepted bilateral agreements at or after the recovery floor; preserve historical revoked identifiers. Use the existing explicit local policy-apply workflow, displaying the recovery state and rejecting pre-recovery agreements with an actionable error.

The reviewed policy is journaled before the recovery marker is changed. A crash during review therefore remains covered by the pending policy intent. The explicit transition can then verify and open only the current fresh approvals. Keep the time floor permanently after review so replaying an older signed agreement cannot reopen access later. Empty policy may leave the gateway deliberately disconnected; it grants no partner access.

Certificate renewal can still succeed while partner recovery review is pending, but must leave transport closed. No command may clear recovery review simply because a process is running.

## Acceptance

- Offline contracts reject mismatched network/profile/identity, unsafe backup links, unknown files, missing revocation state, altered issuer ownership and incomplete component compatibility.
- Actual locks prove capture cannot overlap gateway policy or certificate changes.
- Restore of an old snapshot preserves a later locally known revocation, retains current TLS and records the review floor. Restart/guard deny old agreements before and after recovery review.
- Inject restore and policy-review interruption; neither opens historical partner traffic.
- Disposable Ubuntu uses actual encrypted Restic/SFTP capture and the installed scheduled runner, restores the selected snapshot through the guarded transaction, verifies the retained served certificate, and demonstrates denied old approval plus allowed freshly signed approval. Its synthetic transport fixture is labelled separately from actual-network federation acceptance.
- Public provider credentials, independently reachable real backup storage and physical-site/colleague recovery remain external acceptance items. The test cannot claim those were exercised.

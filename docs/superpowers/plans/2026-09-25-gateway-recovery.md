# Gateway encrypted recovery implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. No subagents. Continue under the existing goal mandate.

**Goal:** Capture and restore owned regional gateways without reviving stale partner permissions.

**Architecture:** Extend the fixed backup package catalogue with a gateway adapter, keep optional issuer recovery material outside Envoy's mount, and retain a permanent recovery approval floor outside swapped data directories. Reuse Restic/SFTP, snapshot compatibility, explicit fencing and the existing restore journal.

**Tech Stack:** Python, existing Restic 0.19.1 transport, systemd, nftables, fixed gateway runtime.

**Spec:** `docs/superpowers/specs/2026-09-25-gateway-recovery-design.md`.

## Global constraints

- Only disposable GitHub-hosted Ubuntu may execute server/network acceptance.
- Lock order is backup then gateway; guard remains nonblocking.
- Preserve exact signed identity, revocations and current replacement TLS.
- Archived issuer credentials are private data, never an executable restore target or proxy mount.
- Pending recovery remains closed across restart, rollback and certificate renewal.

## Review focus

- Old snapshot predates revocation: merge current revocations and require fresh bilateral approval (tasks 1,3).
- Snapshot contains linked or injected runtime files: strict owned data catalogue, regenerate proxy configuration, keep code compatibility checks (task 2).
- Certificate renewal during recovery review: permit TLS maintenance but keep partner access closed (task 1).
- Runtime lock inode changes when directories swap: external durable recovery marker guards every opening path independently (task 3).
- No issuer or interrupted issuer installation: record absence; reject incomplete/foreign configurations without silently dropping recoverable credentials (task 2).

### Task 1: Persistent recovery review boundary

Files: `scripts/gateway_store.py`, `scripts/gateway_transition.py`, `scripts/gateway_runtime.py`, `scripts/gateway_certificates.py`, new `scripts/gateway_recovery.py`; tests for Store, transition and certificates.

- [ ] Add failing real-file tests: old approval cannot yield peers after a floor, fresh bilateral approval can be explicitly reviewed, the floor survives review, revocation remains permanent, malformed marker rejects operation.
- [ ] Implement `Store.recovery()`, `recovery_pending()`, floor filtering and candidate rejection. Recovery marker path is `store.base.parent/'rdc-gateway-recovery.json'`; validate exact fields and pinned fingerprint.
- [ ] Implement `review_recovery(candidate)` only for the matching committed durable policy intent. Call it after verified restart and before opening. A failure retains policy intent and closed transport.
- [ ] Check recovery in startup/guard/open. Certificate `Runtime.reopen()` leaves the boundary closed when review is pending. A generic restore permit only allows closed startup validation.
- [ ] Run local suite and native gateway regression before calling the boundary accepted.

### Task 2: Fixed backup package and consistent capture

Files: new `scripts/gateway_backup.py`, `scripts/gateway_backup_runtime.py`; modify `backup_scope.py`, `backup_contracts.py`, `backup_snapshot.py`, `backup_schedule.py`, `gateway_operations.py`.

- [ ] Add failing owner/resource/unsafe-data tests and an isolated scheduled-runtime import test.
- [ ] Define gateway backup owner with schema, package, network, signed identity and original profile; install its immutable ownership marker and private `/var/lib/rdc-gateway-recovery` directory. Reject network-only scope when the gateway is installed.
- [ ] Add fixed paths, service order and binary/unit catalogues; adapt runtime image/container/readiness checks through the gateway adapter.
- [ ] Capture under gateway lock while the existing outer backup lock blocks issuer changes. Refuse pending policy/certificate/recovery. Refresh only validated optional issuer data into the private recovery archive, then use existing consistent capture and restart-before-upload.
- [ ] Freeze complete dependencies and preserve prior known backup runtime catalogues. Extend `backup include-services` with exact identity preservation and protected scheduler refresh.
- [ ] Run the full suite; commit the independently testable snapshot scope.

### Task 3: Guarded restore and issuer recovery material

Files: `gateway_recovery.py`, `gateway_backup.py`, `restore_transaction.py`, `restore_runtime.py`, `gateway_operations.py`; restore contract tests.

- [ ] Add failing tests for retained fresh TLS, union of revocations, increasing generation/clock and permanent floor after old snapshot restoration.
- [ ] Write recovery marker before candidate data can start. Prepare gateway candidate by merging later revocations, retaining replacement TLS and dropping derived proxy files; preserve private numeric permissions and constrained TLS links.
- [ ] Allow closed gateway readiness under the verified restore permit; never clear recovery review through normal process readiness. Keep marker on rollback and failed promotion.
- [ ] Expose reviewed status/next actions and an explicit private export of archived DNS token for re-issuance. Never print token content or replace active issuer configuration.
- [ ] Exercise failure/interruption locally and preserve the generic restore journal guarantees for existing packages.

### Task 4: Actual encrypted acceptance and documentation

Files: disposable gateway fixture plus a bounded backup helper, GitHub workflow if additional packages required, `docs/regional-gateway.md`, `docs/backups.md`, validation ledger.

- [ ] Prepare actual pinned SFTP/Restic transport with a clearly labelled network stub. Run the installed scheduled gateway backup and check the encrypted snapshot scope.
- [ ] Record a later revocation, restore the selected older snapshot through the actual journal/firewall transaction, verify retained TLS and closed historical approvals, then apply a freshly signed agreement and verify allowed fixture application traffic.
- [ ] Run restart/guard and injected recovery failures, report measured restore duration and backup age, and prove archived issuer secrets remain outside Envoy's mounts.
- [ ] Inspect the current-source native jobs, fix real failures, update beginner recovery instructions and perform an author review. Actual Headscale federation remains separately tested; real-site and colleague acceptance are not claimed.

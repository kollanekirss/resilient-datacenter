# Controlled application upgrades

Date: 2026-09-25. Refines the approved product goal and completion-ledger item 9. The user explicitly authorized implementation through the goal without milestone approval pauses. Execute and review inline; no subagents and no deployment runtime on the developer computer.

## Purpose and choices

Institution operators need a repeatable update procedure that preserves application identity and recoverable data. Personal and regional operators need the same maintenance path without granting the shared network operator access to backups. The operator chooses an explicit maintenance window; this is not unattended updating or zero downtime.

Three approaches were considered: arbitrary image tags are too broad to establish compatibility; simply restarting the old image after database migration can corrupt data; a reviewed adjacent-version catalogue with a stopped-service backup and journalled promotion can establish a bounded support claim. Choose the last approach. It extends existing pinned containers, private backup credentials and guarded restoration instead of creating another package manager.

## Initial version transitions

Verify exact linux/amd64 image/config digests from the upstream registries. Initial acceptance paths are Synapse 1.160.0 to 1.161.0 (the other Matrix components unchanged) and Nextcloud 35.0.0-apache to 35.0.1 (PostgreSQL 17.11 and the proxy unchanged). The older versions are migration source fixtures, not new-install defaults. New installations continue to use the current reviewed images. PostgreSQL major upgrades, arbitrary skipped versions and unreviewed third-party Nextcloud apps remain rejected.

A strictly validated predecessor catalogue permits identifying, backing up and restoring only those exact prior image sets. It does not accept arbitrary ownership changes. Package identity, institution, node, domains, network, signing identity, database credentials and file identity stay fixed across an upgrade. Current fresh-install/resume remains strict; an older package must use the explicit upgrade flow.

## Operator interface and preflight

Add `rdc upgrade check`, `rdc upgrade apply` and `rdc upgrade recover` for the owned local application, plus guide entries. Check discovers the owned Matrix or Nextcloud package, verifies the exact installed runtime and catalogue, names the supported target and identifies blocking prerequisites. Already-current is a no-change result. Check never pulls, restarts or edits configuration.

Apply requires local root administration, the reviewed backup scope, independent recovery credentials, available encrypted storage and adequate space for backup staging and retained recovery material. Pull and validate only target digests before service downtime. Require explicit confirmation of the node, source/target version and maintenance interruption. Keep the existing backup-first application lock; certificate issuance, connectors, account operations and scheduled jobs must not race the transaction.

## Transaction boundaries

Persist a private upgrade journal and a durable startup-blocking marker before modifying application state. Reuse the owned restore startup/isolation mechanisms wherever their contracts remain intact; never disguise an upgrade journal as an ordinary restore journal. Ordinary backup/restore/application actions report the upgrade-specific corrective action while it is pending. Only the explicit upgrade engine may capture its own stopped-service snapshot under that marker, with the expected transaction identity checked.

Stop all application writers and cron before the pre-upgrade snapshot, keeping the previous application data unchanged until an encrypted upload and verified download have succeeded. The snapshot must include the full application scope and exact old component identities. Do not allow user writes between this snapshot and isolation. Staging/pull failure before migration may restart the unchanged old service; no migration is claimed.

Retain the original installed runtime/catalogue bytes and required application source tree privately. Candidate image/catalogue and Nextcloud code change only on the allowlisted paths. Enter the same scoped isolation used for restore, keep regional connectors suspended, permit candidate startup for verification, and perform the package-specific migration. Nextcloud uses a fixed private maintenance entry point with writable staging configuration only; secrets never enter OS arguments or logs. Synapse performs its supported database migration at startup. Do not change the PostgreSQL major version.

Before publication, verify actual pinned backend versions, database/service readiness and trusted HTTPS. Persist `committed` before releasing ingress. After commit, recovery finishes the current version and never automatically restores older data: users may already have written new data. Refresh the owned backup scope and frozen scheduled runtime for the new catalogue; retain history and credentials. Require a new current-version backup and real user operation after successful promotion.

Before commit, failure restores original runtime/code/catalogue and the complete quiesced pre-upgrade database/configuration/files through the guarded restore path. Never run the old application against a migrated database. The upgrade journal must record rollback commitment before restore isolation is released, preventing a crash from causing a second stale rollback after users regain access. Interrupted recovery resumes the exact owned transaction; unknown journal fields, foreign state and changed binaries block automatic action.

## Evidence and boundaries

Unit/file fixtures cover unsupported versions, owner changes, stale/missing/full-scope backups, journal validation, failure before migration, failure after migration, interruption, rollback commitment and post-commit refusal to revert. Disposable GitHub-hosted Ubuntu acceptance installs each exact predecessor, creates real users/messages or files, performs the actual upgrade, verifies version and data, and injects a failure to verify complete old-data/code recovery. It also verifies a post-upgrade backup and same-version restore. The main browser/service tests remain necessary and do not get replaced by mocks.

No old-version image runs on the developer computer. CI predecessors are short-lived fixtures. Successful CI is bounded upgrade evidence, not physical site resilience, public provider issuance or unfamiliar-colleague acceptance.

## Upstream references

- [Synapse upgrades](https://element-hq.github.io/synapse/latest/upgrade.html): review each version's migration requirements and supported dependencies.
- [Synapse backup recovery](https://element-hq.github.io/synapse/latest/usage/administration/backups.html): clear restored one-time keys before starting chat; preserve signing identity and media.
- [Nextcloud upgrades](https://docs.nextcloud.com/server/stable/admin_manual/maintenance/upgrade.html): maintenance interruption, fresh backup and no database downgrade.
- Official registry manifests queried on 2026-09-25: ghcr.io/element-hq/synapse:v1.160.0 linux/amd64 sha256:f113a71cfa9a4900002255983efedf2973875f9ce8d79ee2987f7f05864f0c6b, config sha256:46541738701e24e221c45603d9518b83282acb0c1c3a9245874760f6755b915c; docker.io/library/nextcloud:35.0.0-apache linux/amd64 sha256:e594a5d68fa32d4b16686a60e0beb39c55766de776338ba03761e9e7ca22a740, config sha256:cd80445714fe772a0093f55ca339d36b60e537f0138fe38d36198b40a76fbb35. Verify these again in the native fixture before use.

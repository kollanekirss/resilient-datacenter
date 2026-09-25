# Controlled application upgrades

This development feature has passed the bounded disposable acceptance described below. It supports explicit reviewed transitions, not arbitrary container tags, unattended updates or database major-version jumps. Do not use it for production until the corresponding released source and acceptance evidence are published.

The tested transitions are Synapse 1.160.0 → 1.161.0 and Nextcloud 35.0.0 → 35.0.1, using the exact reviewed linux/amd64 component sets and helper contract. PostgreSQL and companion components remain at their pinned versions. These predecessor versions are migration fixtures; fresh installations always select the current package. Imported installations and other helper revisions are refused.

## Operator sequence

1. Run `./rdc upgrade check` with local administration privileges on the chat or file-service VM. It reports the current and proposed versions and any missing prerequisites. If already current, it changes nothing.
2. Verify that independent recovery credentials are available and that a full application backup no more than one day old can be reached. Network-only snapshots are insufficient. Make space for a complete candidate copy and encrypted snapshot staging. Read the exact version's upstream release notes.
3. Choose a maintenance window. Run `./rdc upgrade apply` and review the named node and versions. The command requires typing `UPGRADE NODE-NAME`. It pauses the application, uploads and verifies a fresh encrypted snapshot, retains the untouched original directories and migrates a copied candidate behind an ingress block. Chat/files will be interrupted; there is no universal completion-time guarantee.
4. If candidate migration or verification fails, the operation restores the exact retained original code and data. If interrupted, keep the same reviewed checkout and run `./rdc upgrade recover`. Do not delete pending markers, replace the database by hand or start an older image against a migrated database.
5. Once committed, the operation publishes the new version and takes and verifies a new-version encrypted backup. A failure after commitment leaves recovery pending at the new version; recovery preserves newly accepted writes and finishes the backup/cleanup. Old-version snapshots alone do not satisfy successful upgrade completion.
6. Run `./rdc status`, log in and perform a real message or file operation. Check backup age and perform a separate current-version restore exercise. Previous partner connectors stay suspended for review; export/attach fresh links appropriate to the current application owner before resuming exchange.

The upgrade record's selected snapshot is the **pre-upgrade** recovery point. After a completed upgrade, ordinary backup status reports the most recent current-version snapshot. Neither a service verification record nor an exit code replaces a real user-operation check.

## What remains stable

Node/controller membership, service domains, local users, database credentials, Matrix signing identity, Nextcloud instance identity and existing files/messages are preserved. Certificates remain outside the application directory swap. Repository credentials and backup history remain intact. A previous frozen backup helper directory may be retained privately under the upgrade records when moving to a reviewed helper version; this is not automatic snapshot pruning.

Only the upgrade engine can create a snapshot under its own preparing or committed maintenance marker. Ordinary backups, account administration, certificate activation and background file jobs remain guarded while maintenance is pending. A reboot must not start a partially promoted package.

The disposable test uses actual old/new applications, PostgreSQL and encrypted storage, plus a separate network namespace to verify closed ingress during migration. Its VPN daemon is explicitly synthetic. That evidence does not cover physical sites, provider issuance, third-party Nextcloud apps, arbitrary legacy installations or a PostgreSQL major upgrade.

Acceptance at source `a9ffb77`: [run 36163148509](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36163148509) passed both packages, including failed candidate migration recovery, interruption, post-commit write preservation, and new-version encrypted backup/restoration. Consult the current commit checks for subsequent changes.

# Peer recovery bootstrap implementation

Use executing-plans inline; no subagents. Existing user authorization covers continued product completion. Never run server/network workloads on the developer computer.

1. Add failing file-only tests for full owned application snapshot to narrow network stage, incompatible binaries, foreign identity/package, linked data and an already installed application. Implement the constrained derivation in `scripts/backup_bootstrap.py` using existing snapshot validation/copy contracts.
2. Add private bootstrap stage/plan/apply entry points and CLI parsing. The existing backup operation lock surrounds mutation; apply revalidates the source and derived scope and reuses `restore_transaction` with explicit fencing. Standard restore-recover remains the sole journal recovery path.
3. Exercise interrupted narrow restore in local tests. Add actual SFTP/Restic bootstrap preparation and journal promotion to the disposable gateway fixture with its network stub explicitly labelled. Verify that the original full snapshot remains available for the later full restore.
4. Extend real Headscale client acceptance to show original client key/address survive restoration after the old process is fenced. Keep this distinct from full application recovery and physical offsite acceptance.
5. Document the two-stage replacement sequence and known limits, inspect native results, fix failures and review before merging the regional increment. Do not call the fresh replacement path accepted from a same-host restore alone.

# Encrypted backups and guarded recovery

This experimental workflow protects the kit's Headscale controller, DERP identity or enrolled networking client. The development source can explicitly extend an enrolled node’s backup scope to the [Matrix package](matrix-services.md#add-chat-to-encrypted-backups), including its database, media and signing identity. It does **not** yet protect Nextcloud or arbitrary directories. Existing network-only snapshots do not become application backups. It briefly stops the owned service to make a consistent private local copy, restarts it, then encrypts and uploads the copy using pinned Restic 0.19.1. Allow local free space for that copy. During recovery, allow additional space for both the candidate and previous data.

The commands below run on the relevant **Ubuntu 24.04 amd64 server**, from a project checkout with its dependencies prepared. `sudo ./rdc` uses that checkout's Python environment. Keep administrative access independent of the network being recovered: provider console, local console or a separately managed SSH connection. Restoring a client can interrupt an SSH session carried by that client; use the independent connection.

## 1. Choose separate storage

Use storage in another location and failure domain. Different machines in one building are not evidence of offsite protection. Keep recovery access outside both the source service and its backup location. Losing the repository password makes encrypted data unrecoverable.

The guided storage target is a dedicated, already enrolled local node. It listens on its private overlay IPv4, TCP 2222, with a separate SFTP daemon and one authorized writer. It does not change the machine's normal SSH daemon configuration. On that target:

```sh
sudo ./rdc backup target prepare /absolute/path/node-storage.yml
```

Save the returned endpoint, port and **public** SSH host key. Verify these directly with the storage administrator; accepting an unverified key defeats host authentication. Use the [guided access workflow](operations.md#approve-a-device-to-service-connection) to authorize only the intended writer to the storage node’s `backup` service (TCP 2222), then apply the reviewed inventory. Merely joining the same network does not grant access.

The offsite controller and relay in the infrastructure-only deployment are not overlay clients. They cannot reach this private storage endpoint automatically. Their administrator must provide a separately reachable SFTP endpoint with the same dedicated user `rdc-backup`, chroot layout `/data`, Ed25519 key authentication and independently verified host key. This release does not silently enroll infrastructure machines or expose the guided storage daemon publicly.

Each guided target initially supports one writer. Storage can be deleted by that writer, so encryption alone does not provide ransomware resistance. Independently retained, access-separated copies and storage immutability are separate operational requirements; they are not implemented by this target.

## 2. Prepare source settings and access

On the source, run:

```sh
./rdc backup setup --output-file /absolute/private/path/backup.json
sudo ./rdc backup configure /absolute/private/path/backup.json
```

The wizard asks for institution/node names, installed role, storage host/port and verified public host key. It never asks you to put passwords or private keys in a profile. Configuration verifies the local ownership marker, creates a repository password and dedicated SSH key under root-private `/etc/rdc-backup`, verifies the pinned Restic download and installs startup guards for interrupted recovery. It does not initialize storage or take a backup.

Give only `/etc/rdc-backup/ssh_key.pub` to the storage administrator. On the guided target, authorize its transferred public file:

```sh
sudo ./rdc backup target authorize /absolute/path/source-public-key.pub
```

Place the repository password and emergency storage access in an independent recovery store. Save the generated SSH private key too if you will use the import workflow below. These secret files belong in a protected recovery store, never GitHub, a support report or chat. Retain the profile, exact project revision, component artifacts and installation configuration needed to rebuild the same identity. The profile contains infrastructure details and should remain private even though it has no secret key.

## 3. Initialize and take a backup

```sh
sudo ./rdc backup initialize
sudo ./rdc backup run
sudo ./rdc backup status
```

Initialization requires an interactive acknowledgement that independent recovery access is saved. It refuses to overwrite an existing repository. The backup command reports success only after receiving a complete snapshot ID. Status shows the latest snapshot's age and explicitly distinguishes a snapshot from a verified recovery. No automatic retention or deletion is installed. Scheduling is a separate opt-in action below.

After a successful manual snapshot, optionally enable a schedule:

```sh
sudo ./rdc backup schedule enable --frequency daily
sudo ./rdc backup schedule status
```

Choose `daily` (02:00 UTC) or `hourly`, with up to ten minutes of randomized delay. Enabling a schedule authorizes the same brief owned-service pause on each run. A missed timer event catches up after the server returns; this is not a guarantee of backup completion during an outage. The installer prepares required Ubuntu Python library packages and copies the backup program into private, root-owned `/opt/rdc-backup-runtime`. It does not execute a mutable home-directory checkout later. Runtime hashes and ownership are checked before each run; fetching newer project source does not silently update this installed copy.

`backup status` shows timer state, last scheduled attempt and last scheduled success, along with the remote snapshot age. Failed attempts preserve the earlier success record. It reports overdue after the selected interval plus a 30-minute grace period; this threshold is a warning, not a recovery-point guarantee. An unreachable repository is reported as unverified, never fresh. No external alert recipient is configured automatically. Check status routinely and include it in the institution's existing monitoring.

To stop future scheduled runs:

```sh
sudo ./rdc backup schedule disable
```

An already-running backup is allowed to finish. Enabling the same schedule resumes it. This experimental version refuses to replace an existing schedule with a different frequency or to overwrite its installed runtime; controlled schedule/runtime changes require a later maintenance path. No snapshots are pruned automatically, so capacity monitoring is essential.

A successful upload is not evidence that an application can be recovered; perform the recovery exercise below with disposable data first.

## 4. Prepare a replacement and stage recovery

Deploy the **same supported role, institution identity, hostname and exact component binaries** on a replacement. Keep it isolated from normal users while preparing it. Arrange fresh, valid certificates and its own current routing settings. Managed recovery retains the replacement's ACME account and certificate generations. It restores persistent identity/data and authorization policy, while retaining the replacement's service configuration and relay map. This supports the kit's generated configuration; custom service configurations require a separate migration review.

Make the saved password and private SSH key available as absolute, root-owned, mode 0600 files through your independent recovery procedure. Import them on the replacement:

```sh
sudo ./rdc backup configure /absolute/private/path/backup.json \
  --recovery-password-file /absolute/private/path/password \
  --recovery-ssh-key-file /absolute/private/path/ssh_key
sudo ./rdc backup status
sudo ./rdc backup restore-stage FULL_64_CHARACTER_SNAPSHOT_ID
sudo ./rdc backup restore-plan FULL_64_CHARACTER_SNAPSHOT_ID
```

Do not initialize an existing repository. Staging decrypts the named snapshot into root-private local storage, checks its resource catalogue and identity, and requires an exact match to the recorded installed component hashes. Staging never replaces live data. Unknown version transitions are blocked; replacing a binary is not a database rollback.

## 5. Fence, promote and verify

Install the Ubuntu `nftables` package on the replacement if it is absent. Do not enable a new firewall service or replace an existing firewall configuration for this workflow. The restore runtime creates and removes only its dedicated temporary table. It blocks service ingress during verification while retaining local diagnostic access. Peer recovery blocks overlay ingress, so use independent administration access.

Independently shut down or isolate the previous instance so it cannot return with the same identity. An unreachable host or failed ping does not prove this. Review the snapshot timestamp and accept that changes made after that snapshot will be lost. Then:

```sh
sudo ./rdc backup restore-apply FULL_64_CHARACTER_SNAPSHOT_ID
```

The command requires typing `FENCED AND REPLACE NODE_NAME`. It journals progress, preserves previous data, verifies the restarted service under isolation, and only then releases service ingress. A validation failure attempts to restore and verify the previous local data. After commit, it never automatically rolls back: clients might have written newer data.

If interrupted, keep the old instance fenced and use the independent administration connection:

```sh
sudo ./rdc backup restore-recover
```

A durable startup guard blocks unattended startup while a transaction is pending. Recovery uses its journal to restore previous data for an uncommitted attempt or finish a committed attempt. If ownership, software or isolation rules changed, stop and inspect the local state; do not delete the pending marker to bypass the guard.

Finally, test an actual client connection and the operations your institution depends on. Record snapshot time, outage start, recovery completion, lost changes and the checks performed. `restored-service-verified` confirms the implemented service-level checks; it does not claim regional failover or successful user/application operations. Confirm DNS points to the replacement and update dependencies through their reviewed administration procedures.

## Current evidence and limits

See [validation status](validation-status.md) and the pull request's actual checks. Disposable tests exercise real Restic/SFTP encrypted round trips and real Headscale/DERP lifecycle recovery. They do not establish physical offsite placement, power-loss durability on your storage hardware, home-network reachability, an enrolled client's recovery, institutional policy acceptance or beginner usability. The old-instance fencing decision remains with the operator.

Restic's [backup documentation](https://restic.readthedocs.io/en/stable/040_backup.html) and [restore documentation](https://restic.readthedocs.io/en/stable/050_restore.html) describe the underlying backup tool. Its [repository preparation guide](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) explains recovery credentials and storage access.

## Regional gateway recovery (development)

The development gateway package extends `backup include-services` to the pinned public institution identity, partner agreements, revocations, gateway profile and managed TLS data. It also archives validated optional DNS issuer account data in root-private `/var/lib/rdc-gateway-recovery`, outside the proxy container's mounts. No approval signing key belongs on the gateway. Keep that key, its passphrase, repository password and emergency storage access independently recoverable.

Disable the backup timer before initially adding the gateway. After installation, run `sudo ./rdc backup include-services`, take a new backup, check its age, and re-enable the reviewed schedule. Existing network-only snapshots cannot recover the gateway. Capture refuses unfinished policy, certificate or recovery changes and briefly stops the gateway before encrypted upload.

Use the existing stage, plan, fence and apply procedure on a replacement with the same signed gateway identity, exact profile and compatible component bytes. The replacement must have a verified current certificate. Restoration retains that certificate, combines snapshot and replacement revocations, and keeps partner access closed. A persistent approval timestamp prevents replaying historical permission. The marker survives restart, certificate maintenance and rollback. `gateway status` reports the required review; ordinary service readiness is not permission to share.

After recovery, independently review partners and exchange newly issued bilateral agreements, then explicitly apply them with `sudo ./rdc gateway policy --agreement /absolute/path/new-agreement.json`. An empty reviewed policy grants no partner access. Revoked agreement identifiers remain revoked. Check an actual partner operation afterward.

Archived issuer data is never installed automatically. If needed, export its provider token to a new file in an existing private root-owned directory:

```sh
sudo ./rdc gateway recovery export-token --output-file /root/private-recovery/dns-token
```

Review or rotate the token, then use the explicit gateway issuer setup/issue/enable workflow. The export never prints the secret. It does not reopen the gateway or replace an active issuer account. Disposable encrypted gateway and clean owned-installation recovery have passing evidence; consult the validation ledger for the synthetic VPN boundary and separate actual client-relocation evidence.

### A fresh application or gateway replacement

A newly enrolled replacement initially has a different VPN identity. Recover the original identity **before** installing chat, files or the gateway; otherwise its listeners or signed gateway address may not match after restoration. This path has disposable gateway acceptance, including an injected restore failure. The gateway lifecycle fixture uses a synthetic VPN identity; actual enrolled-client continuity is a separate test, and real-site acceptance remains pending.

1. Prepare a fresh supported Ubuntu peer with the original institution/node/controller labels, temporary enrollment and approved access to the backup destination. Use its provider console or independent administration connection. Import the saved repository password and SSH key with `backup configure`; do not initialize the repository.
2. Download the exact full application snapshot and prepare its network-only recovery stage. Choose its actual package (`matrix`, `nextcloud` or `gateway`):

   ```sh
   sudo ./rdc backup bootstrap-stage FULL_64_CHARACTER_SNAPSHOT_ID --package gateway
   sudo ./rdc backup bootstrap-plan FULL_64_CHARACTER_SNAPSHOT_ID
   ```

   This validates the complete application snapshot but prepares only its original VPN state for promotion. It refuses a replacement with applications already installed, mismatched network ownership or different network binaries. Application data remains in separate private staging.
3. Independently fence the old instance. Review the capture time and the identity change, then run:

   ```sh
   sudo ./rdc backup bootstrap-apply FULL_64_CHARACTER_SNAPSHOT_ID
   ```

   Enter the displayed `FENCED AND RESTORE NETWORK ...` phrase only after fencing. The original VPN address may replace the temporary address. A pending/interrupted operation uses the same `backup restore-recover` command as ordinary restoration.
4. After network verification, install the same reviewed application version and original service identity on that replacement with valid current certificates. For a gateway, use its saved signed public identity and exact original profile; recreate the profile's input file paths with the reviewed identity and newly issued TLS material. No institution approval signing key is installed there.
5. Run `backup include-services`, then use normal `restore-stage`, `restore-plan` and `restore-apply` with the **same full snapshot ID**. Do not take a new blank-application snapshot as a substitute. Test login and a real user operation. Gateway review and restored application connectors remain closed until explicitly approved again.

A replacement can preserve revocations recorded in its selected snapshot and any later records already present locally. It cannot discover decisions absent from all surviving records. The fresh-approval boundary prevents historical agreements alone from reopening restored gateway access.

# Recovery and identity handling

This pilot has one controller database and one relay. Agree a recovery time objective and an acceptable backup age before institutional use. Backups contain private identities and must be encrypted, access-controlled and stored outside the original provider/region. Define an owner who can recover them without relying on this overlay or its future SSO.

## Consistent controller backup

For the initial lab, a short planned controller stop is preferable to copying a live SQLite main file. Run on control-01 as an administrator during a maintenance window:

```sh
sudo systemctl stop headscale
sudo install -d -m 0700 /root/sc-backups
sudo sh -c 'umask 077; tar --numeric-owner -czf /root/sc-backups/controller-$(date -u +%Y%m%dT%H%M%SZ).tar.gz /var/lib/headscale /etc/headscale /etc/systemd/system/headscale.service /etc/server-connectivity.managed'
sudo systemctl start headscale
sudo systemctl is-active headscale
```

Always restart the controller even if archive creation fails; check each command's exit status and service logs. This archive captures the complete stopped SQLite directory (including any WAL-related files), Noise key, policy, relay map and certificate material. Copying only `db.sqlite` while the service is running is not this backup procedure.

Transfer the archive through your institution's approved encrypted backup process and verify successful retrieval. Encrypt at rest before retaining an offsite copy. Record a checksum, UTC date, versions.yml and deployment revision with the archive. Remove temporary plaintext copies after verified encrypted retention according to institutional practice. Do not store backup archives in this project or Git. Certificate private keys and archives require the same access discipline as other infrastructure credentials.

## Restore exercise

1. Obtain the archive and exact deployed versions/configuration through independent management access.
2. Prepare an isolated Ubuntu 24.04 amd64 machine. Do not expose it to production DNS/peers while the original controller runs.
3. Install the same Headscale package with initial service startup suppressed. Stop and disable the service during recovery. Restore the service unit, `/etc/headscale` and complete `/var/lib/headscale` contents.
4. Restore ownership by service account name, not assumptions about numeric UID equality across machines: Headscale must own its state directory; configuration is root-owned and group-readable by Headscale; private keys must not be world-readable. Inspect the archive before extracting it.
5. Run the pinned `headscale configtest` as the Headscale service user with the restored configuration. Confirm certificate validity and intended DNS name. Ensure no test operation overwrites production backups.
6. Fence off the old controller before activating the restored identity. Switch DNS only as part of the agreed recovery window. Start the restored service, inspect node/user lists, and rerun acceptance checks.
7. Record elapsed recovery time, backup age, errors and follow-up work. Do not claim restore success until the application tests work.

Never run two controllers concurrently from the same SQLite/key backup as an improvised HA arrangement.

## Relay and peers

Relay state is `/var/lib/sc-derp`; its certificate/configuration is `/etc/sc-derp`. Back it up consistently while the service is stopped, using the same encrypted-offsite process. Restore ownership to `sc-derp`. A clean rebuilt relay can be tested separately, but endpoint and certificate changes must be reflected in the controller's relay map.

Peer identity is `/var/lib/tailscale`. Ordinary deploy must preserve it. Do not copy this state onto multiple active servers or boot a snapshot clone while its original is online. For an unrecoverable or compromised peer, revoke the old node in Headscale and enroll a new one through administrator approval. An application backup/restore design will be required once real services are added; the test endpoint contains no user data.

Keep independent administrator console access and offline recovery instructions. Headscale, DERP, DNS, certificate renewal and a future identity provider must not all depend solely on each other for recovery.

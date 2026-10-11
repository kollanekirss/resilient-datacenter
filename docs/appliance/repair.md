# Configuration export and management repair

The base export contains site/release/build records, owned VM definitions, known-good host policy and fresh router XML. When network roles are selected, it additionally requires their consistent private state captures; a missing role capture blocks publication. Each original service is paused in turn, captured with configuration/keys/database sidecars, and restarted even if capture fails. Files travel in bounded hashed chunks over the private guest agent. Virtual disks and application data remain outside this export. Keep it private. Restic encrypts it; the password must be a separate private file, at least 16 non-whitespace characters, outside captured material and the destination.

Interrupted guest captures restart the original service on the next guest boot
and discard incomplete staging. Decryption validates role manifests without
starting any copied identity. Full controller reconstruction and promotion are
outside V1; never activate a recovered enrollment or authority while the original
is active. See the [role workflow](roles.md) for the maintenance pause and size
limits. Actual daemon/database capture still requires machine qualification.

On an installed host with the pinned router channel working:

```sh
rdc-appliance export create --output /root/private-exports/site-one --password-file /root/export-password
```

The destination must be new and its parent private (0700). Password and captured input files are 0600. The operation checks the repository and restores the exact snapshot before publishing it. A failed proof leaves no published export. Private capture files remain below `/var/lib/rdc-appliance/private/capture-*` for deliberate cleanup by the owner. Neither those plaintext files nor passwords belong on generic installer media.

Inspect with a separately held password and a new private output directory:

```sh
rdc-appliance export inspect /root/private-exports/site-one --password-file /root/held-password --output /root/verified-restore
```

Inspection verifies ciphertext inventory and every restored component, and starts no services. On a separate Linux computer or the live USB, supply `--restic-binary` pointing to the expanded pinned Linux executable and `--release` pointing to its reviewed release lock. Keep the independently retained export receipt/digest with your recovery records. A successful content restore is not proof that physical recovery works.

## Restore management locally

An unconfirmed network transaction is automatically rolled back on expiry or reboot. From the actual local/serial console, `rdc-appliance repair local-management` restores the saved configuration. It refuses an SSH pseudo-terminal and unexpected owned-file changes. It does not accept a flag pretending a remote shell is local.

If host configuration is damaged beyond that path, boot USB Repair. Identify the existing appliance disk read-only, then explicitly mount its existing ext4/LVM root at `/target`. Do not run an installer or format command. The initial USB Repair screen remains inspection-oriented; mounting and selecting an existing root are deliberate operator actions.

```sh
rdc-appliance repair inspect
rdc-appliance repair restore-management --opened-export /path/to/verified-restore --target-id /dev/disk/by-id/EXACT-EXISTING-DISK
```

The second command requires the exact displayed identity, resolves the stable disk identity again (even after USB-induced disk renumbering), checks the mounted root against its PV/LV/filesystem UUIDs, validates exported plan identity, resolves current NICs and restores only generated management-only files. A durable repair transaction is written before replacement, so a later boot can complete an interrupted restoration. Other disks are not written. WAN and guest links remain down; no copied router identity is activated. Unmount, remove USB, reboot and verify management from the expected numeric address.

Automatic mounting and whole-site restoration are not provided. The [automatic isolated router recovery](router-recovery.md) command copies the stopped owned router disk, imports the inspected configuration through private recovery media, verifies a disk-only boot and leaves the copy stopped. It requires the documented GPT/UFS router layout, an unused VM ID and a new private workspace. All clone NICs remain disconnected on a temporary empty bridge; successful cleanup removes that bridge. There is no automatic promotion or connection of the copied identity to a live network. Physical restore and isolated guest reimport acceptance remain NOT RUN.

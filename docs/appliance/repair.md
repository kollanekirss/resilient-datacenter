# Configuration export and management repair

The base export contains site/release/build records, owned VM definitions, known-good host policy and fresh router XML. It does not include virtual disks, application data or optional role identities. Keep it private. Restic encrypts it; the password must be a separate private file, at least 16 non-whitespace characters, outside captured material and the destination.

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

Automatic mounting, whole-site restore and automatic cloned-router recovery are not provided. Use the original owned router's console for normal router recovery. Test an exported router configuration only in a separate explicitly isolated VM with every external link disconnected; never attach a duplicate identity to the live network. The physical restore and isolated guest reimport acceptance cases remain NOT RUN.

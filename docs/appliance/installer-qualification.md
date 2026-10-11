# Installer implementation and qualification

The USB installer is implemented as an **unqualified candidate** for Proxmox VE 9.2-1, x86-64, UEFI with Secure Boot disabled, one ext4/LVM-thin target and wired IPv4 networking. The build explicitly requires `--qualification-build`. The release lock and output receipt remain unqualified. Unit tests, source inspection and successful assembly do not establish disk safety or network isolation on a booted machine.

## What was actually inspected

The complete official Proxmox ISO was downloaded, its exact 1,706,178,560-byte size and SHA-256 checked against the release lock, and its contents read without executing guest software. The source files below match the reviewed [Proxmox installer revision](https://github.com/proxmox/pve-installer/tree/32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9). The public [automated installation documentation](https://pve.proxmox.com/wiki/Automated_Installation) describes the upstream answer format and first-boot facility; the custom early launcher and staging below are appliance extensions.

| Shipped ISO member | Verified observation |
| --- | --- |
| `.cd-info` | `RELEASE='9.2'`, `ISORELEASE='1'`, `PRODUCT='pve'` |
| `boot/initrd.img` | SHA-256 `8fdf76b44287af130358c142f1743c30e1b10df21bae1693283736603bef3cba` |
| initrd `init` | SHA-256 `8b0ca78470877fddee457fd044f70f88127a5ce761cda63f35e26a73ddd96265`; overlays installer above base, then starts `/sbin/unconfigured.sh`; no DHCP/network activation in the inspected script |
| `boot/grub/grub.cfg` | SHA-256 `f69d3992415aea9f4dbbfd583ca184ad2a95c38efd47f9fcd8ea4ddd44960947` |
| `pve-base.squashfs` | Provides `/usr/bin/python3 -> python3.13`, Python 3.13.5-2+deb13u2, `json` and `tomllib` |
| `pve-installer.squashfs` | Provides the auto-installer, low-level installer and launcher; Python is inherited from the base layer |
| Installer `/usr/sbin/unconfigured.sh` | SHA-256 `7a5be4ff18f286b9216811a6216e3ddd098d49206d4c900192c75b3c89b74d7c` |
| Installer `/usr/bin/proxmox-low-level-installer` | SHA-256 `b0101a3a0bc4131d4f42a87dd69f3b0305fcc65ec8b57ee18e3f9cdabd9dc348` |
| Installer `/usr/share/perl5/Proxmox/Install.pm` | SHA-256 `43a4271c80a40cb2030f5567723ffe2a545f9bc49ea3dbb4bb586efeaf77d25e` |

The ISO does **not** contain `proxmox-auto-install-assistant`. The running installer does not require that builder-side tool. It generates a bounded answer in RAM, validates TOML, refreshes the shipped low-level inventory, checks the selected disk and NIC against the upstream matching behavior, and sends the answer to the shipped auto-installer. That frontend performs its own answer validation before spawning the low-level installer. This implementation does not claim that parsing TOML alone validates the upstream answer schema.

The source and ISO inspection also found two important details. Upstream disk-list matching uses a suffix, so the adapter requires a unique match to the exact observed device path. The frontend can return successfully at end-of-file without receiving a completed installation message, so this adapter additionally requires its explicit successful `Finished` and `Installation done` records, then independently checks the installed LVM root.

## Build on Linux

Use a trusted Linux builder with Python 3.11 or newer and the following executable paths. They are build tools, not commands run on the future appliance target:

- `/usr/bin/xorriso` — read, remaster and read back the ISO while replaying its original boot metadata.
- `/usr/bin/unsquashfs` and `/usr/bin/mksquashfs` — SquashFS with Zstandard support.
- `/usr/bin/unmkinitramfs` — unpack the pinned Zstandard initrd for inspection.

Debian/Ubuntu package names are `xorriso`, `squashfs-tools`, `initramfs-tools-core` and `zstd`. Prepare these before offline assembly. No x86 guest execution is required to assemble the image. This Mac currently lacks those Linux tools; real remastering has not been run here.

From the repository, use a new output path and a private input cache:

```sh
python3 -m appliance release-check
python3 -m appliance bundle prepare --cache .cache/appliance-media --output build/appliance-inputs
python3 -m appliance bundle verify --output build/appliance-inputs
python3 -m appliance iso build --bundle build/appliance-inputs --output build/appliance-v1-candidate.iso --qualification-build
```

Create the parent `build` directory first. Bundle preparation downloads only pinned base inputs when they are missing; an already complete bundle makes ISO assembly offline. Keep at least 12 GiB free beyond the prepared bundle; 20 GiB is preferable for builder overhead. A full image contains the expanded OPNsense DVD and Ubuntu probe image and should use USB media of at least 8 GB, subject to the actual produced size. USB flashing is an explicit operator action against a separately identified USB device; the builder never writes a block device.

Assembly refuses unknown upstream launcher/initrd/source/boot-layout digests, an already prepared upstream ISO, missing tools, conflicting output files or failed readback. It gathers the current allowlisted appliance source files late in the build, includes only the exact public release JSON, includes service/timer files and known unit drop-ins, and excludes local plans, private state, cached exports and arbitrary JSON. Each copied file has a manifest digest. Source review must still ensure secrets were not accidentally embedded inside source code.

The builder replays upstream ISO boot metadata, replaces the installer SquashFS and closed GRUB menu, adds the public runtime and three offline payloads, and reads those mapped files back from the candidate image before publishing it. Its neighboring `.iso.json` records the image digest/size, adapter/source revision, release/runtime identities, patched launcher and inspected init script digests, `build_id`, and `qualification: not-run`. This receipt binds bytes; it is not a hardware-test receipt.

## Before any disk write

The appliance launcher retains the inspected upstream mount/udev initialization and replaces the tail **before** its hostname, DHCP, IPv6 autoconfiguration, time synchronization and installer dispatch. Its GRUB menu has no timed default, offers local and serial console setup, removes stock alternative installation/rescue paths and passes `ipv6.disable=1` before the kernel starts. Serial input/output is available at 115200 baud. These are source-level controls; packet-capture qualification is still required.

The local menu asks the operator to select an existing plan or create one, identify disk serial/WWN plus by-id/size/model/transport, assign ports by permanent MAC/PCI path/driver, confirm the physical port roles, acknowledge the unqualified build, type the disk serial/WWN and the current full plan hash, and enter a unique root password privately. No site password or site configuration is written onto the generic ISO. Blank choices do not install anything.

Fresh checks reject the boot-media ancestry, ambiguous/missing identities, changed NICs, host WAN addresses, active unselected interfaces, a mounted target, non-target LVM/RAID/ZFS/encrypted/multipath storage, unsupported firmware/virtualization and inadequate resources. The checks run again after the upstream inventory refresh. Only the two explicit qualification labels may be deferred for a candidate; observed hardware and resource errors may not. A private attempt latch is persisted in the live RAM filesystem before the destructive frontend call. No automatic retry or reboot follows an interrupted installation.

The upstream first-boot hook is **after disk installation**, even when its ordering is `before-network`. It is not the pre-erase safety gate. The custom live launcher and inventory checks provide the pre-erase gate.

## Installed-disk staging and startup

After explicit upstream success, the adapter independently verifies that exactly one `pve` PV and root LV belong to the selected physical disk. It uses the shipped `proxmox-chroot prepare --filesystem ext4`, checks the mounted source/type/options/UUID, and checks LVM ancestry again. It then copies the public runtime, expanded media, immutable records, CLI wrapper, service units and unit drop-ins, plus the private site plan. It enables startup services, updates the bootloader configuration to disable IPv6 and refreshes Proxmox boot files. The completion marker is written last, after staged file and directory synchronization. Cleanup runs even after failure. Existing private staging is never silently overwritten.

The first-boot hook starts `rdc-first-boot.service`; the same service is required before networking, SSH, PVE management listeners and guest startup. Every boot verifies staged immutable bytes, restores any interrupted management transaction using a monotonic timeout model, resolves physical port identities again, and refuses changed interface names unless a confirmed local configuration or repair records the new mapping. Initial management-only configuration is generated once; later boots preserve confirmed network changes. The early nftables guard and IPv4/IPv6 policy are applied before listeners. pmxcfs/PVE firewall work is deferred to the separate post-PVE host-policy service. WAN and guest bridges are not automatically activated by the early service.

Mutable site/network files are deliberately excluded from immutable file hashes. Private receipts still bind the original disk, initial plan, release and build identities. A partial stage, missing payload, changed immutable file or unresolved port stops startup; it cannot qualify the appliance by changing a JSON label.

## Local USB repair

`Repair` prints a fresh read-only disk/port inventory, then opens an explicitly entered local root console. `Exit setup` opens that same console. After installation starts or fails, the console remains available and the menu refuses another installation attempt in that boot. Console commands are entered by the physically present operator, not generated and run automatically. The shell does not save command history. Type `exit` to return to the menu when it is still running.

Use `lsblk`, `pvs` and `lvs` to inspect the existing appliance disk. Identify the expected disk and the unique `pve` root before any activation or mount; a second `pve` VG or ambiguous identity requires manual resolution. For an already verified unique existing `pve` root, an operator can activate only that VG and mount its existing filesystem:

```sh
vgchange -ay pve
mkdir -p /target
mount -t ext4 /dev/mapper/pve-root /target
rdc-appliance repair inspect
```

These commands are a manual repair sequence, never part of menu initialization. Do not run the installer, partitioning or formatting tools for repair. `repair inspect` checks the mounted root and original disk/LVM identity. Inspect a previously exported configuration using the separately retained password and pinned Restic binary, then follow [the repair procedure](repair.md) to restore generated management-only settings. Unmount the target, synchronize writes and shut down before removing USB. If staging itself never completed, repair does not invent an ownership receipt; inspect and recover deliberately.

## Qualification still required

Automated tests here use disposable files and controlled external-tool responses. They cover answer restrictions, source/layout rejection, ISO file mapping/readback failure, runtime allowlisting, disk/USB ancestry and LVM conflicts, stale consent, one-attempt staging, unit/drop-in copying, early recovery and NIC rename refusal. Actual source-ISO extraction and inspection were read-only; no installer or guest binary was executed.

The following remain **NOT RUN**, unless a separate test report supplies real evidence for that exact image digest:

1. Linux remaster using the real required tools and successful UEFI local/serial boot from the resulting image.
2. Read-only media boot, idle menu, every cancellation/repair/exit path and rejected preflight, with target/canary disk hashes unchanged and no DHCP/SLAAC/WAN address or packets on captured interfaces.
3. Deliberate install onto an isolated disposable selected disk, USB/non-target disk preservation, interruption at each staging boundary, and refusal of ambiguous storage.
4. Cold first boot from the installed disk without USB, before-network failure cases, direct management access, current interface-name revalidation and management-rollback recovery.
5. Actual OPNsense install/reboot/console channel, neutral-probe runtime, host and router firewall evidence, WAN isolation, reboot sequencing and physical two-port behavior.
6. USB management repair with an actual encrypted export and an isolated router configuration reimport.

A QEMU result can establish only its specific virtual scenario. NIC identity behavior, physical cable assignment, firmware differences, packet isolation and resource budgets still need the selected hardware. Do not set the release profile or budgets to `qualified` from unit tests, source inspection or successful image assembly alone.

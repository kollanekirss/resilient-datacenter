# Neutral workload probe

The probe is a disposable Ubuntu VM with one workload interface. It has no management, upstream, infrastructure or relay attachment, and no connector, controller or relay role. Its seed uses the plan's exact workload MAC and reserved address as a static address, with the workload gateway as DNS and default route. This avoids dependency on DHCP during offline preparation; the router's reservation remains the authoritative allocation for that MAC/address pair.

The implementation creates a private, site-specific NoCloud seed and imports the pinned staged `probe-image`. It leaves the VM stopped with its link disconnected and `onboot=0`. Starting it and connecting its workload link are separate explicit commands. Running QEMU does not prove successful cloud-init or packet isolation.

## Prepare a private seed

Use a Linux seed builder with Python 3.11 or newer and `/usr/bin/xorriso` (Debian/Ubuntu package `xorriso`). If that executable is absent, seed assembly fails; it does not download or install tools. The seed builder does not execute guest software and can operate offline.

Create a private directory (0700), then place a JSON credentials file there with mode 0600. It must contain `password_hash`, a newly generated salted SHA-512 crypt hash for this probe's console login. It may also contain `ssh_public_key`, one Ed25519 public key without a comment. Supply a unique credential; the software validates its format but cannot prove it was never used elsewhere. There is no default or embedded password, and no credential is accepted as a command-line argument.

```sh
rdc-appliance probe seed /private/site.json \
  --credentials /private/probe-credentials.json \
  --output /private/probe-seed.iso \
  --release /private/release.lock.json
```

The output parent must exist and be private. The command writes a new `probe-seed.iso` and `probe-seed.iso.json`, both 0600. Keep both files together. The receipt binds the plan, VM ownership, three source-file digests and final image digest/size. It contains no password hash. The ISO contains the hash, so both seed and credentials remain private local material and must never be added to generic USB images or shared repositories.

The seed uses [NoCloud's labelled ISO format](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html), with `user-data`, `meta-data` and `network-config` at its root. Content and instance identity are deterministic for the same complete plan and credentials. The image sets fixed file/volume timestamps and ownership, then reads back all three files before publication; byte reproducibility across different xorriso versions is not claimed. The builder follows the timestamp controls documented in [the upstream xorriso manual packaged by Debian](https://manpages.debian.org/unstable/xorriso/xorriso.1.en.html).

Cloud-init creates the `probe` user with the supplied console password hash and optional key. Root login and SSH password authentication are disabled. The seed requests fresh Ed25519 host keys, disables cloud-init package updates/upgrades, masks automatic package/update timers and Snap services, and installs no packages or roles. Version 2 networking matches only the workload MAC, disables DHCPv4, DHCPv6, router advertisements and link-local addressing. IPv6 and IP forwarding are disabled through early sysctl settings; a GRUB drop-in also disables IPv6 in subsequent kernels. These instructions rely on the pinned Ubuntu image's cloud-init and Netplan; [cloud-init documents the Netplan passthrough behavior](https://docs.cloud-init.io/en/latest/reference/network-config-format-v2.html). Real guest validation remains required.

## Import and first boot

Copy the private seed and receipt onto the installed appliance, preserving modes and a private parent. The following commands use the installed site/release records and the staged pinned Ubuntu image:

```sh
rdc-appliance probe prepare --seed /root/private/probe-seed.iso
rdc-appliance probe start
```

Preparation verifies the source image digest, inspects it with `qemu-img info`, and refuses a backing image, external data file, encryption, unsupported format or an image larger than the declared disk budget. It refuses an occupied VM ID, unowned target volumes and unavailable/non-LVM-thin VM storage. It requires the normal `local` directory ISO storage at `/var/lib/vz`, publishes a private verified seed there, and imports the image into the planned VM ID using the documented [Proxmox import-from disk option](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc). The image is copied, not modified. An imported disk smaller than the declared budget is grown while stopped; guest filesystem growth is handled by the image's cloud-init and must be checked at the console.

Every `qm` mutation has a durable intent first. After each command, the implementation checks current/effective VM configuration, ownership, exact volume, disk size, boot order, sole NIC and stopped/running outcome. The VM boots from `scsi0` only. The seed CD remains attached as data; it is not an installation boot device. Preparation never starts the VM, changes another VM, formats a host disk or attaches another zone.

`probe start` starts only that already prepared owned VM. If it previously had a confirmed workload link, the command first disconnects the link while stopped and verifies the change before starting. A running VM is not silently restarted. Automatic host startup does not start this probe.

Use the Proxmox local console or `qm terminal` for the configured serial socket. Log in as `probe` with the supplied unique password and verify:

- `cloud-init status --wait --long` completed without errors; the intended packages/update services remain disabled.
- `ip link` and `ip -4 address` show the planned workload MAC and address on the only non-loopback interface. No additional zone interface exists.
- `ip -6 address` is empty. On first boot the IPv6 disable sysctls must be `1`; after a kernel boot with `ipv6.disable=1`, those sysctls may be absent. Forwarding must remain disabled.
- The guest contains no optional appliance roles or overlay identity. Confirm the unique login and availability of the local tools needed for your planned packet tests.

The first boot stays disconnected while these settings take effect. The image does not promise that every desired diagnostic package is installed; package downloads are not part of this offline workflow.

## Explicit workload attachment

After those console checks, use the local appliance console:

```sh
rdc-appliance probe attach-workload
```

The command asks for all required checks and explicit typed confirmation. Its in-process attestation is bound to the current plan, exact VM configuration and QEMU process identity for at most five minutes. A JSON file or old console claim cannot replace it. The attachment gate freshly queries the restricted, pinned router channel, requires successful router configuration checks, transit policy with its blocking guard released, and the actual router workload link connected in the same observed router boot. It rechecks the probe immediately before recording the link-change intent.

Only the existing `net0` with the planned MAC on `vmbr3` is connected. No bridge, upstream address, host route or management attachment is added. The result means the configured link change was observed; guest reachability, firewall isolation and successful packet tests are separate evidence.

## Interrupted operations and limits

If import, resize, start or attachment has an uncertain outcome, the next operation stops. Inspect the VM and private operation record, then explicitly request observation:

```sh
rdc-appliance probe reconcile
```

Reconciliation never replays the command. It accepts only the exact journaled configuration and running state; altered disks, ownership, interfaces, boot order or extra devices are refused. A failed create with no complete observable VM requires deliberate operator recovery, not automatic adoption or deletion. Resume preparation only after successful reconciliation; it preserves the imported disk and continues the remaining stopped-state preparation.

This implementation does not clone probes, reset guest identity, rotate existing seed credentials, migrate a probe after a site-plan revision, delete a VM, or make a guest-ready claim from stored state. A changed plan requires deliberate review and re-provisioning. Base configuration exports retain the probe definition, not its guest disk or seed credentials; treat it as disposable and retain needed private recovery material separately.

Unit tests use bounded fake process responses and temporary seed/receipt files. They cover private deterministic seed content/readback, image and seed integrity failures, backing-file refusal, VM-ID conflicts, pre-mutation intents, import/resize idempotence, exact reconciliation, drift rejection, disconnected startup, cold-start link withdrawal and fresh attachment gates. Actual seed ISO creation with Linux tools, Ubuntu cloud-init execution, console access, guest filesystem growth and packet/isolation tests remain **NOT RUN** unless a separate report supplies evidence for the tested image and seed digests.

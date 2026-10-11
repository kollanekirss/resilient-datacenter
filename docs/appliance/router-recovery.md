# Automatic isolated router recovery

The recovery command tests a decrypted base export against a new copy of the
original router disk. It never replaces or starts the original router, and it
never activates the recovered copy on the site network. A successful result
leaves the copied VM stopped, with all links disconnected and its temporary
isolated bridge removed. The copy can be inspected or discarded explicitly.

This implementation is a development candidate. Controller tests, private-file
checks and serial-protocol tests run on the development machine. The actual
Proxmox disk copy, recovery DVD boot, installed OPNsense boot and packet isolation
remain **NOT RUN** until a disposable x86-64 test machine is available.

## Supported source

Use the V1 router installed from the pinned OPNsense 26.7 DVD with the guided
**GPT UFS** layout: EFI partition, BIOS bootstrap partition, and root on the third
partition. The existing V1 VM uses SeaBIOS and one `scsi0` disk on local LVM-thin
storage. Other layouts, ZFS roots, extra disks, live installation media, snapshots
that require special activation, foreign VM definitions, and running source
routers are refused. This procedure requires the original installed disk; the
configuration export does not contain a replacement operating-system disk.

Stop the original router cleanly before starting. Management access by the host's
numeric address remains independent of the router. Recovery takes the same
shared configuration lock used by Proxmox when copying a stopped volume. This
blocks normal start/update operations for the original until the complete
recovery attempt has finished, while permitting Proxmox's shared disk-copy lock.
It does not alter the original router configuration or storage.

## Isolation and proof

1. The inspected export must contain exactly the six base components. Its plan,
   release lock, build record and original VM ownership/disk identity must match
   this host. The exported XML must match the managed V1 policy and plan.
2. A new VMID is mandatory. Existing VMs and leftover storage volumes are never
   adopted. Durable intent is written before every VM mutation.
3. Recovery creates a new, owned, empty bridge named `rdcr<VMID>`. It remains down,
   has no IP addresses, no physical ports and no other VM members. Every copied
   NIC is created with `link_down=1` and its firewall enabled. An omitted bridge
   is deliberately avoided because Proxmox interprets it as user-mode NAT.
4. The original disk is copied with Proxmox's `import-from` operation. No copied
   configuration containing a live site bridge exists at any point.
5. A private recovery DVD mounts only the copy's serial-tagged GPT UFS partition,
   checks it without repairing filesystem errors, imports the exact exported XML,
   installs one temporary proof hook, unmounts it, and reports the imported digest
   over the local virtual serial port. No guest agent or working network is used.
6. The DVD is detached. The clone boots from its installed disk only. A second
   challenge proves the configuration digest, OPNsense version and installed UFS
   root. The temporary hook removes itself before returning its proof. No extra
   credentials or persistent console changes are installed.
7. The host stops the clone and verifies the result, then removes only its own
   empty bridge and private recovery ISO. Configuration export contents and serial
   challenges are excluded from the public result.

A proof is an observation from this attempt, not imported JSON or a configured
boolean. Missing, stale, partial or mismatched serial responses cannot complete
recovery. The guest handshake and host commands have deadlines. Guest failure
paths request shutdown; the host also stops the owned clone in its cleanup path.
A power interruption leaves `onboot=0` and disconnected links; it does not make
the clone a replacement router.

## Interrupted attempts

Do not retry the same VMID. Reconciliation observes its current configuration,
ownership, disk and isolation without replaying a copy, import or boot. A failed
or uncertain attempt remains incomplete even if its clone is now stopped.
Unexpected ownership, a connected/foreign port, an assigned address, or a cleanup
failure requires inspection. Recovery never deletes a possibly foreign disk or
stops a VM whose ownership cannot be established.

The private journal is under `private/router-recovery/<VMID>.json`. Keep the
private export and independently held decryption password separate. Do not copy
the generated recovery DVD to a shared installation USB: it contains plaintext
site configuration. The command removes its DVD after a verified stop; if cleanup
cannot establish that the clone is stopped, private artifacts remain available
for inspection and are not published.

## Run from the installed host

After inspecting the encrypted export and stopping the original router cleanly:

```sh
rdc-appliance repair router-clone --opened-export /root/verified-restore --vmid 901 --work /root/private-recovery/run-one
rdc-appliance repair reconcile-router --vmid 901
```

Choose an unused VM ID and a new work path below a private directory. The first
command creates and checks the isolated copy; the second only inspects an
existing attempt. Neither starts the original or connects the clone.

## Software interface

`restore_router_isolated(plan, inspected_export, clone_vmid, runner, private,
*, dvd, work, release, build)` performs the bounded attempt. `work` must be a new
path under a private directory. `dvd` is the verified, expanded release DVD.
`inspected_export` is the new private directory produced by `inspect_export`.
The privileged CLI establishes the installed-host identity before invoking it.
`reconcile_router_recovery(clone_vmid, runner, private)` is observation-only.

The private remaster uses `genisoimage`, which is a dependency of the actual
pinned Proxmox `qemu-server` package. It read-only loop-mounts the verified DVD,
copies its filesystem into a private directory, replaces only the declared
recovery files, builds a BIOS El Torito DVD, and mounts the result read-only to
compare every injected file. Mounts are explicitly cleaned up. It needs enough
local temporary space for the copied DVD and output image, plus space for the
router disk copy. This is a VM recovery DVD; it does not change the USB installer's
UEFI support.

The source contracts are the official [Proxmox VM import implementation](https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu.pm),
[configuration lock implementation](https://github.com/proxmox/pve-guest-common/blob/master/src/PVE/AbstractConfig.pm),
[network device schema](https://github.com/proxmox/qemu-server/blob/master/src/PVE/QemuServer/Network.pm),
[OPNsense DVD build](https://github.com/opnsense/tools/blob/master/build/dvd.sh),
[OPNsense 26.7 boot sequence](https://github.com/opnsense/core/blob/26.7/src/etc/rc),
and [console configuration recovery guide](https://docs.opnsense.org/troubleshooting/config_reset.html).
The pinned Proxmox ISO's own package index contains `genisoimage` 9:1.1.11-4
(SHA-256 `e6dc605d0ef3fc375d6cc96c16af32b48a1053e2f08db769d3483d3c7fdb6884`)
and `qemu-server` 9.1.15 declares it as a dependency.

## Disposable lab router provisioning

`appliance.lab_router.setup_router(plan, release, runner, private, credentials)`
installs the pinned OPNsense DVD into a newly allocated lab router. It requires
Linux root, the disposable acceptance SMBIOS marker, the lab target serial and
the two fixed lab port MACs. It refuses an existing VM receipt or a repeated
setup attempt. This is not a production router reinstall command.

The private BIOS DVD runs the pinned release's `bsdinstall scriptedpart`,
`opnsense-install`, `bootconfig` and `entropy` steps. Formatting requires the
nonce-bound serial request, exactly one blank target disk and its exact planned
size. The official source filesystem is restored before its mtree verification;
private configuration and the restricted helper are installed afterwards. All
NIC links stay down through both media and installed-disk boots. A one-time disk
hook runs the real restricted helper, reports actual runtime policy and the SSH
host key, then removes itself. The host installs a private, pinned SSH channel
only after this observation passes the normal router audit.

The result contains `checks` for `router.attest_console`, guest/VM boot IDs and
`state: bootstrap-verified`. The caller separately controls management, WAN and
transit activation. `router_certificate(plan, runner, private)` reads the current
HTTPS certificate through that pinned channel. Neither API returns private XML,
password hashes or private keys in public evidence.

The controller, policy validation, shell syntax and failure cleanup have local
unit coverage. Actual DVD assembly/mounting, FreeBSD installation, first-boot
model migrations, serial service startup, and certificate persistence still need
the first disposable x86-64/KVM execution. In particular, OPNsense's pinned
`run_migrations.php` enumerates model classes and `BaseModel::runMigrations()` can
serialize previously absent model defaults. The strict managed-configuration
audit remains in force; unexpected defaults stop the run for review rather than
being silently accepted. The source-confirmed empty firmware registration
metadata and backed HTTPS certificate reference have narrowly scoped audit
exceptions and regression tests.

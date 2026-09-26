# Carry the software needed to reconstruct Ubuntu roles

This development feature prepares public software for the portable DNS/time,
NGINX, Matrix/Element, Nextcloud and recovery roles. It is **role software**, not a
complete bootable crisis appliance. Site configuration, credentials, private keys,
application backups and guest/hypervisor installation media remain separate.

The purpose is to remove package repositories, Python indexes, image registries
and the recovery-tool download from the replacement Ubuntu guest's dependencies.
The guest still needs a supported installed OS, local administration, prepared
networking/time/trust and independently accessible recovery material.

## Prepare while connected

Use a disposable **Ubuntu 24.04 amd64, Python 3.12** preparation machine with
root access, Git, APT, Skopeo and the project's Python environment. Do not use a
production application server as the acquisition machine. Start from the reviewed
committed source revision; builds reject tracked source changes.

```sh
sudo .venv/bin/python scripts/offline_bundle.py build /private/crisis-software
```

Preparation acquires:

- A clean, allowlisted source export; private inventories, operator work files,
  repository credentials and test keys are excluded.
- Ubuntu packages resolved against empty package state using isolated official
  Ubuntu sources and authenticated archive metadata. The bundle retains the
  original archive metadata and keyring for provenance.
- Binary Python wheels for the supported interpreter and all resolved dependencies.
- The five unique pinned Linux/amd64 images shared by chat/files, with their
  original manifest/configuration digests and blobs.
- The exact upstream-pinned compressed Restic executable.

No application container is started by preparation. A failed build never publishes
its final manifest/destination. A completed bundle includes exact file sizes and
SHA256 values and the source commit. Keep the printed **manifest SHA256 in an
independent trusted record**, such as your institution's controlled handover.
A checksum saved next to replaceable software is not an independent trust anchor.
This locally generated digest is not a publisher signature or public release
attestation. Independently review the source/build host before trusting its output.

The full Ubuntu closure is intentionally larger than the subset missing on the
preparation host. Do not optimise it by assuming a replacement already has the
builder's installed libraries or cached images. Exact resolved versions are held
by the bundle manifest; rebuild and retest when changing software.

Third-party notices/licences remain in the original packages, wheels and image
layers. The project's licence does not relicense dependencies or establish the
right to publish a combined binary distribution. This workflow prepares your
institution's software copy; public distribution review remains separate.

## Verify using independently trusted code

Copy the complete directory without changing its files. From a separately trusted
reviewed copy of this verifier, run:

```sh
python3 /trusted/rdc/scripts/offline_bundle.py verify /media/crisis-software \
  --manifest-sha256 YOUR_INDEPENDENTLY_RECORDED_SHA256
```

Verification uses Python's standard library, reads locally and executes no
bundled software. It rejects changed, missing or additional files; symlinks and
special files; path escapes; inconsistent schemas; and oversized manifests or
artifacts. Do not execute a verifier from an unverified removable bundle to decide
whether that same bundle is trustworthy.

`bundle-integrity-verified` describes only the verified bytes. It does not prove
private recovery material, certificate coverage, successful user login or a whole
site restoration. Keep the verifier and its own trusted source identity accessible
without cloud sign-in.

## Prepare a fresh replacement Ubuntu guest

Use an independently installed Ubuntu 24.04 amd64 guest with systemd, Python 3
and root console access. Bootstrap refuses a pre-existing application/site identity
or unowned installation directory. It does not provision Proxmox or OPNsense,
partition a disk, change the host's management network or enrol a VPN node.

```sh
sudo python3 /trusted/rdc/scripts/offline_bundle.py bootstrap /media/crisis-software \
  --manifest-sha256 YOUR_INDEPENDENTLY_RECORDED_SHA256 \
  --confirm-fresh-guest
```

All bytes are verified and copied into protected local staging before installation.
APT uses only the local packages, with downloads disabled and a separate network
namespace. Installed OS packages are preserved rather than upgraded. A simulated
transaction rejects any removal except replacing `systemd-timesyncd` with chrony;
a base OS whose installed versions cannot satisfy the bundled software must be
prepared separately. Run no other package operations during bootstrap. Package service autostart is suppressed; a foreign existing autostart
policy requires review rather than replacement. Python uses only bundled wheels;
container import uses local storage and preserves exact pinned identities.

This is an explicit package-install operation on that guest. Retain independent
console access. The marker binds a partial operation to one bundle; do not change
bundles to resume it. Failed preparation is not application readiness. Do not
remove ownership or pending-recovery markers to force installation.

The result provides the installed source under `/opt/rdc-offline/source` and the
verified local Restic artifact path. Follow [local network preparation](portable-local-network.md)
and [local applications](portable-local-applications.md) using the prepared
software, private site plan and TLS material. Use the existing application
`--offline` mode and [readiness checks](offline-applications.md).

For new backup/recovery configuration, use the reported artifact path:

```sh
sudo /opt/rdc-offline/source/rdc backup configure /private/backup.yml \
  --restic-artifact /absolute/reported/path/tools/restic.bz2
```

For recovery, additionally supply the existing `--recovery-password-file` and
`--recovery-ssh-key-file` through private local administration. The supplied Restic
file must match the original pinned checksum and executable format; there is no
online fallback. Backup access and credentials remain separate from installing
the binary. Follow the existing [fenced recovery procedures](backups.md).

## Private material that must travel separately

Before leaving, independently protect and test access to:

- Site plan, addressing, DNS/time settings, OPNsense exports and administrator
  console access; do not depend on an online password manager to retrieve them.
- Permanent service names, client/guest trust anchors, and encrypted TLS private
  material covering the intended offline period plus margin.
- Consistent encrypted application snapshots and separately held decryption and
  storage-access credentials. A remote backup unreachable from headquarters is
  not an available offline recovery copy.
- Application login accounts and user-held Matrix encryption recovery keys.
- The trusted software-manifest hash, verification code, guest/hypervisor media,
  and a printed recovery sequence including fencing of the original writers.

This feature does not automatically export/encrypt/restore the whole private site.
Application snapshots do not include every edge/DNS/frontend resource. Treat any
missing item as a reconstruction blocker, even if the public bundle verifies.

## Acceptance boundary

The new disposable workflow builds the bundle, boots pinned replacement Ubuntu
guests with the virtual uplink blocked before first boot, installs dependencies
without cloud-init downloads or warm application caches, imports exact images,
and runs both portable application access/restart/native-restore fixtures. Check
the exact source run before treating this workflow as passing evidence.
Both roles passed at `284db4d` in
[run 36231822767](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36231822767),
including repeated bootstrap and local installation of the recovery executable.

The pinned guest base is prepared separately from this role bundle. Its download
and QEMU-host provisioning are outside the disconnected guest boundary. Test TLS
material and snapshots are generated in the disposable fixture. This does not
prove restoration of an independently encrypted private whole-site configuration,
OS installation from ISO, simultaneous complete-site boot, physical relocation,
power endurance, or an unfamiliar operator's successful reconstruction.

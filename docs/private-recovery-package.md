# Carry private recovery material

This development tool encrypts an explicitly prepared recovery folder into a local
Restic repository and verifies a complete byte-for-byte restoration before
publishing it. It uses the pinned recovery tool from the public software bundle.
No network backend, cloud account or online download is used by seal/check/open.
Run these operations as root on Ubuntu 24.04 amd64, both when sealing and
recovering. This preserves a consistent ownership identity across replacement
machines; nonroot packaging is not supported. The preparation Mac is not a deployment
or recovery host.

This is **private material transport**, not live application backup or whole-site
restoration. It does not collect from servers, export OPNsense, check password
usability, certify certificate validity, start services or promote restored data.
Use the existing consistent application snapshot procedures before preparing it.

## Prepare an input folder

Use an encrypted local disk. The input folder, its parent, every subdirectory and
every file must be owned by root with no group/other access
(directory mode 0700, file mode 0600). Links and special files are refused. Do not
point the tool at a live database or an actively changing backup repository.

The input contains exactly these directories, each nonempty:

| Directory | Material to prepare and independently verify |
|---|---|
| `configuration` | `site.json` and `network.json` using the existing portable schemas; other private deployment settings |
| `edge` | Consistent OPNsense export and any required export-decryption instructions |
| `trust` | Client and server trust anchors and verification instructions |
| `tls` | Frontend/backend certificate chains and their private keys |
| `backup-access` | Credentials needed to unlock application snapshots and reach local backup copies |
| `application-backups` | Consistent local copies of encrypted application repositories/snapshots, including necessary metadata |
| `operator` | Offline restoration sequence, fencing procedure and independent console-access instructions |

Site/network settings are validated together. The other categories are checked
for presence, private file safety and exact bytes only. An arbitrary file in a
category is **not evidence of readiness**. Backup age, certificate coverage,
correct credentials, correct institutional identity and application-level restore
must still be checked independently. Input limit: 30,000 files, 128 GiB total and
64 GiB per file. Larger deployments need a separately designed transport profile.

Keep the **outer package encryption password** in a separate private regular file,
outside the input and output trees. Use a strong randomly generated password; the
file-length check cannot assess its strength. Retain an independent offline copy
of it. Losing that password prevents decryption. Application backup passwords may
be carried inside the encrypted package; the outer password must not be its only
recoverable copy.

## Seal and prove recovery

Use the reviewed source and the verified compressed Restic artifact reported by
the offline software bootstrap. All paths below represent your own absolute local
paths; the destination must not exist and its parent must be private.

```sh
sudo .venv/bin/python scripts/private_recovery_package.py seal /private/recovery-input \
  --output-dir /private/carried-repository \
  --password-file /separate-private/package-password \
  --restic-artifact /private/software/tools/restic.bz2
```

The tool privately copies the material, records file sizes/hashes, encrypts a
snapshot, checks every encrypted data pack, restores into temporary staging and
verifies exact contents. It publishes the repository only after all checks pass.
The result prints the full snapshot ID and private manifest SHA256, without
printing institution names, input paths or secret values. Keep those identifiers
in your controlled independent handover record. They are not publisher signatures.

Preparation temporarily needs space for two plaintext copies plus the encrypted
repository. Use encrypted storage for input, work and destination. Temporary data
is deleted on normal completion/failure, but deletion is not secure erasure and
abrupt termination may leave a private temporary directory to inspect and remove.
Do not run another process that modifies input, password or repository during an
operation. Keep the original consistent backup until a separate recovery succeeds.

## Check after transport

```sh
sudo .venv/bin/python scripts/private_recovery_package.py check /private/carried-repository \
  --password-file /separate-private/package-password \
  --restic-artifact /private/software/tools/restic.bz2 \
  --snapshot FULL_SAVED_SNAPSHOT_ID \
  --manifest-sha256 INDEPENDENTLY_RECORDED_MANIFEST_SHA256
```

Check decrypts into private temporary storage to verify actual recovered files.
It needs an encrypted, writable private parent directory beside the repository.
It reports `private-package-verified`, with readiness and whole-site recovery
explicitly unassessed. Wrong passwords, wrong identities and corrupt data fail.

## Open into staging

Use the same arguments with `open` and a new `--output-dir /private/recovery-stage`.
The destination is published only after full verification. Nothing is written to
live system directories and no service starts. Fence the original writers before
following the existing application restoration procedures. Edge/DNS/frontend and
complete-site promotion remain separate work.

## Evidence boundary

Unit verification and a disposable Ubuntu test use synthetic materials. The hosted
test runs all seal/check/open operations in a network namespace without an uplink
and exercises wrong passwords, wrong trust hashes and corrupted repository data.
A successful test proves encrypted material transport and exact recovery only;
it does not validate actual institutional credentials or complete-site restoration.

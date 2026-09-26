# Private portable recovery package

User-authorized continuation of the offline role-software bundle. The institution
must carry crisis tools and recovery material to headquarters without external
sign-in or downloads. This increment transports private recovery material; it
neither captures running databases nor activates restored identities.

## Design

Reuse the pinned Restic executable already carried by the public software bundle.
A local-only encrypted repository holds a copy of an explicitly prepared private
input tree. Require configuration/site.json and configuration/network.json, checked
against existing portable validators. Require nonempty edge, trust, tls,
backup-access, application-backups and operator categories. These categories are
inventory requirements, not proof that credentials, certificates or backups work.
Only regular root-owned private files/directories are accepted; reject
links, special files, path escapes, oversized metadata and concurrent source changes.

Seal copies into private temporary staging, writes an exact file digest manifest,
encrypts into a fresh local repository, performs a full read check and round-trip
restore verification, and publishes by rename only after verification succeeds.
The encryption password remains outside input, output and staging. Accept only a
local checksum-verified pinned Restic artifact. Root-only Linux Ubuntu 24.04 amd64 execution
is enforced; the preparation Mac runs unit tests only.

Check and open require the full snapshot ID and independently retained manifest
SHA256. They read a local repository with no ambient credentials/network backend,
restore only into private staging, and verify exact contents before publishing.
Open requires a new destination and never changes system configuration or starts
services. Repository and decrypted output must be kept on encrypted storage;
deleting temporary plaintext does not promise secure erasure.

## Alternatives and limits

An unencrypted folder is simpler but unsuitable for keys. A custom encrypted
archive adds cryptographic implementation risk. A local Restic repository reuses
existing reviewed dependency identities and standard authenticated encryption.
Restic is therefore selected. Institution source snapshots must already be
consistent, fenced where required, and independently tested. Collecting from live
hosts, automatic OPNsense export/import, complete-site restore, certificate/backup
readiness, SSO and partner federation are separate milestones.

## Acceptance

Unit tests cover unsafe paths/permissions/types, required categories, wrong site
settings, unexpected restored files, corruption, password placement and refusal
to overwrite. A disposable Ubuntu job executes the real pinned Restic under a
network namespace with no uplink and checks seal/check/open round trip, wrong
password, wrong trust hash and repository corruption using synthetic material.
Independent final review and exact test evidence are required before completion.

# Portable offline software and recovery-tool bundle

Goal: collect verified software while connected, then provision the supported
Ubuntu role dependencies and recovery tool from those bytes with WAN unavailable.
Execution is inline with failure-first tests and a separate final review.

The owner approved continuation toward a self-contained portable crisis kit.
Private site configuration, TLS keys, application accounts and encrypted backups
remain separate from publicly shareable software. This increment must not label
file availability as physical-site or full empty-hardware recovery acceptance.

## Contract

- Bundle manifest is strict, content-addressed and bound to an exact source commit.
  Verification requires the expected manifest SHA256 from an independent trusted
  record. A self-generated hash is integrity evidence, not publisher identity.
- Include exact project source, Ubuntu package closure from authenticated official
  archives, target Python wheels, pinned Linux/amd64 image manifests/blobs, and the
  pinned Restic executable distribution. Guest media has separate coverage.
- Preparation runs on disposable Ubuntu 24.04 amd64 with Python 3.12. It acquires
  data only; no application services or private site state enter the public kit.
- Standalone verification/bootstrap uses Python's standard library so Python
  dependencies need not already exist on a replacement guest.
- Bootstrap is explicit, root-only on a fresh supported guest, checksum-verified,
  refuses unexpected existing role state and never falls back to internet.
- Load images with original manifest/config identities; do not rewrite runtime
  pins to convenience tags. Force local container storage.
- Retain the existing application and recovery ownership/fencing contracts.
  Offline backup configuration accepts only the exact pinned local Restic bytes.
- The first live proof is a new pinned Ubuntu guest with its virtual uplink blocked
  before boot, no warmed package/image/wheel cache, both package identities,
  then real portable application startup/restoration fixtures. Proxmox/OPNsense
  and full private site reconstruction remain separately unperformed gates.

## Tasks

1. Write failing manifest tests: trusted-root mismatch, schema/types, path escapes,
   links, special files, size/count limits, changed/missing/extra artifacts.
   Implement focused stdlib manifest verification and safe publication.
2. Build public software from an allowlisted clean tracked revision. Resolve APT
   using isolated official Ubuntu sources and empty dpkg state; retain metadata.
   Acquire only binary wheels; preserve pinned OCI manifest/config identities and
   original Restic checksums. Publish completion only after local verification.
3. Add explicit stdlib bootstrap. Preverify all bytes, stage into an owned private
   directory, suppress package service autostart, install only local debs/wheels,
   import exact images and verify the installed store. Preserve a progress marker
   so retries cannot silently switch bundles.
4. Add guarded local Restic artifact support to backup configuration; test no URL
   access and rejection of wrong artifacts before identity/credential creation.
5. Add operator commands/docs, standalone offline verification, prepared software
   boundaries and a private recovery checklist. Keep all online defaults intact.
6. Add disposable fresh-guest acceptance with WAN disabled before guest boot and
   no package installation by cloud-init. Run current tests, Linux acceptance,
   separate code review, then publish exact evidence in a draft PR.

Local execution evidence: 850 tests and 21 playbook checks passed. Independent
review fixes have regression coverage. Hosted fresh disconnected VM proof is
pending; the draft change must not be described as complete site recovery.

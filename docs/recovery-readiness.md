# Assess the carried recovery kit

This read-only report checks a public role-software bundle and already decrypted,
verified private recovery staging. It makes no network requests, starts no
programs or services, changes no material and prints no private paths, hostnames,
keys or credentials. It uses the assessment machine's clock, whose accuracy must
be independently checked.

The report deliberately separates these states:

| State | Meaning |
|---|---|
| `verified` | The specific byte, schema or certificate check passed |
| `recorded` | Carried files or saved historical evidence exist; operational success was not independently exercised |
| `missing` | A required file, reference or repository layout is absent |
| `expired` | Certificate validity does not cover the required window |
| `stale` | Saved backup/exercise age exceeds the selected limit |
| `invalid` | Evidence is unsafe, inconsistent, changed, malformed or bound to another site/backup |
| `not-tested` | The necessary operational check has not been performed by this report |

Any missing/expired/stale/invalid item gives overall `blocked` and exit code 1.
Otherwise the outcome is `needs-exercise`, exit code 2. This version never returns
an all-ready result or exit 0: complete disconnected reconstruction, actual
credential use and client login still require an exercise. A saved operator
claim cannot turn those checks green.

## Prepare the evidence index before sealing

Copy [the example](../examples/recovery-readiness.json) to
`operator/readiness.json` inside the private recovery input. Edit it there, then
seal a new private package with the existing private-package command. Do not edit
already verified staging: that invalidates its independently retained manifest.
Keep files/directories private using the existing package requirements.

The index contains no secret values, commands, URLs or absolute source paths.
Every reference is a relative path inside its designated category and must match
the exact private manifest before it is read.

- `max_backup_age_hours`: explicit institution policy, integer 1–8760.
- `max_exercise_age_days`: explicit institution policy, integer 1–365.
- `certificates`: exactly frontend chat/Element/files and backend chat/files.
  Each entry gives certificate, private-key and carried CA references, or `null`
  when material is unavailable. Backend chat must cover both chat and Element.
- `backups`: chat/files entries reference a saved native `snapshot.json` and a
  local encrypted repository directory under `application-backups`. The timestamp
  comes from native snapshot metadata, never file modification time. Save this
  metadata alongside the consistent repository copy through controlled snapshot
  preparation; this report does not collect/decrypt it from a live backup server.
- `access`: router export, recovery-credential reference, emergency login
  instructions and runbook. These are presence checks only. The report does not
  parse router configuration or attempt to use a password.
- `exercises`: optional saved chat/files/site restoration records. Leave `null`
  until a real exercise has taken place. Recorded history remains explicitly
  separate from execution by this report.

Example paths are suggestions, not files created by the report. Point the
router-export reference at the actual carried export. A repository layout check
requires config, data, index, keys and snapshot files, but does not prove that the
repository can be decrypted or contains the snapshot named by separate metadata.

## Run without external dependencies

Use independently reviewed source, its prepared Python dependencies, the carried
software directory, the private package's opened staging directory and both
independently retained manifest hashes:

```sh
sudo .venv/bin/python scripts/recovery_readiness.py \
  --software-dir /private/software \
  --software-sha256 SOFTWARE_MANIFEST_SHA256 \
  --private-dir /private/recovery-stage \
  --private-sha256 PRIVATE_MANIFEST_SHA256
```

Add `--json` for machine-readable output. Interpret the documented exit codes;
`needs-exercise` is intentionally not a success signal for automatic deployment.
No report file is written automatically. If saving output, use a private location.
The report can inspect only already decrypted private staging; use the private
package's verified `open` operation first on the supported Ubuntu recovery host.

## What the checks establish

Software and private checks verify every carried byte against independently
retained hashes. The software must also contain the supported role layout; this
is not a substitute for installation acceptance or bootable OS/hypervisor media.
No downstream private evidence is trusted when private verification fails.

Certificates are parsed from the actual carried PEM files. Each leaf must match
its private key and the names derived from the site plan. A certificate path must
validate to the selected carried CA both now and through `offline_days` plus
`certificate_margin_days`; every certificate used in that path must cover the
window. The pinned cryptography 46.0.3 server verification profile is used, which
may reject a chain lacking required extensions even if another TLS client accepts
it. This checks the selected carried trust anchors, not their installation on user
devices. Online revocation is not checked, and the report makes no remote calls.

Backup metadata must match the plan-derived institution, role, application,
addresses, names, image catalogue and managed resource list. Future timestamps,
naive times and inconsistent metadata fail. A recent valid record still does not
prove the encrypted repository matches it, that the password works, or that its
application data restores successfully.

## Recording a real restoration exercise

A record has exactly these fields:

```json
{
  "schema_version": 1,
  "site_sha256": "CANONICAL_SITE_PLAN_SHA256",
  "role": "chat",
  "backup_metadata_sha256": "SHA256_OF_EXACT_SAVED_SNAPSHOT_JSON_BYTES",
  "performed_at": "2026-09-26T12:00:00+00:00",
  "result": "pass"
}
```

Use `chat`, `files` or `site`; record `fail` for an unsuccessful exercise. The
site hash is the existing canonical `portable_network.fingerprint(plan)`. For a
site exercise, the backup binding is that same canonical fingerprint applied to
`{"chat": CHAT_METADATA_SHA256, "files": FILES_METADATA_SHA256}`. Do not use the
outer private-manifest hash, which would create a circular dependency.

Records must match the selected metadata, be no earlier than the backup capture,
not be in the future and fall within the policy age limit. They are protected
against unnoticed transport changes by the enclosing private manifest; they are
not independent attestations or executable proof. Never fabricate a passing
record merely to clear a readiness report.

## Acceptance boundary

Synthetic tests exercise real certificate chain validation, site-bound native
metadata, manifest tampering, privacy, missing evidence and stale/future times.
The report is also run with socket/subprocess calls forbidden and checked for
unchanged input bytes. No real institutional data or live service is inspected.
Complete-site restoration and physical relocation remain later milestones.

All 38 assessment tests passed on disposable Ubuntu with networking disabled at
`abba83e` in [run 36234059897](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36234059897). The complete local suite passed 915 tests.

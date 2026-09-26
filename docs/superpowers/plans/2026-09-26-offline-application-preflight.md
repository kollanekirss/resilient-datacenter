# Disconnected application preparation and installation

Goal: portable chat/files installation must offer an explicit no-download mode,
and identify missing local software before claiming that a machine is prepared.
This is a bounded first step toward the owner's approved self-contained crisis
kit; it does not complete offline reconstruction of the whole site.

Implementation proceeds inline using test-driven development and verification.
No new server is required. Server binaries must not execute on the preparation
Mac. Existing online and overlay behaviour stays compatible.

## Design

Add a read-only `applications-check` command for chat/files on their Ubuntu guest.
Report platform and executable prerequisites, each pinned image's actual local
identity, and explicit NOT TESTED boundaries for certificates, accounts, application
operations and full recovery. Only local filesystem and bounded Podman inspection
are allowed. Unsupported computers cannot report prepared.

Add `--offline` to portable `applications-apply`. Reject this option for unrelated
commands. Before writing the portable ownership marker or requesting an initial
file-service password, require the software check to pass. Both lower-level
installers enforce the same no-download contract, including rerun at consumption.
Missing packages must never trigger APT; missing images must never trigger pull.
Pinned image validation and all existing target ownership/TLS checks remain.

## Tasks

- [x] Write failing tests for missing packages/images, wrong image identity,
      inspection failure, unsupported host and blocked CLI exit status.
- [x] Implement focused local dependency checks and wire read-only CLI routing.
- [x] Write failing tests for both installers' no-download guard and pre-marker
      portable failure; implement explicit offline propagation.
- [x] Update disposable Linux acceptance to prime the reviewed image cache,
      then invoke the real portable installer in offline mode. Retain existing
      WAN-blocked restart and restoration tests; do not call cached install a
      complete empty-host offline rebuild.
- [x] Document commands and the unfinished package-bundle/whole-kit recovery work.
- [x] Run the complete local suite, inspect the diff, record exact evidence.

Review focuses: read-only checks cannot acquire software; malformed inspection
results must block; missing prerequisites must precede ownership mutations;
online callers must remain compatible; a prepared-software result must never be
presented as end-user or whole-site recovery acceptance.

## Execution evidence

2026-09-26: 25 new regressions failed before implementation and pass after it.
The complete local run passed 809 tests and all 21 playbook syntax/read-only
checks. Inline review added refusal of remote Podman environment settings and
real image-identity mismatch tests. No server binary ran on the preparation Mac.
Hosted Linux acceptance is pending at publication; complete offline software
bundling and whole-kit recovery remain future work.

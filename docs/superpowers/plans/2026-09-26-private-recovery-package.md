# Private Recovery Package Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline for this continuation. Final review uses a separate reviewer.

**Goal:** Carry and verify encrypted private recovery material without external services.
**Architecture:** Strict local input tree and exact manifest; pinned Restic local repository; verified staging-only restore.
**Tech Stack:** Python, existing portable validators, pinned Restic, GitHub Ubuntu acceptance.
**Spec:** ../specs/2026-09-26-private-recovery-package-design.md

## Global constraints

No server software on preparation Mac. No live collection, remote repository,
ambient secrets, live restore promotion or real institutional data in CI.

## Review focus

Reject symlinks/special files including parent escapes; never log material/paths.
Keep outer password outside captured material. Fail before overwriting output.
Verify bytes restored, not just Restic exit status. Preserve source permissions
and require private owned output parents. Distinguish inventory from readiness.

## Tasks

- [x] Add failing tests for private tree and manifest contracts; implement focused
  scripts/private_recovery_contract.py with bounded strict JSON and digest checks.
- [x] Add tests for local Restic command/environment, unsupported platform and
  publication failure. Implement scripts/private_recovery_package.py with explicit
  seal/check/open CLI, verified artifact and atomic output publication.
- [x] Add disposable real offline Restic acceptance, operator instructions and
  updated delivery pipeline. Test synthetic materials and adverse cases.
- [ ] Run local checks, independent review and hosted acceptance; publish draft
  stacked PR with exact evidence and remaining limitations.

Local evidence: 877 tests and all local configuration checks passed. Independent
review fixes have RED/GREEN regression coverage. Hosted proof pending.

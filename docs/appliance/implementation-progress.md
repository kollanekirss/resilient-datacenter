# Appliance V1 implementation evidence

This record distinguishes implemented preparation code from the approved product's acceptance gates. Work began on 11 October 2026 from commit `8b35219` in an isolated `feat/appliance-v1` worktree.

| Area | Implemented now | Still required |
|---|---|---|
| B1: inputs and contracts | Strict plan/release parsing, overlap/resource/identity checks; verified downloads and bounded expansion; real base input pins | Optional role binaries, tested hardware budgets, complete redistribution notices and image/runtime qualification |
| B2: installer preparation | Pure confirmation/identity/refusal gate, immutable offline input directory, prerequisite/evidence-integrity checks | Custom bootable ISO, exact upstream adapter, actual Install/Repair entry, offline target staging and every real boot scenario |
| B3: state support | Private durable records, nonblocking locks, uncertain-operation refusal and explicit reconciliation | Local host command boundary and integration into actual host operations |
| B4–B10 | No acceptance claim | Host/router installation, network application/rollback, installed operations, export/repair and physical pilot |
| R1–R6 | No implementation/acceptance claim | Joining, separate hosting roles and complete V1 release |

The project owner confirmed that no disposable x86-64 Linux/KVM machine is currently available. This preparation Mac is ARM64 and has no KVM. The implementation therefore exposes no destructive installation path. Editing an input's qualification field cannot enable one.

The standard existing repository check passed before these changes. New tests were written and observed failing before their implementations. Focused preparation tests exercise actual files, hashes, compression, lock contention, process entry points and explicit refusal behavior; network transport is replaced only where external downloads would make tests nondeterministic.

Final integration verification on 11 October: `.venv/bin/python scripts/check_local.py` exited 0 with **1,116 tests passed**, all Ansible playbook syntax checks and read-only task/host checks passed. These checks required local test-server and Ansible temporary-directory permissions; they made no target connections. `git diff --check` passed. The example layout preview succeeded with destructive actions disabled, the actual Restic preparation command downloaded and verified its inputs, and an independent offline check verified the expanded file. The `install` command returned the expected blocked result and exit 2.

A fresh independent review found no critical issues, two important input-validation issues and one minor interrupted-download error. All three were reproduced and fixed: ordinary Linux driver names containing underscores now pass a dedicated bounded validator; dot-directory disk paths and blank serial/WWN combinations are rejected; interrupted HTTP reads produce a controlled refusal and leave no published artifact. Regression tests failed before each fix and passed afterward; the final integrated checks above include those fixes. No review finding is deferred. Boot behavior, network isolation and recovery remain unjudged because their executing adapters do not exist yet.

Execution decisions:

- The app worktree tool could not resolve the nested repository, so Git created a sibling worktree; the original feature branch remains untouched by implementation.
- Independent media, provenance and lab/state work ran in parallel to honor the request for speed. A separate final reviewer checked the integrated branch, followed by one correction pass and full integration verification.
- The plan's task extractor accepts numeric IDs while this plan uses B/R IDs; briefs were extracted by their exact headings without rewriting the approved plan.
- Without a suitable test host, the batch implements non-destructive preparation and supporting state, while preserving the M0 gate on production installer work. The consequence is explicit: no usable bootable appliance installer is delivered in this batch.
- Required Restic downloads use GitHub's official CDN redirect. A narrow tested exception permits that route; all other redirects remain refused. Content pins remain mandatory.
- The development environment symlink needs its own ignore entry; `.venv/` alone does not ignore a symlink named `.venv`. This keeps machine-specific setup out of the committed product.

No image was booted, USB written, host installed, network changed, role enrolled or software release published during this batch. Upstream OPNsense signature evidence and the exact download checks are in [release inputs](release-inputs.md); those checks do not establish the appliance's boot or network behavior.

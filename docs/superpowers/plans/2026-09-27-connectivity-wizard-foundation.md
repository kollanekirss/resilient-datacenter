# Connectivity wizard foundation implementation

**Goal:** deliver the first independently usable increment of the approved connectivity design: a separate, scope-first planning and checkpoint workflow. It must never suggest that planning has installed infrastructure.

**Spec:** [Connectivity-first design](../specs/2026-09-27-connectivity-foundation-design.md).

**Execution:** implement inline in the existing isolated branch, test first, then independent code review and a draft PR. No host access or deployment is part of this increment.

## Global constraints

- Separate entry point: `./rdc connectivity install`; preserve existing commands.
- No service selection, application downloads, backup questions or automatic handoff.
- No network access, credentials or server mutations in this first increment.
- Public certificate requirements and domestic dependencies must be visible in the plan.
- Atomic private save/resume, strict schema, concurrent-write protection and no adoption of unrelated files.
- Never accept stored claims that an unavailable deployment adapter has configured or verified a stage.

## Files and tasks

1. `scripts/connectivity_plan.py`: strict schema and field validation; `questions(answers)`, `record(answers)`, `validate(record)`, `render(record)`. Derive roles, dependencies and stage states from validated answers; maintain different authority identities for the two networks. Unit tests cover invalid URLs, overlapping role endpoints, bridge collisions, incomplete answers, foreign-only dependencies and forged stage success.
2. `scripts/connectivity_state.py`: `load(path)` and `save(folder, record, expected=None)`, using owned private records, atomic writes, a workspace lock and an optimistic concurrency check. Tests cover permissions, symlinks, unrelated state and stale writers.
3. `scripts/connectivity_wizard.py`: `wizard(folder, resume=None, input_fn=input, output_fn=print)`. Show scope before asking anything, then explicit new/resume/exit. Support `:back`, `:save`, `:cancel` during planning. Review topology before SAVE. Show configured/verified/not-available/next-step checkpoint after save/resume, with unsupported deployment steps clearly identified. Test real flow and the CLI; cancellation must not create state.
4. `scripts/rdc.py`: add `connectivity install --output-dir ... --resume ...`; dispatch only the new wizard. Suppress irrelevant legacy final text for this dedicated entry point. Preserve old CLI tests.
5. `docs/connectivity-installation.md` and README: document implemented scope, current command, saved record, resuming and the remaining adapters. Do not advertise planning as deployment.

## Verification sequence

Write focused regression tests first; run and observe missing behavior. Implement the smallest supporting code; rerun focused checks. Run `scripts/check_local.py`, inspect failures, and complete independent read-only review before publishing. No Linux installation code runs on the preparation Mac.

## Review focus

- EOF/cancellation before saving leaves no misleading completed installation.
- Resume cannot silently overwrite changed or foreign workspace records.
- Arbitrary text in records or invalid inputs cannot become executable commands or leaked credentials.
- A second authority is actually distinct, not merely a differently named role using the same endpoint.
- All six stage states accurately distinguish saved intent from deployment and real verification.

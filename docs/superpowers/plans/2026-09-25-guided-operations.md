# Guided Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Work inline; this side conversation prohibits subagents, including reviewer agents. Steps use checkbox syntax for tracking. Preserve local test evidence in .work/operations/progress.md.

**Goal:** Give the existing networking pilot one understandable command interface, bounded read-only diagnostics, private support reports, source identity and clean-checkout continuous integration.

**Architecture:** A repository-local launcher dispatches to the existing wizard and guarded installation/enrollment backends. Small typed result/check records let the new interface distinguish errors, blocked prerequisites and pending approval without parsing human output; old scripts retain their contracts. Diagnostics have a separate allowlisted report serializer.

**Tech Stack:** Python 3.11+, standard-library argparse/dataclasses/enum/subprocess/socket/ssl, existing PyYAML/cryptography/pytest/Ansible dependencies, POSIX launcher, Ubuntu GitHub Actions runner.

**Spec:** [Approved guided operations design](../specs/2026-09-25-guided-operations-design.md). Implement increment A only; B (distribution), C (certificates) and D (updates) remain separate implementation units.

## Global constraints

- Local installation supports Ubuntu 24.04 amd64 with systemd. Operator preparation remains available on macOS.
- No network client installation/start, host networking changes, cloud purchases or live enrollment on the developer Mac.
- Preserve legacy and schema-1 workflows, infrastructure schema 2, the six-field local manifest and exact ownership guards.
- No implicit package downloads, automatic enrollment, identity reset, TLS bypass, arbitrary Ansible overrides or service start from diagnostics.
- New exit statuses: 0 success, 1 operational failure, 2 invalid input, 3 blocked prerequisite/ownership, 4 pending approval/cancellation. Old direct-script exit behaviour stays compatible.
- Reports exclude manifests, personal/institution names, hostnames, domains, IPs, usernames, paths, arbitrary raw output, environment variables, enrollment URLs, credentials and tracebacks.
- Existing baseline: 184 passing tests, 16 syntax-checked playbooks; live deployment has not been validated.
- No automatic releases, certificate issuance, self-updater, Matrix, Nextcloud or partner gateway in increment A.
- Execute all tasks inline. No agent-based review. Review changes directly before publication.

## Review focus

1. Running the launcher from another directory, through a symlink, or with hostile ANSIBLE_* variables must not change the trusted execution paths (tasks 3 and 5).
2. A user edits an inventory after seeing the confirmation summary: apply must use the validated private snapshot and revalidate on the backend (task 3).
3. A resolver hangs or exposes a private hostname in an exception: doctor must time out, emit a fixed result and save no raw exception (tasks 2 and 4).
4. Pending enrollment and denied local inspection must not become success, reauthentication or an unexpected sudo prompt (tasks 1, 2 and 5).
5. A report destination is a symlink, already exists or is replaced during writing: writing must fail without overwriting another file or publishing an incomplete report (task 4).

## File responsibilities

| File | Responsibility |
|---|---|
| rdc | Locate the project and its prepared Python environment; invoke trusted CLI |
| scripts/rdc.py | Parser, menu, command dispatch, terminal presentation and new exit codes |
| scripts/operation_results.py | Stable action/check records, exceptions, messages and exit mapping |
| scripts/local_checks.py | Structured read-only checks with legacy list-of-errors wrapper |
| scripts/local_node.py | Reusable typed action dispatcher while preserving original script behaviour |
| scripts/infrastructure_operations.py | Strict remote infrastructure validation, snapshot, confirmation and subprocess scope |
| scripts/operation_environment.py | Trusted project Ansible command/environment construction |
| scripts/doctor.py | Aggregate read-only checks; ordered dependency-aware probe handling |
| scripts/diagnostic_probe.py | Isolated timeout-bounded DNS/TCP/TLS worker |
| scripts/support_report.py | Allowlisted JSON projection and exclusive atomic private write |
| scripts/source_identity.py | Source metadata, commit and tracked dirty status |
| project-version.json | Declared development version and metadata schema |
| .github/workflows/local-checks.yml | Read-only Ubuntu CI for the local check suite |
| docs/operations.md | Common interface, diagnostics, exit statuses and scope |

Existing scripts/setup_wizard.py, setup_contracts.py, local_enrollment.py, profile_state.py and installation roles should be reused. Do not reorganize unrelated files.

## Task 1: Structured checks and local action results

**Files:** Create scripts/operation_results.py and tests/test_operation_results.py. Modify scripts/local_checks.py, scripts/local_node.py; extend tests/test_local_node.py and tests/test_local_enrollment.py.

**Interfaces:** Introduce frozen records and an exception carrying a stable code. Terminal text is selected from a fixed catalogue; raw exception strings are never result fields.

```python
from dataclasses import dataclass, field
from enum import IntEnum

class Exit(IntEnum):
    SUCCESS = 0
    FAILED = 1
    INVALID = 2
    BLOCKED = 3
    PENDING = 4

@dataclass(frozen=True)
class Check:
    code: str
    outcome: str  # pass, fail, unknown, not-applicable
    next_step: str

@dataclass(frozen=True)
class ActionResult:
    state: str
    exit_code: Exit
    checks: tuple[Check, ...] = ()
    details: dict = field(default_factory=dict)  # local display only

class OperationError(Exception):
    def __init__(self, code: str, exit_code: Exit):
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)
```

- [ ] Add failure-first tests for state mapping and legacy compatibility. Define `result_for_state(state: str, *, details: dict | None = None) -> ActionResult`: prepared, draft, checks-passed, installed and enrolled map to 0; awaiting_enrollment and cancelled to 4; client_not_running and blocked to 3; failed to 1. Unknown states raise OperationError with FAILED, never default to success.

```python
import pytest
from operation_results import Exit, result_for_state

@pytest.mark.parametrize('state, expected', [
    ('installed', Exit.SUCCESS), ('enrolled', Exit.SUCCESS),
    ('awaiting_enrollment', Exit.PENDING), ('cancelled', Exit.PENDING),
    ('client_not_running', Exit.BLOCKED), ('failed', Exit.FAILED),
])
def test_action_states_have_explicit_exit_codes(state, expected):
    assert result_for_state(state).exit_code == expected
```

- [ ] Run `.venv/bin/python -m pytest tests/test_operation_results.py -q`; observe missing-module/function failures.
- [ ] Add `inspect_local_checks(manifest: dict, *, require_owned=False, check_tls=True) -> list[Check]`. Preserve check_local's existing signature as a wrapper that renders failures through the fixed catalogue. Reuse the current platform, ownership, marker permission, state and client inspection logic; do not broaden supported installations. Catalogue codes include manifest.invalid, platform.unsupported, tooling.sudo_missing, ownership.invalid, ownership.mismatch, client.unavailable, client.inspect_denied and controller.connection_failed. Validate outcomes and next-step IDs when records cross into public rendering.
- [ ] Make read-only inspection return client.inspect_denied/unknown where privilege is insufficient; never invoke sudo or start a service. Preserve install/enrollment's conservative blocking of unverified identity. Existing old wrapper text tests must remain valid.
- [ ] Extract `execute_local(action: str, manifest_path: Path) -> ActionResult` from local_node.main. It validates before operations, calls apply_manifest or existing explicit enrollment_action, and returns typed states. New callers consume records; legacy main renders its old JSON shape and maps to its old exit behaviour. Keep validation/loading errors sanitized.
- [ ] Add tests with injected/mocked subprocess adapters: invalid input invokes nothing, unsupported apply invokes no installer, denied status invokes no sudo, enrolled status invokes no registration, and pending enrollment yields exit 4 only through the new result interface. Reuse existing fixture manifest() and NativeRuntime fake patterns.
- [ ] Run `.venv/bin/python -m pytest tests/test_operation_results.py tests/test_local_node.py tests/test_local_enrollment.py tests/test_profiles.py -q` and fix regressions. Commit only these changes with `feat: expose structured local operation results`.

## Task 2: Bounded read-only doctor

**Files:** Create scripts/doctor.py, scripts/diagnostic_probe.py and tests/test_doctor.py. Extend tests/test_local_tls.py. Consume Check, inspect_local_checks and strict manifest validation from task 1.

**Interfaces:** `diagnose(manifest: dict, *, probe_runner=None) -> tuple[Check, ...]`; `probe_controller(hostname: str) -> list[Check]`. The internal probe worker accepts only `--hostname HOST`; no caller-supplied URLs, ports, command overrides or TLS bypass options.

- [ ] Write failing tests for invalid manifest before probing, non-Linux service checks marked not-applicable, DNS failure, connection refusal, timeout, expired/wrong-host/untrusted certificates, valid TLS and insufficient inspection privileges. Catalogue probe codes: dns.resolve, tcp.connect, tls.verify, tls.expiry, probe.timeout and probe.unavailable. Codes carry outcomes; exception contents never enter Check records.

```python
import subprocess
from doctor import diagnose
from test_setup_contracts import manifest

def test_probe_timeout_is_fixed_and_private():
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('PRIVATE_COMMAND', 15,
                                        output='PRIVATE_OUTPUT')
    checks = diagnose(manifest(), probe_runner=timeout)
    assert any(c.code == 'probe.timeout' for c in checks)
    assert 'PRIVATE_' not in repr(checks)
```

- [ ] Run `.venv/bin/python -m pytest tests/test_doctor.py -q`; confirm failure before implementation.
- [ ] Implement diagnostic_probe using getaddrinfo, a maximum of three resolved candidates on port 443, socket timeouts, default system TLS trust and hostname verification. On verified TLS only, inspect peer certificate validity to emit expiry outcome. Classify certificate failure by structured SSL error information where reliable; otherwise emit a fixed generic trust failure. Do not use an unverified handshake to claim trust.
- [ ] Execute the worker in a subprocess with `sys.executable`, the absolute project worker path and a 15-second outer timeout. This bounds even a stuck DNS resolver. Kill/reap on timeout and cancellation; validate its small JSON output against allowed codes/outcomes and a size cap. The outer timeout bounds the entire controller probe, not each DNS address independently. Tests use fixtures or injected runners; no real controller is contacted.
- [ ] Aggregate local checks without duplicating the TLS probe. Reuse `inspect_local_checks(..., check_tls=False)`; stop identity inspection when platform/ownership dependencies fail. Operator DNS/TLS checks may still run on macOS after validating the manifest. Label dependent checks unknown or not-applicable and explain the earlier failure. Use fixed next-step IDs such as check-dns, check-connectivity, inspect-certificate, inspect-clock, inspect-local-permissions and contact-controller-admin.
- [ ] Extend the existing loopback TLS fixture tests for new structured outcomes. Inject an internal test SSL context/address adapter only in Python tests; no CLI exposure of trust bypass or destination override.
- [ ] Run `.venv/bin/python -m pytest tests/test_doctor.py tests/test_local_tls.py tests/test_local_node.py -q`. Commit with `feat: add bounded read-only network diagnostics`.

## Task 3: Trusted infrastructure operations

**Files:** Create scripts/infrastructure_operations.py, scripts/operation_environment.py and tests/test_infrastructure_operations.py. Modify scripts/local_node.py only to reuse the trusted environment helper. Existing Ansible entry points and guards remain intact.

**Interfaces:** `ansible_environment(root: Path) -> dict[str, str]`; `run_infrastructure(action: str, inventory_path: Path, *, ask_become_pass=False, runner=subprocess.run, confirm_fn=input) -> ActionResult`.

- [ ] Add failing tests: reject local-node/v1 inventories and extra fields before runner calls; check uses preflight without mutation confirmation; apply cancellation invokes no Ansible; apply uses a private validated snapshot even if the original changes at confirmation; inherited ANSIBLE_CONFIG, ANSIBLE_INVENTORY and ANSIBLE_CONNECTION cannot redirect execution.

```python
import os
from operation_environment import ansible_environment
from test_setup_contracts import ROOT

def test_inherited_ansible_overrides_are_removed(monkeypatch):
    monkeypatch.setenv('ANSIBLE_INVENTORY', '/PRIVATE/redirect')
    monkeypatch.setenv('ANSIBLE_CONFIG', '/PRIVATE/config')
    env = ansible_environment(ROOT)
    assert 'ANSIBLE_INVENTORY' not in env
    assert env['ANSIBLE_CONFIG'] == str(ROOT / 'ansible.cfg')
```

- [ ] Run `.venv/bin/python -m pytest tests/test_infrastructure_operations.py -q`; observe missing-feature failures.
- [ ] Implement environment construction by retaining ordinary environment variables, removing all ANSIBLE_* values, then setting the trusted project config/cache/temp paths used today. Do not disable host-key verification or change unrelated global Git/Ansible settings.
- [ ] Strictly load and validate the inventory with check_files=True before any subprocess. Display managed targets and roles locally. Use tempfile.TemporaryDirectory and a mode-0600 JSON/YAML snapshot containing only the validated input. Preserve absolute artifact/certificate paths. Confirmation must precede execution and reference the same in-memory data that is serialized.
- [ ] Construct the fixed argument array: project venv ansible-playbook, `-i SNAPSHOT`, and either infrastructure-preflight.yml or infrastructure-deploy.yml. Run with cwd=ROOT and the trusted environment. Provide a dedicated Boolean CLI `--ask-become-pass` forwarded only as the exact Ansible flag for infrastructure apply. Reject ask_become_pass=True for check. Read-only check uses noninteractive existing management credentials and reports unavailable privilege instead of requesting a password. Never accept a general argument passthrough.
- [ ] Return ActionResult checks-passed or installed only on backend exit 0; cancellation returns 4 and subprocess failure returns 1. Backend output is local terminal output, never a support-report field. Snapshot cleanup runs on success, failure and interruption. Keep enrollment separate.
- [ ] Test actual task/host listing and malformed input with the existing nonconnecting SSH stub, never fixture public addresses. Run `.venv/bin/python -m pytest tests/test_infrastructure_operations.py tests/test_setup_infrastructure.py tests/test_local_node.py -q`. Commit with `feat: guard common infrastructure operations`.

## Task 4: Source identity and private support reports

**Files:** Create project-version.json, scripts/source_identity.py, scripts/support_report.py, tests/test_source_identity.py and tests/test_support_report.py.

**Interfaces:** `source_identity(root: Path) -> dict`; `make_report(checks: tuple[Check, ...], identity: dict, platform_info: dict, *, generated_at: str) -> dict`; `write_report(path: Path, report: dict) -> None`.

- [ ] Add failing source identity tests for a clean Git repository, tracked edits, ignored private files, absent Git, source archives, malformed version metadata, unexpected Git output and bounded command failures. Metadata is exactly:

```json
{"schema_version": 1, "version": "0.2.0-dev", "channel": "development"}
```

- [ ] Implement identity metadata validation and strict component pins from versions.yml. Git commands use a short timeout and explicit root; reject inherited GIT_DIR/GIT_WORK_TREE/index overrides. Confirm git top-level equals root before accepting identity, so an unpacked archive inside another repository cannot inherit its parent's version. Accept only a full hex commit ID and a Boolean tracked dirty status. Missing/invalid metadata becomes unknown/unreleased, with no provenance claim.
- [ ] Run `.venv/bin/python -m pytest tests/test_source_identity.py -q` through failure and passing implementation.
- [ ] Add report projection and file-safety regression tests before implementing report writes:

```python
import json
from operation_results import Check
from support_report import make_report

def test_support_report_uses_an_allowlist():
    report = make_report(
        (Check('dns.resolve', 'fail', 'check-dns'),),
        {'version': '0.2.0-dev', 'commit': 'a' * 40,
         'private_path': '/PRIVATE_PATH', 'token': 'PRIVATE_TOKEN'},
        {'system': 'Linux', 'architecture': 'x86_64',
         'hostname': 'PRIVATE_HOST'},
        generated_at='2026-09-25T00:00:00+00:00')
    assert 'PRIVATE_' not in json.dumps(report)
    assert report['schema_version'] == 1
```

- [ ] Build report output by constructing fresh dictionaries containing only approved fields. Validate every retained value: supported version syntax, hex commit, allowed platform/architecture labels, Boolean dirty state, pinned component version syntax and UTC timestamp. Unknown check codes/next-step IDs map to fixed unknown values or reject serialization; arbitrary strings must not cross the allowlist via a nominally safe key. Generate explanation text from the fixed catalogue, not exceptions.
- [ ] Include only schema_version, generated_at_utc, source, platform and checks at the top level. Do not include ActionResult.details. Redaction is omission by construction, not regex cleaning of raw logs.
- [ ] Write an opt-in report to a private, user-owned directory. Require an existing parent directory to avoid accidental tree creation. Reject symlink parents/targets, directory targets, unsafe ownership/mode and preexisting files. Use a mode-0600 tempfile in that directory, flush/fsync, then exclusive os.link followed by temporary-file unlink. Never replace an existing file. Cleanup temporary files after errors. The doctor result must distinguish report-write failure from the original diagnostic findings.
- [ ] Test bytes/permissions after success; no overwrite on a race; sentinel exception/path values absent; invalid outcomes and malformed Git metadata cannot inject text into reports. Run `.venv/bin/python -m pytest tests/test_source_identity.py tests/test_support_report.py -q`. Commit with `feat: report source identity and private diagnostic results`.

## Task 5: Common launcher, CLI and menu

**Files:** Create executable rdc, scripts/rdc.py and tests/test_rdc.py. Modify scripts/setup_files.py for generated next-step commands. Consume the exact task 1–4 interfaces.

- [ ] Add failing executable tests from a directory unrelated to the repository; missing venv, missing dependencies, path spaces, unsupported command, extra flags and symlink launcher must be deterministic and nonmutating. No-argument invocation on a nonterminal prints help rather than blocking for input. On a terminal show a menu that constructs the same parsed command arguments; cancellation returns 4.
- [ ] Use a POSIX bootstrap that resolves its own directory, refuses symlink invocation with instructions to run the real path, checks for .venv/bin/python, and invokes scripts/rdc.py via exec. Do not run pip in the launcher. Print prerequisite commands with the actual project path and POSIX-safe quoting. Existence of the interpreter does not prove dependencies are available; catch missing imports and provide fixed preparation instructions.

```sh
#!/bin/sh
set -eu
if [ -L "$0" ]; then
    printf '%s\n' 'Run rdc from its real project location, not a symlink.' >&2
    exit 3
fi
RDC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$RDC_ROOT/.venv/bin/python" ]; then
    printf '%s\n' 'Prepare the project Python environment using the README.' >&2
    exit 3
fi
exec "$RDC_ROOT/.venv/bin/python" "$RDC_ROOT/scripts/rdc.py" "$@"
```

- [ ] Run `.venv/bin/python -m pytest tests/test_rdc.py -q`; confirm failures before creating the implementation.
- [ ] Implement `main(argv: list[str] | None = None) -> int` with argparse allow_abbrev=False for every parser. Commands: setup [--resume PATH] [--output-dir PATH]; infrastructure check INVENTORY; infrastructure apply INVENTORY [--ask-become-pass]; node check/apply/enroll/status MANIFEST; doctor MANIFEST [--report PATH]; version. Reject `--extra-vars`, `--limit`, `--tags`, remote inventory injection and arbitrary extra arguments. No automatic apply after setup.
- [ ] Menu options cover prepare configuration, infrastructure check/apply, node check/apply/enroll/status, doctor, version and quit. Prompt for only the paths/options applicable to the chosen existing parser. Use the same dispatch function for interactive and explicit commands. Confirmation remains in action backends; menus cannot skip it.
- [ ] For doctor, invalid input returns 2, a report write or probe operational failure returns 1, unresolved ownership/privilege or unknown required checks return 3, and cancellation returns 4. Completed applicable checks with no failures return 0 while explicitly labelling unsupported local installation checks not-applicable; this must never print installation-ready on macOS. Test these outcomes.
- [ ] Display current-computer versus remote-infrastructure scope clearly. Render known state/check messages from the catalogue. Catch expected OperationError, missing files/dependencies, subprocess errors and Ctrl-C without printing arbitrary exception contents. Fresh node install success says installed, enrollment not verified; draft success says draft saved, not ready to deploy.
- [ ] Test router dispatch with mocked backends and a real private setup wizard interaction. Verify doctor/status do not invoke apply or enrollment, and only explicit enroll can display temporary registration material. Include pending/cancelled exit-code assertions.
- [ ] Update prepare_outputs next-step content to use ./rdc commands while preserving existing bundle filenames, schemas and safe output rules. Test generated join/infrastructure instructions and keep old direct-script examples available in reference docs.
- [ ] Run `.venv/bin/python -m pytest tests/test_rdc.py tests/test_setup_files.py tests/test_setup_wizard.py -q`; smoke-run `./rdc --help` and `./rdc version` from both root and a different cwd. Do not run real apply/enroll. Commit with `feat: add unified guided operations command`.

## Task 6: CI, operator documentation and final verification

**Files:** Create .github/workflows/local-checks.yml and docs/operations.md. Update README.md, CONTRIBUTING.md, docs/guided-setup.md, docs/validation-status.md, scripts/check_local.py only if required to discover the new checks. Existing pytest invocation already collects new test modules.

- [ ] Create the local-check workflow with these verified upstream action commit pins (resolved from each action's v6 tag on 2026-09-25):

```yaml
name: Local checks
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  local-checks:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.12'
      - name: Prepare local dependencies
        run: |
          python -m venv .venv
          .venv/bin/python -m pip install -r requirements.txt
      - name: Run local checks
        run: .venv/bin/python scripts/check_local.py
```

- [ ] Inspect the referenced action metadata before execution and keep pins immutable. Do not add secrets, write permissions, workflow publishing, privileged installation, public network probes or pull_request_target. CI logs must not upload developer .work files or private reports.
- [ ] Document clone/environment preparation, menu and every explicit command, source identity, report privacy/paths, all exit statuses and examples of DNS failure/pending approval. Explain that infrastructure check performs read-only SSH while doctor probes only the declared controller and local state. Distinguish local clock reporting from verified synchronization.
- [ ] Update README's first-run command and link to operations.md. Preserve the old-script reference, experimental status and absence of application services/recovery. Describe the source as development/unreleased until an actual release exists. Document that binary distribution, certificate automation and managed upgrades are separate increments, not hidden command features.
- [ ] Run `.venv/bin/python scripts/check_local.py`, record actual totals and expected dynamic-group warnings. Run `git diff --check`. Review the complete diff and command construction, input contracts, exception paths and report projections. Fix meaningful findings with failing-then-passing regression tests.
- [ ] Verify from an isolated clean source export or worktree with its own prepared dependency environment, excluding ignored build artifacts and inventories. At minimum rerun the full existing check command there; do not reuse files accidentally available only in the developer checkout. Record this separately from hosted CI.
- [ ] Record evidence in docs/validation-status.md and .work/operations/progress.md. Mark real Linux package/service installation, actual node approval, NAT/failover and beginner usability NOT RUN unless observed. Do not invent successful remote CI results.
- [ ] Commit with `ci: verify guided operations and document the interface`. When implementation is approved for publication, push the implementation branch to kollanekirss/resilient-datacenter, create a reviewable PR and attach its URL to this task. Check the hosted CI result if the workflow is allowed to run; report any account approval/quota block without changing billing or permissions. Do not auto-merge or create a release as part of this plan.

## Coverage review and handoff

- Spec action/exit semantics: tasks 1, 3 and 5.
- Guard and compatibility preservation: tasks 1, 3 and full regression in task 6.
- Read-only bounds and platform differences: tasks 1 and 2.
- Safe report projection and file writes: task 4.
- Source identity and archive behaviour: task 4.
- Common user journeys and existing generated instructions: task 5.
- Clean checkout/Ubuntu CI and operator instructions: task 6.
- Certificate lifecycle, verified binary distribution and managed upgrades: explicitly out of increment A; retained as B/C/D in the approved design.

Status: approved and executed inline through implementation and local verification. The original checklist above is preserved as planning detail; actual task evidence and rulings are recorded in .work/operations/progress.md and docs/validation-status.md. Clean-source verification and publication outcomes are recorded there as they complete. No subagents were used.

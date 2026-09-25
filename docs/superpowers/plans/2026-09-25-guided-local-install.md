# Guided Setup and Local Node Installation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline, task by task. No subagents are permitted in this side conversation. Record test evidence and decisions in a project-local ledger; do not initialize Git or publish remotely.

**Goal:** Let an operator prepare offsite infrastructure and install/enroll a home-network node through guided questions without editing YAML or exposing that node's SSH port publicly.

**Architecture:** Add an infrastructure-only schema and a separate, constrained local-node manifest. A question-and-answer interface generates those documents; explicit apply commands call guarded Ansible entry points. Reuse the pinned installation roles and existing enrollment-state inspection. Preparation, installation and enrollment remain distinct actions.

**Tech Stack:** Existing Python 3.11+ tooling, PyYAML, pytest, Ansible Core, pinned Headscale/Tailscale binaries, Ubuntu 24.04 amd64 and systemd. Use Python standard-library CLI/file/TLS facilities; do not add a web framework or another package manager.

**Spec:** [Approved guided-local-install design](../specs/2026-09-25-guided-local-install-design.md).

## Global constraints

- Preserve all legacy and schema-version-1 profile workflows and their existing tests.
- Infrastructure-only inventory uses schema_version 2 and deployment_mode independent; exactly one controller and one relay are remote targets.
- Enrollment-node declarations are permissions requests, never SSH targets.
- Local-node manifest uses kind local-node and schema_version 1; this is a different document contract from inventory schema versions.
- On-host local ownership uses schema_version 2 and install_method local at the existing profile marker path.
- Only Ubuntu 24.04 amd64 with systemd supports local apply. Preparation may run on the operator workstation.
- Never install/start Tailscale on the developer Mac, modify host networking, buy servers, create DNS records or publish to GitHub during implementation.
- No implicit enrollment, reusable enrollment tokens, certificate verification bypasses, state deletion, SSH exposure or firewall replacement.
- No application installation, backup/restore, gateway, automatic certificate issuance or invented resilience claims in this milestone.
- Actual Ubuntu installation, NAT behaviour and enrollment tests remain NOT RUN until disposable test machines and offsite infrastructure exist.

## Review focus

1. A malformed imported manifest smuggles an inventory target, command or Ansible variable: reject before any subprocess or privilege request.
2. A fresh local install silently replaces existing identity or ownership: reject unowned/conflicting installations and preserve matching state.
3. A stopped daemon or pending approval is reported as enrolled: inspect actual state and give a resumable, accurate result.
4. A wizard output overwrites a symlink or unrelated configuration: refuse unsafe paths, use restrictive permissions and require explicit replacement choice.
5. Infrastructure-only deployment accidentally contacts planned home nodes: test exact host/task lists and the absence of client roles/peer targets.

## Files and interfaces

| File | Responsibility |
|---|---|
| scripts/setup_contracts.py | Validate/normalize infrastructure inventory and local manifest; construct ownership |
| scripts/validate_setup.py | Sanitized CLI validation for either new document kind |
| scripts/setup_files.py | Atomic, private wizard outputs and distinct incomplete drafts |
| scripts/setup_wizard.py | Question flow, back/save/resume, summaries and generated instructions |
| scripts/local_node.py | Check/apply/enroll/status dispatcher with strict local scope |
| scripts/local_checks.py | Read-only platform, ownership and TLS checks |
| scripts/local_enrollment.py | Explicit enrollment subprocess, cancellation and state inspection |
| playbooks/infrastructure-preflight.yml | Local validation plus read-only remote controller/relay checks |
| playbooks/infrastructure-deploy.yml | Infrastructure-only installation |
| playbooks/local-node.yml | Fixed localhost client installation after local guard |
| roles/local_node_guard/tasks/main.yml | Local ownership and platform checks before mutation |
| tests/test_setup_contracts.py | New contracts and compatibility rejection |
| tests/test_setup_files.py | Draft/file safety |
| tests/test_setup_wizard.py | Scripted user journeys and generated outputs |
| tests/test_local_node.py | Local-only command selection and privilege boundaries |
| tests/test_local_enrollment.py | Enrollment status, cancellation and safe resume |
| docs/guided-setup.md | Operator-facing preparation and installation instructions |
| docs/local-install-acceptance.md | Disposable Ubuntu and home-network test procedures |

Pure interfaces:

```python
validate_infrastructure(data: dict, *, check_files: bool = True) -> list[str]
normalize_infrastructure(data: dict) -> dict
validate_local_manifest(data: dict) -> list[str]
local_ownership(manifest: dict) -> dict
prepare_outputs(kind: str, configuration: dict) -> dict[str, str]
write_bundle(directory: Path, outputs: dict[str, str], *, overwrite: bool = False) -> list[Path]
platform_errors(system: str, machine: str, os_release: dict, systemd: bool) -> list[str]
```

Infrastructure normalization returns the same safe keys consumed by reusable roles: mode, institution_id, controller_hostname, controller_host, relay_host, policy, roles and ownership. It also returns enrollment_requests. `roles` contains only controller/relay hosts; `policy.grants` is always empty. Local ownership returns exactly the fields required by the specification, including node name/tag and install method.

CLI interfaces, implemented only after their guards exist:

```text
setup_wizard.py                       interactive preparation
setup_wizard.py --resume DRAFT        resume preparation
validate_setup.py FILE --kind infrastructure|local-node
local_node.py check MANIFEST          read-only checks
local_node.py apply MANIFEST          explicit local installation
local_node.py enroll MANIFEST         explicit registration or safe resume
local_node.py status MANIFEST         read-only enrollment summary
```

No CLI accepts arbitrary shell commands, executable overrides or an external inventory for local apply. A wizard may print these commands but never run apply/enroll merely because the user finished answering questions.

## Task 1: New document contracts and infrastructure-only targets

**Files:** setup_contracts.py, validate_setup.py, tests/test_setup_contracts.py, tests/fixtures/setup/, inventories/examples/infrastructure/hosts.yml, examples/local-node.yml.

**Consumes:** existing strict YAML loader, identifier/hostname checks and TLS validation. **Produces:** contract functions and normalized infrastructure facts.

- [ ] Create test fixtures by copying the existing independent fixture, setting schema_version to 2, removing its peers group and moving peer names/tags into all.vars.enrollment_nodes. Add a separate local-node fixture with the exact six fields from the design. Synthetic fixture addresses are never connection targets.
- [ ] Add failing contract tests:

```python
def test_infrastructure_has_no_home_targets(infrastructure):
    assert validate_infrastructure(infrastructure, check_files=False) == []
    result = normalize_infrastructure(infrastructure)
    assert set(result['roles'].values()) == {'controller', 'relay'}
    assert result['policy']['grants'] == []
    assert result['enrollment_requests']

def test_manifest_cannot_supply_execution_settings(local_manifest):
    local_manifest['ansible_connection'] = 'local'
    assert validate_local_manifest(local_manifest)

def test_local_ownership_records_node_and_installation_method(local_manifest):
    record = local_ownership(local_manifest)
    assert record['schema_version'] == 2
    assert record['install_method'] == 'local'
    assert record['node_name'] == local_manifest['node_name']
    assert record['node_tag'] == local_manifest['node_tag']
```

- [ ] Run `.venv/bin/python -m pytest tests/test_setup_contracts.py -q` and observe missing-feature failures.
- [ ] Implement shared primitive validation without relaxing the existing version-1 validator. Extract reusable primitives from profile_config.py only where needed, retaining their original contract and tests. New CLI uses strict duplicate-key/alias rejection and sanitized errors.
- [ ] Reject missing/extra groups, duplicate planned identities/tags, controller/relay collisions with planned node names, invalid types, unsupported versions, blank enrollment lists, unknown keys and template expressions. Infrastructure requires real artifact/TLS files only for deployment validation; public examples remain invalid by default.
- [ ] Add parameterized cross-version tests: old CLI rejects new inventory, new CLI rejects old inventory, local validator rejects an inventory and infrastructure validator rejects a local manifest. Assert secret sentinels never appear in errors. Run the existing suite plus contract tests.

## Task 2: Deploy offsite infrastructure without managing service nodes

**Files:** infrastructure-preflight.yml, infrastructure-deploy.yml, role guard validation interface, tests/test_setup_contracts.py, tests/test_local_node.py.

**Consumes:** normalized infrastructure ownership/policy/roles. **Produces:** a guarded two-host installation workflow.

- [ ] Add a failing task-selection test that reads the new entry point and requires exactly controller and relay installation plays, with no client role and no peers host pattern.
- [ ] Add a full-entry-point invalid-input test with a nonconnecting SSH stub: invalid enrollment declarations must fail before any SSH call. Reuse the existing testing pattern rather than contacting fixture IPs.
- [ ] Implement local validation followed by read-only ownership/platform checks. Reuse controller and relay roles with explicit normalized policy and relay name; retain staged target-binary configuration validation.
- [ ] Generalize the existing profile guard's input interface only as needed to accept explicitly supplied expected ownership from the new validated path. Keep exact-record equality, reverse legacy protection and local-validation prerequisites. Version-1 callers retain their original ownership format and behaviour.
- [ ] Require complete, unfiltered runs. Missing validation facts, wrong schema, tag filters and incompatible markers fail before installation. Do not convert an existing version-1 controller to version 2 automatically.
- [ ] Run Ansible syntax and `--list-hosts --list-tasks` against the synthetic infrastructure fixture. Require only the two managed remote hosts and localhost validation. Add actual localhost template tests proving planned tags appear in tagOwners and grants is explicitly empty. Run legacy/profile regression tests.

## Task 3: Safe wizard outputs and resumable preparation

**Files:** setup_files.py, setup_wizard.py, tests/test_setup_files.py, tests/test_setup_wizard.py, .gitignore.

**Consumes:** validated contract dictionaries. **Produces:** finalized configurations, local-node manifests, instructions or a clearly incomplete draft.

- [ ] Write failure-first file tests covering existing files, symlinks, path traversal in output names and restrictive permissions:

```python
def test_bundle_refuses_existing_target(tmp_path):
    target = tmp_path / 'local-node.yml'
    target.write_text('keep this')
    with pytest.raises(FileExistsError):
        write_bundle(tmp_path, {'local-node.yml': 'replacement'})
    assert target.read_text() == 'keep this'

def test_bundle_refuses_symlink_even_with_replace(tmp_path):
    original = tmp_path / 'original'
    original.write_text('keep this')
    (tmp_path / 'local-node.yml').symlink_to(original)
    with pytest.raises(ValueError):
        write_bundle(tmp_path, {'local-node.yml': 'replacement'}, overwrite=True)
    assert original.read_text() == 'keep this'
```

- [ ] Implement staged temporary files in the selected private directory, mode 0600, with an atomic replacement per file. Preflight all output names/collisions before writing; refuse symlink directories/targets and names escaping the output directory. Interrupted multi-file output must be labelled incomplete until a final bundle manifest is written. Never present a partially written bundle as ready.
- [ ] Implement `prepare_outputs`: independent setup emits infrastructure.yml, one local-node manifest per planned node, and NEXT-STEPS.md; join emits its local-node manifest and instructions. Use deterministic safe file names derived from validated node identifiers. Do not include supplied private-key contents in any generated file.
- [ ] Add scripted wizard tests for independent, join, back, save-draft, resume, invalid answers and cancellation. Inject input/output functions for tests; assert subprocesses are not invoked during preparation.
- [ ] Implement prompts for purpose and required inputs with concise explanations. Display controller, node identities, managed targets and remaining prerequisites before writing. Use a distinct `kind: setup-draft` wrapper for incomplete answers; deployment validators must reject it.
- [ ] If TLS/artifact inputs are unavailable, save a draft and specific next steps. Do not report deployment-ready output. Ask before replacing an existing finalized configuration; cancellation preserves existing files.
- [ ] Default drafts and output to inventories/lab/, already ignored. Cover an operator-selected output directory with a warning to keep private configuration outside a public repository. Run wizard/file/contract tests.

## Task 4: Read-only local checks and guarded client installation

**Files:** local_checks.py, local_node.py, local-node.yml, roles/local_node_guard/tasks/main.yml, tests/test_local_node.py.

**Consumes:** validated local manifest and local machine facts. **Produces:** a check result and an explicit current-machine-only apply operation.

- [ ] Add failing platform tests:

```python
def test_mac_cannot_apply_local_install():
    assert platform_errors('Darwin', 'arm64', {}, False)

def test_supported_ubuntu_platform():
    assert platform_errors('Linux', 'x86_64', {'ID':'ubuntu', 'VERSION_ID':'24.04'}, True) == []
```

- [ ] Add dispatcher tests asserting invalid manifests and unsupported platforms invoke no install subprocess. Supply commands through an internal subprocess adapter in tests, never through imported manifest data or public executable-override flags.
- [ ] Implement read-only checks for platform, root/sudo availability, exact ownership, reserved installation paths, persistent client state, DNS resolution and a timeout-bounded TLS handshake to the declared controller on 443. Use standard certificate and hostname verification; test wrong-hostname, expired/untrusted certificate and unreachable endpoint failures using local TLS fixtures.
- [ ] Treat clock as a diagnostic prerequisite: report local time and certificate validity errors without claiming an unverified clock is synchronized. Do not alter time service settings.
- [ ] Implement fixed localhost-only Ansible execution generated by the trusted launcher. The playbook gathers local facts, independently revalidates the manifest and compares full expected ownership before installing the existing client role. It must not contain controller/relay roles, add_host from user input or remote host patterns.
- [ ] Require the explicit apply subcommand and normal sudo/become authentication. Do not save/capture a sudo password. Show current-machine identity and planned installation before privilege escalation; do not accept raw Ansible flags that bypass local guards.
- [ ] Preserve persistent identity and refuse unowned/mismatched installs, even when the daemon is stopped. Write the ownership marker only after all read-only guards pass. A matching partially completed installation can resume without deleting state.
- [ ] Test task selection, ownership failures and generated launcher arguments locally without executing the installation role. Record Linux package/service execution as NOT RUN; do not use the developer workstation as a live target.

## Task 5: Explicit enrollment, cancellation and accurate status

**Files:** local_enrollment.py, local_node.py, tests/test_local_enrollment.py.

**Consumes:** validated manifest, matching installed ownership and existing profile_state.inspect_peer. **Produces:** explicit enrollment and resumable status with no implicit approval.

- [ ] Add tests for already-enrolled, not-enrolled, awaiting approval, wrong controller/tag, unavailable daemon and cancellation. A matching enrolled node must cause zero enrollment subprocess calls:

```python
def test_matching_enrollment_does_not_restart_registration(local_manifest, enrolled_runtime):
    result = enrollment_action(local_manifest, enrolled_runtime, start_requested=True)
    assert result['status'] == 'enrolled'
    assert enrolled_runtime.started_commands == []
```

Define `enrollment_action(manifest: dict, runtime, *, start_requested: bool) -> dict` in local_enrollment.py. The internal runtime adapter exposes `read_status()`, `read_preferences()`, `start_registration(argv)`, and `cancel_registration()`; it is injected only by Python callers/tests, not by manifest fields. A test adapter records commands and returns controlled state sequences.

- [ ] Confirm the pinned client's registration CLI flags from the matching source/help before constructing commands. Use argv arrays, keep DNS/route acceptance and Tailscale SSH disabled, and never add reset/forced-reauth flags.
- [ ] On explicit enroll, recheck ownership/state first. Start registration only when required, display the pending registration information transiently, and explain independent administrator approval. Do not write registration URLs/IDs to logs or saved reports.
- [ ] Bound polling and handle Ctrl-C by stopping only the launched foreground registration process. Preserve tailscaled and its persistent state. Return a pending/cancelled result; never label it enrolled without rereading verified status.
- [ ] Status/resume uses fresh state inspection. Reuse the existing exact-controller/tag/overlay checks. Reports contain only state, node name, intended controller, safe node ID/address when verified and UTC timestamp.
- [ ] Test that temporary registration sentinels do not appear in captured logs or persisted reports; they may appear only in the explicit interactive registration display. Verify repeated pending/cancelled runs do not reset identity or issue reusable keys.

## Task 6: Instructions, complete regression checks and acceptance handoff

**Files:** docs/guided-setup.md, docs/local-install-acceptance.md, README.md, docs/validation-status.md, scripts/check_local.py.

- [ ] Write supported prerequisites and exact preparation/check/apply/enroll/status commands. Explain how to obtain local tooling on Ubuntu, how to transfer a nonsecret manifest, and which actions run on the operator workstation versus each target. Do not recommend piping an unreviewed remote script into sudo.
- [ ] Document TLS/DNS prerequisites, incomplete drafts, pending administrator approval, blocked ownership changes and interrupted-install resume. Describe network enrollment success separately from absent application/backup capabilities.
- [ ] Extend check_local.py with new unit/integration tests, invalid-example rejection and all new playbook syntax/task-list checks. Keep live installation tasks out of its execution path.
- [ ] Run `.venv/bin/python scripts/check_local.py`. Record actual test counts, expected warnings and unperformed checks. Inspect generated example bundles to confirm home nodes are never SSH targets and all files have intended permissions.
- [ ] Create live acceptance instructions for two disposable Ubuntu VMs/private-network nodes and separate offsite controller/relay machines: install, approval, rerun, reboot, pending/cancelled enrollment, direct/relay observation, and no public management SSH requirement. Mark every live case NOT RUN until executed.
- [ ] Review all command construction, local/remote boundaries, ownership comparisons, output paths and secret handling. Fix meaningful findings with regression tests. Perform review inline because subagents are prohibited.
- [ ] Deliver the operator guide, exact completed local evidence and remaining prerequisites. Do not claim NAT compatibility, beginner usability or successful Linux installation merely from unit tests.

## Coverage and implementation handoff

Task 1 owns document and privilege-input boundaries. Task 2 owns infrastructure-only deployment. Task 3 owns questions, drafts and file safety. Task 4 owns current-machine identity/platform/installation safeguards. Task 5 owns enrollment and resumable state. Task 6 owns usability instructions and honest acceptance evidence.

The five review-focus risks are covered respectively by tasks 1/4, task 4, task 5, task 3 and task 2. All code/deployment work remains inside the approved milestone; real service packages and regional gateways require their own specifications.

Status: implementation completed inline following user approval. Final local evidence: 184 tests and 16 playbook syntax checks passed. Live Ubuntu/NAT/enrollment acceptance remains NOT RUN. Detailed steps above preserve the original planning checklist; current completion evidence and coverage decisions are recorded in docs/validation-status.md and .work/guided/progress.md.

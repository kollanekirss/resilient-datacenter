# Independent and Join Profiles Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task, inline. Do not use subagents in this side conversation. Checkboxes track implementation, not live acceptance.

**Execution status (2026-09-25):** All five local implementation tasks complete. 121 tests and 13 playbook syntax checks passed. Live deployment remains NOT RUN; see [validation status](../../validation-status.md).

**Goal:** Add separately validated independent and join deployment paths while preserving the existing four-host pilot.

**Architecture:** New profile entry points consume a strict versioned static inventory and reuse the existing installation roles. Pure local code validates input, derives owned targets and constructs explicit policy. Join deployment never manages an external controller or relay. Enrollment remains an administrator action.

**Tech Stack:** Existing project Python environment, PyYAML, pytest, Ansible Core, pinned Headscale/Tailscale, systemd and supplied TLS certificates.

**Spec:** [Approved profile design](../specs/2026-09-25-deployment-profiles-design.md). Product context: [expanded product design](../specs/2026-09-25-resilient-services-product-design.md).

## Global constraints

- Initial target support remains Ubuntu 24.04 amd64 with reachable public IPv4 management addresses.
- No cloud provisioning, DNS changes, purchases, live deployment or GitHub publication without the required external inputs and authorization.
- Independent mode manages exactly one controller, one relay and one or more peers.
- Join mode manages one or more peers only; the existing controller is never a managed target.
- New independent application policy is explicit deny-by-default, with only an optional two-peer TCP 8443 test grant.
- Preserve controller keys, client state, service identity and legacy inventory behaviour.
- No automatic reenrollment, controller migration, subnet advertisement or exit-node setup.
- Real inventory, private keys and runtime artifacts stay outside Git.
- The interactive wizard, private/home bootstrap, real applications and regional gateway are separate milestones.
- Work only inside server-connectivity. There is no requirement to initialize Git or commit during this local milestone.

## Review focus

1. Join inventory accidentally includes a controller host or controller credentials: reject before SSH.
2. A stopped client still belongs to another controller: detect ownership mismatch without resetting state.
3. A malformed or absent policy becomes implicit allow-all: always render an explicit grants list and validate with the pinned target binary.
4. Optional tests widen access to unrelated peers: restrict pairing and grants to two unique, explicitly selected nodes with distinct tags.
5. Legacy defaults change after reusable-role edits: run existing fixtures and template tests unchanged throughout.

## Files and interfaces

| Path | Responsibility |
|---|---|
| scripts/profile_config.py | Strict profile loader, structural/file validation and normalized configuration |
| scripts/validate_profile.py | CLI validation; JSON output of nonsecret derived values only |
| tests/fixtures/profiles/*.yml | Independent, join and invalid synthetic fixtures; never used for live connections |
| tests/test_profiles.py | Schema and normalized-policy contract |
| tests/test_profile_deployment.py | Profile task boundaries and legacy compatibility |
| playbooks/profile-preflight.yml | Local validation and read-only target ownership checks |
| playbooks/profile-independent.yml | Only independent installation entry point |
| playbooks/profile-join.yml | Only join installation entry point |
| playbooks/profile-enrollment.yml | Read-only registration guidance and enrolled-state checking |
| playbooks/profile-test-services.yml | Optional selected-pair installation |
| playbooks/profile-verify.yml | Selected-pair HTTPS and denied-port verification |
| roles/profile_guard/tasks/main.yml | Versioned ownership record and mismatch handling |
| inventories/examples/independent/hosts.yml | Invalid-by-default independent public example |
| inventories/examples/join/hosts.yml | Invalid-by-default join public example |
| docs/deployment-profiles.md | Exact supported commands, enrollment responsibilities and limitations |

Keep the existing validator and legacy playbook entry points. Reuse TLS validation; do not fork certificate logic. The pure module exposes:

```python
def load_profile(path: str) -> dict: ...
def validate_profile(data: dict, *, check_files: bool = True) -> list[str]: ...
def normalize_profile(data: dict) -> dict: ...
def expected_ownership(profile: dict, host_name: str) -> dict: ...
```

`normalize_profile` requires already validated input and returns `mode`, `institution_id`, `controller_hostname`, `controller_host` (name or null), `relay_host` (name or null), `peer_names`, `test_pair` (empty list or two names), `policy` (object for independent, null for join), and `enrollment_requests` (name/tag pairs). It must not return keys, tokens or private certificate contents. Ownership records contain schema_version, deployment_mode, institution_id, role and controller_hostname. Helpers raise a sanitized ValueError for invalid input; never interpolate secret values into error messages.

## Task 1: Strict profile input and derived policy

**Files:** scripts/profile_config.py, scripts/validate_profile.py, tests/test_profiles.py, tests/fixtures/profiles/, both new public examples.

**Consumes:** the exact schema from the profile design. **Produces:** the four interfaces above.

- [x] Create fixtures with one independent controller/relay, one join peer, several independent peers and an optional test pair. Use synthetic public addresses only in non-connecting unit tests. Public examples use documentation addresses and must fail deployment validation.
- [x] Write the following contract tests first, with fixture dictionaries loaded by PyYAML:

```python
def test_join_has_no_remote_management(join_inventory):
    assert validate_profile(join_inventory, check_files=False) == []
    normalized = normalize_profile(join_inventory)
    assert normalized['controller_host'] is None
    assert normalized['relay_host'] is None
    assert normalized['policy'] is None

def test_join_rejects_controller_target(join_inventory):
    join_inventory['all']['children']['controller'] = {'hosts': {'remote': {}}}
    assert validate_profile(join_inventory, check_files=False)

def test_default_policy_denies_application_traffic(independent_inventory):
    assert normalize_profile(independent_inventory)['policy']['grants'] == []

def test_test_pair_does_not_grant_third_peer(three_peer_test_inventory):
    grants = normalize_profile(three_peer_test_inventory)['policy']['grants']
    assert len(grants) == 2
    assert all(g['ip'] == ['tcp:8443'] for g in grants)
    assert 'tag:third-peer' not in str(grants)
```

- [x] Run `.venv/bin/python -m pytest tests/test_profiles.py -q`; confirm failures arise from the missing implementation.
- [x] Implement a SafeLoader subclass that rejects duplicate YAML keys; reject unsupported keys and YAML/Jinja expressions in user strings, wrong types, invalid identifiers/tags, repeated names across groups, duplicate addresses/tags, invalid SSH options, unknown mode/schema, forbidden join fields and unsupported federation settings. Reuse existing hostname/TLS validators where compatible.
- [x] Implement conditional file validation: independent controller/relay certificate pairs and DERP checksum are required; peer certificate/CA files are required only for the selected optional test pair. Validate all errors before returning any normalized deployment object.
- [x] Implement explicit policy construction:

```python
policy = {'tagOwners': owners, 'grants': []}
if len(test_pair) == 2:
    first, second = (peer_tags[name] for name in test_pair)
    policy['grants'] = [
        {'src': [first], 'dst': [second], 'ip': ['tcp:8443']},
        {'src': [second], 'dst': [first], 'ip': ['tcp:8443']},
    ]
```

Here `owners` maps each validated independent peer tag to the configured enrollment administrator; join mode returns no policy.

- [x] Add parameterized rejection tests for every input category listed above, including unknown/identical/three-node test pairs and error messages that omit a secret sentinel. Verify both public examples fail deployment validation. Run profile and legacy tests together.

## Task 2: Separate entry points and ownership protection

**Files:** profile-preflight.yml, profile-independent.yml, profile-join.yml, roles/profile_guard/tasks/main.yml, tests/test_profile_deployment.py.

**Consumes:** validated normalized values and `expected_ownership`. **Produces:** correct owned-host task selection and identity-preserving guards.

- [x] Write tests that independent targets resolve to its supplied controller/relay/peer names and join targets contain only peers. Test a join configuration with injected controller vars fails local validation before any remote task.
- [x] Write ownership mismatch tests, covering running and stopped client states:

```python
def test_controller_change_is_a_migration(join_inventory):
    normalized = normalize_profile(join_inventory)
    record = expected_ownership(normalized, normalized['peer_names'][0])
    changed = dict(record, controller_hostname='other.pilot.test')
    assert changed != record
```

Add task-level assertions that mismatched ownership causes an Ansible assertion before any installation role and that daemon liveness is not used to excuse a mismatch.

- [x] Run the new tests and observe failure before implementing playbooks.
- [x] Implement local preflight validation before remote plays. Mark a successful local validation result and require that fact on every remote target so excluding localhost with `--limit` cannot bypass validation. Require the correct mode for each entry point; reject a join inventory passed to independent deployment and vice versa.
- [x] Inspect `/etc/server-connectivity-profile.json` and existing reserved service/state paths before mutation. On a clean host, establish the expected ownership record before installation. On rerun, require exact ownership equality. On an unowned pre-existing installation, reject takeover. Do not infer ownership from the legacy marker alone.
- [x] For managed clients, inspect stored ownership even if tailscaled is stopped. If running, also compare client preferences to the intended controller. Never start another controller's identity merely to inspect it. Fail with migration guidance when recorded and observed ownership conflict.
- [x] Implement independent entry point with controller, relay and client roles; implement join entry point with client role only. Do not include a conditional controller role in the join playbook.
- [x] Run unit tests and both Ansible syntax checks. Inspect `--list-hosts` and `--list-tasks` using the synthetic fixtures; these commands must not contact targets. Record that actual install/rerun remains NOT RUN.

## Task 3: Generalize reusable roles without changing legacy behaviour

**Files:** roles/controller/templates/policy.json.j2, derp-map.yml.j2, roles/controller/tasks/main.yml, profile-independent.yml, tests/test_templates.py, tests/test_profile_deployment.py.

**Consumes:** normalized independent policy and selected relay host. **Produces:** correct configuration for arbitrary supported inventory names, with legacy defaults preserved.

- [x] Add failing render tests for an independent inventory with names `north-control`, `west-relay`, and three custom peer names. Assert only the selected relay appears and the new default policy has an explicit empty grants list.
- [x] Add regression tests rendering existing legacy inputs without new profile variables; require the original two tags, two TCP 8443 grants and relay-01 mapping.
- [x] Run tests, then pass profile policy and relay inventory name explicitly into reusable templates. Use defaults only for the legacy caller. Never fall back to a permissive policy if a new profile value is missing: assert profile inputs before rendering.
- [x] Keep staged configuration validation with the pinned Headscale binary before activation; retain package startup suppression and persistent state paths. No controller source-version upgrade is part of this change.
- [x] Run all template tests and every existing playbook syntax check. Capture target parser validation as pending until deployment.

## Task 4: Explicit enrollment and optional test pair

**Files:** profile-enrollment.yml, profile-test-services.yml, profile-verify.yml, roles/test_service/files/test_service.py, tests/test_profiles.py, tests/test_service.py, tests/test_profile_deployment.py.

**Consumes:** enrollment_requests, test_pair, selected tags and controller hostname. **Produces:** clear registration instructions, read-only state verification, and optional real-HTTPS test reports.

- [x] Add tests that base join deployment needs no endpoint certificates and no test pair; a requested test stage without a pair fails with an actionable message.
- [x] Add tests that endpoint identity accepts a validated arbitrary inventory identifier and rejects empty/unsafe identifiers while retaining overlay-only address validation and real TLS tests.
- [x] Run tests and observe failures before modifying the endpoint argument validator.
- [x] Generate explicit enrollment instructions using validated values. Independent mode names the local administrator; join mode emits a nonsecret request for the receiving administrator. Do not execute enrollment, issue reusable keys, send requests externally or modify remote policy.
- [x] Build the temporary Ansible test group from exactly the validated two peer names. Derive reciprocal peer_name values, and supply the selected CA through the existing test role's interface. Validate actual controller, accepted tags and discovered overlay IPs before installing test endpoints.
- [x] Reuse or extract the current positive/negative verification tasks so both legacy and profile entry points verify TLS identity, known listeners, timeout-only negative results and cleanup. Reports must name the actual pair and timestamp, leaving untested outage/restore scenarios as not-run.
- [x] Run tests with zero, two and three peers, enabling tests only for a valid pair. Confirm the unrelated third peer receives neither test-service tasks nor added grants. Confirm join verification cannot add permission when the receiving administrator has not granted it.

## Task 5: Documentation, local checks and delivery record

**Files:** README.md, docs/deployment-profiles.md, docs/validation-status.md, scripts/check_local.py, both public example inventories.

**Consumes:** completed tasks 1–4. **Produces:** reproducible advanced-operator instructions and accurate validation evidence.

- [x] Document exact independent and join commands using their own examples and entry points. Explain manual enrollment, ownership mismatches, optional tests and the legacy path. No wizard or home-NAT support may be advertised as implemented.
- [x] Extend the local check runner to test both profile examples, all new syntax checks and task selection; assert deployment validation rejects documentation addresses. Keep network calls out of unit tests.
- [x] Run the final offline suite:

```sh
.venv/bin/python scripts/check_local.py
```

- [x] Inspect rendered policy and relay configuration for independent mode and the task list for join mode. Review diffs for secret leakage, hardcoded peer names in the new path, unexpected enrollment commands and state deletion.
- [x] Update validation status with actual test counts, syntax/task-list results and explicit NOT RUN entries for installation, enrollment, live access enforcement, identity preservation and recovery.
- [x] Link the finished operator instructions and state the next external inputs required for live validation. Do not publish to GitHub or claim the broader product is complete.

## Coverage and handoff

Task 1 owns configuration, secrets-safe diagnostics and policy scope. Task 2 owns authority boundaries and persistent ownership. Task 3 owns controller/relay templates and legacy compatibility. Task 4 owns enrollment and optional endpoint verification. Task 5 owns reproducibility and truthful reporting.

The only implementation method available in this side conversation is inline execution with self-review; do not dispatch an independent agent. The user approved this plan and inline implementation. The broader personal/institutional/regional product roadmap does not add application work to this completed networking milestone.

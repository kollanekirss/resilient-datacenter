# Server Connectivity Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Work locally in this side conversation. Do not use sub-agents or change the presentation project.

**Goal:** Produce a locally validated Ansible deployment kit for one Headscale coordinator, one DERP relay and two institutional test servers, ready for later deployment to four VPSs.

**Architecture:** Standard Ubuntu VMs run native system services. Ansible installs version-pinned software and applies explicit network policy. Separate enrollment and application-test stages preserve machine identity and keep bootstrap administration independent of the overlay.

**Tech Stack:** Ubuntu Server 24.04 LTS targets, Ansible Core, Python test tooling, Headscale, Tailscale clients, Tailscale DERP, systemd and TLS.

**Spec:** the original local server-connectivity readiness design (historical planning reference)

## Global constraints

- Target baseline: Ubuntu Server 24.04 LTS. First implementation supports amd64; explicitly reject other architectures rather than installing an incompatible binary.
- Four distinct roles: control-01, relay-01, server-a, server-b.
- Permit A to initiate TCP 8443 to B and B to initiate TCP 8443 to A. Deny other new inter-server application connections.
- No cross-institution SSH, subnet routing, exit node or Tailscale SSH in this milestone.
- Preserve enrolled node identities and state. Never reset enrollment during an ordinary playbook rerun.
- Pin software versions and verify downloaded artifacts. Runtime credentials stay outside Git and logs.
- No cloud provisioning, physical disk changes, broad firewall replacement or local networking changes.
- One relay and one controller provide no high-availability guarantee.
- Offline validation and live integration results must have separate status fields.
- Local root: the project directory. Do not modify the adjacent presentation project.
- Use isolated development dependencies inside this project. Do not alter the system Python environment.
- No GitHub publication or remote repository creation in this phase. Prepare a local Git-ready directory.

## Review focus

1. Incomplete or conflicting inventory must stop deployment before any remote mutation.
2. Missing access policy must never silently fall back to Headscale's allow-all default.
3. A rerun must preserve controller keys, client identities and the selected coordination server.
4. Relay verification, TLS and DNS bootstrap dependencies must be explicit, including controller-outage behaviour.
5. A negative connectivity check must prove a known listener is blocked; a closed port must not count as policy success.

## Intended files and interfaces

| Path | Responsibility |
|---|---|
| README.md | Operator entry point, status, installation sequence and limitations |
| requirements-dev.txt | Pinned local validation dependencies |
| ansible.cfg | Project-local role paths, inventory selection and strict SSH host-key verification |
| inventories/example/hosts.yml | Four non-routable documentation addresses and their roles |
| inventories/example/group_vars/all.yml | Nonsecret deployment inputs with invalid-by-default unset values |
| versions.yml | Exact upstream versions, artifact URLs, checksums and provenance |
| playbooks/preflight.yml | Local input validation and read-only target checks |
| playbooks/deploy.yml | Configure controller, relay and clients in dependency order |
| playbooks/test-services.yml | Configure overlay-only test endpoints after enrollment |
| playbooks/verify.yml | Application reachability checks with structured results |
| roles/controller/ | Headscale package, explicit policy, TLS and private service endpoints |
| roles/relay/ | Standalone DERP service, certificates and verification behaviour |
| roles/client/ | Tailscale installation without implicit enrollment/reset |
| roles/test_service/ | Test responses and HTTPS listeners bound to overlay addresses |
| tools/validate_inventory.py | Pure local checks with nonzero exit status on invalid input |
| tests/ | Inventory, rendered policy, service configuration and verification tests |
| docs/enrollment.md | Explicit administrator-approved node registration |
| docs/networking.md | Public ports, DNS, TLS, management access and firewall prerequisites |
| docs/recovery.md | Consistent controller backup, restore and node-state handling |
| docs/acceptance.md | Live connection, isolation, outage and restart experiments |
| docs/validation-status.md | Exact completed checks and tests awaiting VPSs |
| .gitignore | Ignore real inventory, private keys, credentials, logs and development environments |

Inventories use the groups `controller`, `relay` and `peers`. Peers carry `node_tag` and `peer_name`. Global inputs include `headscale_fqdn`, `derp_fqdn`, `enrollment_admin`, certificate source paths and the pinned software manifest. Overlay addresses are discovered after enrollment; they are not preassigned or guessed.

## Task 1: Inventory and validation contract

**Files:** `tools/validate_inventory.py`, `tests/test_inventory.py`, example inventory, dependency lock, `.gitignore`.

**Consumes:** parsed inventory mapping and software manifest. **Produces:** `validate_inventory(inventory, manifest) -> list[str]`; empty means locally valid. The CLI reads YAML and returns exit status 1 if the list is nonempty.

- [ ] Write failing tests for missing roles, duplicate management addresses, unresolved example domains, invalid tags, absent checksums and embedded private keys.
- [ ] Include a valid four-host fixture with reserved documentation values only in an explicitly named offline fixture mode. Deployment mode must reject the shipped example inventory.
- [ ] Test diagnostic messages without echoing secret input values.
- [ ] Implement the validator and run the full test suite.

Test pattern:

```python
def test_duplicate_host_address_is_rejected():
    inventory, manifest = valid_fixture()
    inventory['all']['children']['peers']['hosts']['server-b']['ansible_host'] = \
        inventory['all']['children']['peers']['hosts']['server-a']['ansible_host']
    assert any('distinct' in error for error in validate_inventory(inventory, manifest))
```

The fixture belongs in `tests/conftest.py`. It must specify each required input and may only use offline validation. Run `python -m pytest tests/test_inventory.py` before implementation to demonstrate the expected failure, then repeat after implementation.

## Task 2: Controller and explicit access policy

**Files:** controller role, its templates/handlers, `versions.yml`, `playbooks/preflight.yml`, `playbooks/deploy.yml`, `tests/test_controller.py`.

**Consumes:** validated inventory and exact package manifest. **Produces:** controller configuration and the explicit grant policy before the service accepts node enrollment.

- [ ] Select a stable Headscale release from its official repository, record exact artifact URLs and verified checksums, and use the configuration example from that same release.
- [ ] Pin the compatible local Ansible/test dependencies in a project virtual environment.
- [ ] Test rendered policy in both directions, proving TCP 8443 is the only authorised peer destination port. Use the selected Headscale release's own validator if executable locally. Treat any custom structural check as a separate, weaker check.
- [ ] Test that policy configuration always refers to the deployed file, metrics remain private and persistent state paths remain outside temporary directories.
- [ ] Add package installation and configuration validation before reload/restart. If the package would autostart before policy exists, suppress its initial service startup until configuration is complete.
- [ ] Keep existing keys and database. A controller with unknown existing ownership/state must fail with an actionable message rather than overwrite it.
- [ ] Use administrator-supplied, valid TLS files for the first deployment. Validate expiry, hostname matching and key/certificate pairing. Do not implement a second certificate-management product in this milestone.

Policy contract to render, with the administrator supplied from validated configuration:

```json
{
  "tagOwners": {
    "tag:institution-a-server": ["lab-admin@"],
    "tag:institution-b-server": ["lab-admin@"]
  },
  "grants": [
    {"src": ["tag:institution-a-server"], "dst": ["tag:institution-b-server"], "ip": ["tcp:8443"]},
    {"src": ["tag:institution-b-server"], "dst": ["tag:institution-a-server"], "ip": ["tcp:8443"]}
  ]
}
```

Confirm this exact syntax against the selected release before claiming policy validation. Denied-port tests must cover 22 and 8444, both directions.

## Task 3: Relay and client services

**Files:** relay/client roles, DERP map template, enrollment and networking guides, `tests/test_network_templates.py`.

**Consumes:** reachable controller/relay names, manifest and validated certificate material. **Produces:** one independent relay, a private relay map, and two unregistered client installations.

- [ ] Select the DERP build from an exact Tailscale source version and record its provenance. If compiling, pin the Go toolchain and modules and produce a checksum for the resulting binary.
- [ ] Test that relay configuration contains only the selected lab relay for the private-relay acceptance experiment. Public fallback must require an explicit alternate profile.
- [ ] Bind public relay HTTPS to TCP 443 and STUN to UDP 3478. Restrict administrative/diagnostic access and keep private files readable only by their service identity.
- [ ] Configure DERP verification against the documented controller endpoint with explicit fail-closed behaviour. State that fresh relay admission may fail during a controller outage; test this separately from existing connections.
- [ ] Install a pinned Tailscale package without running a remote installer shell pipeline.
- [ ] Test that ordinary deployment contains no logout, forced reauthentication, node-state removal, exit-node advertisement or automatic route acceptance.
- [ ] Document interactive tagged enrollment and administrator approval. Check the installed release's CLI help when writing exact commands. Keep registration an explicit operator action.
- [ ] Read-only checks must detect an already-enrolled client using an unexpected controller and stop rather than silently repoint it.

No host firewall replacement is included. The networking guide must list provider firewall prerequisites and the source-limited management SSH rule. Preserve console/management access throughout.

## Task 4: Test endpoints and verification

**Files:** test-service role, `playbooks/test-services.yml`, `playbooks/verify.yml`, `tests/test_verification.py`, `docs/acceptance.md`.

**Consumes:** enrolled peer identities and discovered overlay addresses. **Produces:** TLS test endpoints and a report whose live results are explicit pass/fail/not-run values.

- [ ] Serve a small response identifying the peer on port 8443, bound only to its discovered overlay address. Use certificates trusted by the other peer and verify the hostname.
- [ ] Test the response identity, TLS mismatch, expired certificate and public-address exposure cases. Never use insecure TLS bypass flags to get a passing result.
- [ ] Add an explicitly temporary negative-test listener on port 8444. Verify that it works locally before testing that the other server cannot reach it.
- [ ] Ensure cleanup runs after negative tests even when a step fails. Absence of the listener must make the test inconclusive/failing, not successful.
- [ ] Keep direct/relay observations separate from application-policy results. Record actual selected path and repeat real HTTPS requests when forcing relay transport in the lab.
- [ ] Document controlled direct-path blocking, restoration, controller outage, server restart and second deployment. Do not automatically apply disruptive network fault injection as part of normal verification.

Example result contract:

```json
{
  "scope": "live",
  "allowed_a_to_b": "not-run",
  "allowed_b_to_a": "not-run",
  "denied_a_to_b": "not-run",
  "denied_b_to_a": "not-run",
  "private_derp_path": "not-run",
  "controller_outage": "not-run"
}
```

The verification code must never change `not-run` to `pass` based on a local template check. Test this behaviour directly.

## Task 5: Operations, offline validation and handoff

**Files:** README, recovery guide, validation-status record, optional local check command.

- [ ] Document the sequence: prepare inventory and credentials, validate locally, run read-only preflight, deploy infrastructure, enroll peers, deploy test endpoints, verify connections.
- [ ] Document TLS issuance/renewal as an operator prerequisite for this first version, including redeployment after renewal. Never invent a domain or provision a DNS record.
- [ ] Provide a controller backup procedure that consistently captures database, keys, policy and configuration. A short service stop is acceptable for the lab. Copying a live SQLite main file alone is not the backup procedure.
- [ ] Require encrypted storage outside the controller and protect ownership/permissions on restore. Restore into an isolated environment and prevent two controllers from using the same restored identity simultaneously.
- [ ] Run `python -m pytest`, render the example templates and run `ansible-playbook --syntax-check` for each playbook with the explicit example inventory.
- [ ] Where target binaries cannot execute on this computer, report parser validation as pending rather than treating YAML syntax as application validation.
- [ ] Review every requirement against the readiness blueprint and record all live tests as `not-run` until VPSs exist.
- [ ] Deliver the repository path, the exact successful local checks and the remaining deployment inputs. Do not claim successful installation or connectivity.

## Completion boundary

The offline kit is complete when its files, documentation and local checks exist and pass. Deployment readiness still requires real addresses, trusted certificates and credentials. Operational acceptance requires the live tests from the readiness spec. Those are distinct milestones.

## Review and execution

Implemented locally on 2026-09-24 using inline execution and a final self-review. See [validation status](../../validation-status.md) for exact local results and pending live checks. Implementation adaptations: the static inventory includes its variables in one file; validators live in `scripts/`; dependencies are in `requirements.txt` and `requirements-lock.txt`. Earlier checklist items describe the intended requirements, not proof of live completion. Sub-agents were not used.

## Sources checked

- https://headscale.net/stable/setup/install/official/
- https://headscale.net/stable/ref/policy/
- https://headscale.net/stable/ref/derp/
- https://headscale.net/stable/ref/registration/

Stable documentation can change. The implementation must also retain the exact selected release's configuration examples and CLI compatibility evidence.

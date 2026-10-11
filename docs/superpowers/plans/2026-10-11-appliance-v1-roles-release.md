# Appliance V1 network roles and release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the approved V1 by adding network joining, separately qualified Headscale/DERP hosting, role-state export and whole-product acceptance to the two-port base.

**Architecture:** Build on the [USB and router base plan](2026-10-11-appliance-v1-base.md), preserving its local management and network ownership boundaries. Run each network role in a separate Linux VM, provisioned through a private hypervisor-to-guest channel. Keep desired configuration, eligibility and externally observed verification distinct.

**Tech Stack:** Base-plan Python contracts and local Proxmox tools; one pinned Linux guest image with cloud-init, QEMU guest agent and a fixed appliance helper; pinned Tailscale, Headscale and standalone derper; guest systemd; native role TLS with operator-supplied certificates; existing pinned Restic export adapter; independent Linux probe endpoint.

**Spec:** [Approved two-port network appliance V1 design](../specs/2026-10-11-two-port-network-appliance-v1-design.md).

## Global Constraints

The base plan's global constraints also apply. These additional requirements are copied from the specification.

- “The default journey joins an existing institutional network using a dedicated Linux connector VM.”
- “Neither Proxmox nor OPNsense must join that overlay for local administration.”
- “Joining requires verification of the chosen controller identity and explicit network-owner approval.”
- “Arbitrary subnet routing and application ingress are outside this version; future services must request specific access.”
- “Headscale and DERP remain separate roles and VMs.”
- “If both are hosted, their public HTTPS endpoints must be distinct.”
- “Without an external test endpoint, hosting remains unverified.”
- “Failure of eligibility does not erase an installed authority, switch its identity, or silently claim a successful downgrade.”
- “Never activate a copied controller or enrolled node identity while its original is still active.”

## Review Focus

1. A lost enrollment response must not consume another authorization or create a second node: R1 guest operation journal and R2 identity tests.
2. A successful local HTTPS probe or stale remote receipt must not certify public hosting: R2 challenge receipts and R3/R4 remote qualification.
3. Two different DNS names pointing at the same public IPv4:443 must still be rejected for separate hosted roles: R3 endpoint ownership and R4 combined-role tests.
4. Working outbound connectivity through NAT must not qualify a standalone relay; controller outage must not open relay admission: R4 source-preservation and new-session tests.
5. Export failure during a maintenance pause must restart the original role, protect private state and leave recovered identities inactive: R5 failure injection and isolated inspection.

---

## Execution sequence

R1 begins after B1–B9 interfaces are stable. Complete B10 base acceptance before declaring M1 usable or progressing to physical full-product acceptance. R1–R2 deliver M2, joining an existing network. R3–R6 deliver M3, complete V1. Hardware or external endpoint unavailability is a recorded acceptance blocker, not a reason to fabricate passing evidence or redefine complete V1.

The guest-agent channel avoids adding a host address to infrastructure or exposing guest SSH. Proxmox supports stdin to guest execution with a 1 MiB limit; use small requests and bounded results. This is a trusted local administration path, so VM ownership checks remain mandatory. [Proxmox command reference](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc), [cloud-init integration](https://github.com/proxmox/pve-docs/blob/master/qm-cloud-init.adoc).

For first-release TLS, import a complete publicly trusted certificate chain and its private key through the private guest channel. Validate name, key match, trust chain and lifetime before activation; surface renewal needs 30 days before expiry and support explicit replacement. No public role depends on DNS or certificates reachable only after joining its own overlay. Automated certificate issuance/renewal is not required by this plan; document this operational responsibility clearly.

## Files and shared interfaces

| Path | Responsibility | Owner |
|---|---|---|
| `appliance/guests.py` | Linux image provisioning and bounded guest-agent requests | R1 |
| `appliance/guest/helper.py`, `appliance/guest/state.py` | Fixed role operations and private durable guest state | R1 |
| `appliance/guest/image.py`, `appliance/guest/rdc-guest.service` | Reproducible guest-image contents and initialization | R1 |
| `appliance/connector.py`, `appliance/guest/connector.py` | Approval-aware, identity-preserving enrollment | R2 |
| `appliance/probes.py`, `appliance/probe_agent.py` | Independent endpoint challenge and verification | R2 |
| `appliance/hosting.py` | Separate eligibility and public endpoint ownership | R3 |
| `appliance/headscale.py`, `appliance/guest/headscale.py` | Named authority configuration and lifecycle | R3 |
| `appliance/derp.py`, `appliance/guest/derp.py` | Routed relay configuration and admission | R4 |
| `appliance/guest/snapshot.py` | Consistent role-state capture and bounded readback | R5 |
| `appliance/export.py` | Extend base export with labeled role snapshots | R5 |
| `scripts/ci_appliance_roles.py`, `.github/workflows/appliance-roles.yml` | Disposable role and whole-product acceptance | R2, R6 |
| `docs/appliance/roles.md`, `docs/appliance/qualification.md` | Role prerequisites, renewal and release evidence | R6 |

All record aliases, `ApplianceError`, `identity`, `require`, `Runner`, `Evidence`, ownership checks and B3 private state functions come from the base plan. Role-specific inputs are validated in R1/R3, not passed directly to command execution.

`GuestRequest` is a schema-1 JSON record with `operation_id`, `plan_id`, `role`, `action`, `parameters`; private request values may occur only in `parameters`, delivered on stdin. `GuestReply` contains `operation_id`, `phase=pending|complete|failed`, `code`, `observations` and no secret values. The sole private-response variant, `GuestDataReply`, adds `chunk_base64`, offset, length and digest for `snapshot-read`; only the export adapter consumes it, and its contents are never logged or displayed as status. The fixed helper accepts actions `inspect`, `configure`, `enroll`, `verify`, `snapshot`, `snapshot-read`, `snapshot-cleanup`; it has no arbitrary command action. Exact allowed actions vary by role. For state inspection following a timeout, the same operation ID is queried, not automatically resubmitted.

`ProbeRequest` contains `schema=1`, random `nonce`, `expires_at`, `plan_id`, `build_id`, `capability`, explicit authorized `targets`, expected peer identities and selected relay region. `ProbeReceipt` echoes those bindings and contains observed results, probe identity, creation time and signature. An external probe is selected by the operator, reachable independently of the appliance and administered separately; a VM on the tested host is never classified as that external endpoint. The operator registers its verification key out of band. R2 defines the bounded JSON serialization and signs/verifies it using the locked OpenSSL implementation, rather than custom cryptography.

## Task R1: Shared Linux role image and private guest administration

**Files:** Create `appliance/guests.py`, `appliance/guest/__init__.py`, `appliance/guest/helper.py`, `appliance/guest/state.py`, `appliance/guest/image.py`, `appliance/guest/rdc-guest.service`, `tests/appliance/test_guests.py`, `tests/appliance/test_guest_helper.py`; modify `appliance/releases/v1.lock.json`, `tests/appliance/conftest.py`.

**Interfaces:** Consume `vm_spec`, `ensure_vm`, `observe_vm` from B6. Produce `provision_linux(plan: SitePlan, role: str, runner: Runner, state: Path) -> Json`, `guest_call(vmid: int, request: Json, runner: Runner) -> Json`, `dispatch(request: Json, state: Path) -> Json`, `query_operation(operation_id: str, state: Path) -> Json`. Secret inputs never enter `VmSpec`, cloud-init metadata or the generic image.

- [ ] **1. Write tests** for a foreign VMID, guest-agent absence, oversized requests/responses, unknown helper action, operation response loss, changed image, duplicate machine identity and secrets in command arguments/config drives/logs.

```python
def test_guest_action_cannot_run_arbitrary_commands(tmp_path):
    request = {"schema": 1, "operation_id": "test-op", "plan_id": "p",
               "role": "connector", "action": "shell", "parameters": {}}
    with pytest.raises(ApplianceError) as err:
        dispatch(request, tmp_path)
    assert err.value.code == "unsupported-guest-action"

def test_secret_is_only_sent_on_stdin(runner):
    request = {"schema": 1, "operation_id": "test-op", "plan_id": "p",
               "role": "connector", "action": "enroll",
               "parameters": {"authorization": "synthetic-private-key"}}
    guest_call(101, request, runner)
    assert "synthetic-private-key" not in json.dumps(runner.calls)
```

The runner fixture for the second test returns the owned VM observation and a bounded successful guest response. Record stdin only inside the test fixture for assertions, never in production diagnostic traces.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_guests.py tests/appliance/test_guest_helper.py`; expect failure before implementation.
- [ ] **3. Build the pinned base image and implement fixed helper dispatch.** Use a disposable image-building VM and signed distro repositories, record exact package versions and derived image hash, then validate reproducibility inputs. Include cloud-init, QEMU guest agent, helper, role binaries and the snapshot dependency. Clear machine-id/SSH host keys and any enrolled state before publishing; generate unique identity on first boot. Config drives contain only network assignments, site/role ID and verification material. Disable guest SSH, IPv6, OS forwarding and default cloud-user credentials. Set static infrastructure addresses or the routed relay address according to role; attach exactly one allowed zone.

The host request transport uses this bounded serialization core after ownership verification:

```python
def encode_request(request: Json) -> bytes:
    raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    require(len(raw) <= 512 * 1024, "guest-request-too-large")
    return raw
```

Define `encode_request(request: Json) -> bytes` in `guests.py`. Invoke `qm guest exec VMID --pass-stdin -- /usr/lib/rdc-guest/helper` using the exact syntax qualified against the pinned PVE release. Poll the returned guest PID with bounded time and output; a timeout records pending state and offers inspection. The helper uses per-operation durable private records before enrollment/configuration. Unknown outcome cannot trigger a second enrollment. Image download occurs through the working router and checks the B1 lock; it never grants the host a WAN address.
- [ ] **4. Re-run tests and boot two instances** in the nested lab. Confirm different machine identities, no DHCP/SSH on infrastructure, no stored enrollment key and no extra host/guest management interface. Kill the helper transport after mutation and verify that inspection discovers the original outcome without replay.
- [ ] **5. Commit** with `feat: provision isolated network-role guests`.

## Task R2: Join an approved network and prove useful relay connectivity

**Files:** Create `appliance/connector.py`, `appliance/guest/connector.py`, `appliance/probes.py`, `appliance/probe_agent.py`, `scripts/ci_appliance_roles.py`, `tests/appliance/test_connector.py`, `tests/appliance/test_probes.py`; modify `appliance/guest/helper.py`, `appliance/cli.py`, `appliance/startup.py`, `tests/appliance/conftest.py`.

**Interfaces:** Produce `join(plan: SitePlan, authorization: Json, runner: Runner, state: Path) -> Evidence`, `connector_config(plan: SitePlan) -> Json`, `make_probe(plan: SitePlan, build_id: str, capability: str, targets: list[Json], *, now: int) -> Json`, `verify_probe(request: Json, receipt: Json, trusted_key: Path, runner: Runner, *, now: int) -> Evidence`, `run_probe(request: Json, private_key: Path, runner: Runner) -> Json`. Authorization has controller URL/TLS identity, approving network-owner reference, node name, expiry and one-use enrollment credential; it is never part of status output. Probe requests expire after 15 minutes and cannot be reused as evidence after plan/build/target changes.

- [ ] **1. Write tests** for wrong controller name/certificate, expired authorization, denied owner approval, changed controller on rerun, repeated enrollment after timeout, stale receipt, substituted target, failed negative-control listener and use of a relay different from the requested one.

```python
def test_connector_advertises_no_routes(site):
    config = connector_config(site)
    assert config["advertise_routes"] == []
    assert config["advertise_exit_node"] is False
    assert config["accept_routes"] is False
    assert config["tailscale_ssh"] is False
    assert config["accept_dns"] is False

def test_expired_remote_receipt_is_not_verification(probe, receipt, key, runner):
    result = verify_probe(probe, receipt, key, runner, now=probe["expires_at"] + 1)
    assert result["state"] != "verified"
```

Add `probe`, `receipt`, `key` fixtures containing a real test signing keypair and a current, signed synthetic result; production never trusts these fixture keys.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_connector.py tests/appliance/test_probes.py`; expect failure before implementation.
- [ ] **3. Implement deliberate enrollment and challenge-bound remote proofs.** Verify the public controller identity before handing it authorization. Use a short-lived one-use credential supplied by the network owner; do not require the owner's administrator password. Store the resulting Tailscale state once, delete the consumed enrollment material and refuse authority changes without an explicit new operation. The connector's policy core is:

```python
def connector_config(plan):
    return {"controller": plan["roles"]["connector"]["controller"],
            "advertise_routes": [], "advertise_exit_node": False,
            "accept_routes": False, "exit_node": "", "tailscale_ssh": False,
            "accept_dns": False, "ip_forward": False}
```

The guest helper translates these fields to the pinned client's flags, then reads actual preferences/routes to verify them. Never authorize all ports merely to make a connectivity test pass. The network owner supplies approval for one HTTPS test peer and a policy that denies the unapproved test endpoint. The independent probe proves its denied listener is actually up and reports both endpoint identities plus the fresh nonce. Validate signature, nonce, target list, build/plan bindings, timestamps and complete positive controls before producing `verified`. Missing probe infrastructure yields `unknown` with an action to run the external probe.

For relay acceptance, selectively block direct peer traffic at the disposable lab's boundary while retaining control, DNS, relay transport and required STUN access. Complete real HTTPS and inspect the pinned client's connection diagnostics to prove the selected DERP region carried the flow; another working fallback relay is not a pass. Undo only test-owned firewall rules in a finally path. This tool never applies such disruption to an unspecified production network. Wire resume/startup to inspect existing identity and reconnect, not delete state or reenroll. [Headscale registration](https://headscale.net/stable/ref/registration/).
- [ ] **4. Run unit tests, then** `python3 scripts/ci_appliance_roles.py --suite join --lab-config .work/appliance-lab.json`. Test ordinary upstream NAT with no inbound mapping, authorized HTTPS, denied live listener, forced selected relay, host/router/connector reboot and WAN loss/return. Expected: one unchanged connector identity, no advertised/accepted routes and no management overlay membership. Repeat through an actual independent remote probe before M2 acceptance.
- [ ] **5. Commit** with `feat: join approved networks with verified relay fallback`.

## Task R3: Separate eligibility and a deliberately created Headscale authority

**Files:** Create `appliance/hosting.py`, `appliance/headscale.py`, `appliance/guest/headscale.py`, `tests/appliance/test_hosting.py`, `tests/appliance/test_headscale.py`; modify `appliance/plan.py`, `appliance/router_config.py`, `appliance/guest/helper.py`, `appliance/cli.py`.

**Interfaces:** Produce `eligibility(plan: SitePlan, observations: Json, role: str) -> Evidence`, `endpoint_owners(plan: SitePlan) -> dict[tuple[str, str, int], str]`, `headscale_config(plan: SitePlan) -> Json`, `create_authority(plan: SitePlan, credentials: Json, runner: Runner, state: Path) -> Evidence`. Hosting settings include authority name, public IPv4, DNS name, certificate reference and explicit controller choice; upstream DNAT, if used, records both controlled hops and their ownership. A single external IPv4/protocol/port tuple has one owner.

- [ ] **1. Write tests** for private WAN address mistaken as public reachability, missing DNS, invalid/expired TLS, endpoint collision hidden by distinct names, unknown external proof, and join failure being used to trigger authority creation.

```python
def test_two_names_cannot_share_public_443(site):
    site["roles"]["headscale"].update(selected=True, public_ipv4="198.51.100.10")
    site["roles"]["derp"].update(selected=True, public_ipv4="198.51.100.10")
    with pytest.raises(ApplianceError) as err:
        endpoint_owners(site)
    assert err.value.code == "public-endpoint-conflict"

def test_missing_remote_evidence_stays_unverified(site):
    result = eligibility(site, {}, "headscale")
    assert result["state"] != "verified"
```

Documentation-only IPv4 ranges are allowed in explicitly marked unit fixtures; production public-endpoint validation rejects them.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_hosting.py tests/appliance/test_headscale.py`; expect failure before implementation.
- [ ] **3. Implement independent role decisions and a persistent named authority.** Separate `prerequisites` from `configured` and externally `verified`. Allow controlled/tested upstream DNAT for Headscale; require external DNS/HTTPS before ordinary client enrollment. Validate IPv4 endpoint ownership with this core:

```python
def endpoint_owners(plan):
    owners = {}
    for role in ("headscale", "derp"):
        settings = plan["roles"][role]
        if not settings["selected"]:
            continue
        key = (settings["public_ipv4"], "tcp", 443)
        require(key not in owners, "public-endpoint-conflict")
        owners[key] = role
    return owners
```

Check ownership against all configured publication rules, including router administration, not just the two requested roles. Configure Headscale with embedded DERP disabled, native TLS, explicit deny-by-default policy, persistent database/key paths and independently usable local guest-agent administration. Validate the configuration with the pinned Headscale version before replacing it. Require a deliberate `roles create-controller` action naming the new authority; generic join failure cannot call it. Enroll disposable verification clients first and withhold ordinary-client readiness until a fresh external enrollment and allow/deny test pass. Joining the newly created authority is a separate explicit connector action.

Update router policy through B7's restricted authenticated operational channel, preserving WAN administration restrictions and exact current-config checks; do not edit router XML while assuming it is already active. A failed eligibility recheck reports blocked/unknown while retaining the installed authority's identity and data. Certificates and keys travel privately, and expiry/renewal status is surfaced separately. [Headscale public deployment requirements](https://headscale.net/stable/setup/requirements/).
- [ ] **4. Run tests and** `python3 scripts/ci_appliance_roles.py --suite headscale --lab-config .work/appliance-lab.json`. Exercise direct public addressing and controlled upstream DNAT, missing DNS, wrong certificate, new remote enrollment, allow/deny policy, restart and certificate replacement. Expected: local setup remains usable through the guest agent during public-path failure; the authority identity never changes automatically.
- [ ] **5. Commit** with `feat: qualify and host a separate Headscale authority`.

## Task R4: Publicly routed standalone DERP with fail-closed admission

**Files:** Create `appliance/derp.py`, `appliance/guest/derp.py`, `tests/appliance/test_derp.py`; modify `appliance/hosting.py`, `appliance/router_config.py`, `appliance/guest/helper.py`, `appliance/cli.py`, `scripts/ci_appliance_roles.py`.

**Interfaces:** Produce `derp_config(plan: SitePlan) -> Json`, `relay_policy(plan: SitePlan) -> Json`, `configure_relay(plan: SitePlan, credentials: Json, runner: Runner, state: Path) -> Evidence`. Relay settings include stable public VM address/prefix, router-side gateway, upstream routed allocation, region ID, DNS/TLS endpoint and selected Headscale verification URL. Eligibility consumes observed inbound/outbound source addresses and external STUN/relay results, not just declared topology.

- [ ] **1. Write tests** for NAT/CGNAT, missing return route, inherited outbound NAT, unknown client, unreachable verifier, colliding public endpoint, source rewrite and different relay region carrying a successful request.

```python
def test_relay_admission_is_fail_closed(site):
    config = derp_config(site)
    assert config["verify_client_url_fail_open"] is False
    assert config["verify_client_url"].endswith("/verify")

def test_relay_segment_is_excluded_from_nat(site):
    policy = relay_policy(site)
    assert policy["inbound_translation"] is False
    assert policy["outbound_translation"] is False
    assert policy["preserve_client_source"] is True
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_derp.py`; expect failure before implementation.
- [ ] **3. Implement the explicit routed profile.** Add the owned internal relay bridge without a host IP and the router's corresponding routed interface. The upstream routes the public allocation through OPNsense; the DERP VM holds its own public IPv4 and returns through OPNsense. Firewall only the selected profile's required public services, including TCP 443/80, UDP 3478 and required ICMP. Exclude the relay prefix from outbound NAT and apply no inbound address translation. The relay retains client source addresses and its own public source on return/outbound traffic. A public address on the router with private NAT to the relay is ineligible.

Configure the selected controller verifier and explicitly disable the documented fail-open behavior:

```python
def derp_config(plan):
    settings = plan["roles"]["derp"]
    return {"region_id": settings["region_id"], "hostname": settings["hostname"],
            "verify_client_url": settings["controller_url"].rstrip("/") + "/verify",
            "verify_client_url_fail_open": False}
```

Make verifier reachability an explicit policy dependency. For a co-located controller, resolve its certificate-matching hostname to its infrastructure address inside the relay guest and permit only the relay-to-controller TCP 443 flow across those zones; do not depend on implicit NAT reflection. External clients continue to use public DNS. For an external controller, use its independently reachable public endpoint. Test both arrangements, plus denial of relay access to management and unrelated infrastructure listeners.

Verify the pinned derper supports and receives `-verify-client-url-fail-open=false`; reject a binary/config that lacks this behavior. Create identity only once. Delay publication as an available relay to ordinary clients until independent tests pass. Test remote client source as observed by the relay and relay public source as observed remotely; compare both to known endpoint addresses. Test new-session rejection with an unknown identity, then while the verifier is unreachable. Existing sessions are recorded separately, not used to claim admission behavior. [Headscale relay verification](https://headscale.net/stable/ref/derp/).

The standalone server's documented direct-connectivity restriction is a release gate for this routed topology. Do not infer that a rendered no-NAT rule is sufficient. Qualify actual client/relay/STUN operations through the selected upstream and OPNsense version. [Tailscale standalone relay requirements](https://tailscale.com/docs/reference/derp-servers/custom-derp-servers).
- [ ] **4. Run tests and** `python3 scripts/ci_appliance_roles.py --suite derp --lab-config .work/appliance-lab.json`. Include the external routed allocation, real relayed HTTPS, STUN, public source preservation, verifier outage and both hosting roles together on distinct endpoints. Simulated routing covers development behavior; absence of an actual routed allocation leaves public hosting NOT RUN, never verified. Joining through an external relay remains supported.
- [ ] **5. Commit** with `feat: qualify routed DERP hosting and deny unverified admission`.

## Task R5: Consistent private role exports without identity activation

**Files:** Create `appliance/guest/snapshot.py`, `tests/appliance/test_role_export.py`; modify `appliance/export.py`, `appliance/guest/helper.py`, `appliance/cli.py`, `docs/appliance/repair.md`.

**Interfaces:** Produce guest `snapshot_role(role: str, operation_id: str, state: Path, runner: Runner) -> Json`, `snapshot_read(snapshot_id: str, relative_path: str, offset: int, limit: int) -> Json`, `snapshot_cleanup(snapshot_id: str) -> None`; host `collect_roles(plan: SitePlan, runner: Runner, staging: Path) -> dict[str, Path]`. Snapshot metadata binds role, original identity, component versions, timestamp, declared file paths/sizes/hashes and restart outcome. Readback is at most 256 KiB raw per request, encoded in bounded JSON; snapshot paths are resolved from the stored manifest, never arbitrary guest paths.

- [ ] **1. Write tests** for capture failing after service stop, restart failing independently, incomplete SQLite state, truncation/reordered chunks, unsafe paths, wrong password and recovered identity accidentally entering a live network.

```python
def test_failed_capture_still_attempts_restart(snapshot_runner, tmp_path):
    with pytest.raises(ApplianceError):
        snapshot_role("headscale", "capture-one", tmp_path, snapshot_runner)
    assert ["systemctl", "start", "headscale.service"] in snapshot_runner.calls
```

The fixture scripts a successful stop, a capture failure and successful restart; an additional fixture makes restart fail and requires both outcomes in the redacted report.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_role_export.py`; expect failure before implementation.
- [ ] **3. Implement a declared maintenance pause.** Lock configuration changes, stop one selected role at a time, copy its complete declared state to private guest staging, hash it and restart the original role even when capture fails. Record Headscale's database plus any SQLite sidecars, policy, configuration, keys and versions together. Capture connector enrollment state and relay identity/configuration under separate role manifests. Never reuse a config-only export as a complete authority snapshot. Define `capture_files(role: str, state: Path) -> Json` and `service_name(role: str) -> str` in the guest snapshot module; the latter maps only the three allowed roles to fixed unit names. Use this structure:

```python
def snapshot_role(role, operation_id, state, runner):
    unit = service_name(role)
    captured, capture_error, restart_error = None, None, None
    try:
        runner.run(["systemctl", "stop", unit])
        captured = capture_files(role, state)
    except ApplianceError as error:
        capture_error = error.code
    finally:
        try:
            runner.run(["systemctl", "start", unit])
        except ApplianceError as error:
            restart_error = error.code
    result = {"operation_id": operation_id, "snapshot": captured,
              "capture_error": capture_error, "restart_error": restart_error}
    write(state / (operation_id + ".snapshot.json"), result)
    require(restart_error is None, "role-restart-failed")
    require(capture_error is None, "role-capture-failed")
    return result
```

Validate operation IDs before constructing paths, verify the service actually stopped before capture and bound the whole pause. Even a stop command with a lost response must lead to a restart attempt. Interrupted capture is reconciled on next guest boot: restart the original role, discard incomplete staging and report the failed export. Read snapshots over the existing guest-agent channel in hashed chunks. Plaintext exists only in root-private staging on the trusted guest/host; the published export is encrypted by B9's Restic adapter. Bound aggregate size using release budgets, reject missing/extra paths, and remove temporary access/material on success or failure with crash cleanup on restart. Do not build a new cryptographic format or expose backup transfer over WAN.

Verify decryption into an isolated directory using the independently held credential. Validate all role manifests and versions without starting a restored controller/connector. B9's isolated router reimport remains the recovery acceptance claim. Full controller reconstruction is explicitly outside V1.
- [ ] **4. Run tests and** `python3 scripts/ci_appliance_roles.py --suite private-export --lab-config .work/appliance-lab.json`. Export with all roles running, inject capture/transport/restart failures, decrypt independently and confirm original identity continuity. Expected: no success with incomplete state, no plaintext published, no restored identity activated.
- [ ] **5. Commit** with `feat: export consistent private network-role state`.

## Task R6: Whole-product qualification and release packaging

**Files:** Modify `scripts/ci_appliance_roles.py`, `appliance/checks.py`, `appliance/releases/v1.lock.json`, `README.md`, `docs/appliance/install.md`, `docs/appliance/evidence.md`; create `.github/workflows/appliance-roles.yml`, `tests/appliance/test_v1_release.py`, `docs/appliance/roles.md`, `docs/appliance/qualification.md`.

**Interfaces:** Produce `v1_release_allowed(base: list[Evidence], roles: list[Evidence], qualification: Json) -> bool`. The qualification record declares exact build/source/lock identities, exercised resource budgets, physical hardware profile, separate independent-endpoint identity and each acceptance case. Missing, mismatched, failed, synthetic or NOT RUN evidence rejects the V1 release label. Installation status can legitimately show a role `not-selected`; product qualification must still exercise every supported role/profile.

- [ ] **1. Write tests** for base-only evidence, no external relay proof, mismatched source build, missing resource measurement, synthetic evidence and unchanged status after a relevant configuration change.

```python
def test_base_preview_is_not_complete_v1(base_results):
    assert not v1_release_allowed(base_results, [], {})

def test_skipped_hosting_case_blocks_v1(base_results, role_results, qualification):
    role_results[0]["state"] = "unknown"
    assert not v1_release_allowed(base_results, role_results, qualification)
```

Define `role_results` and `qualification` as complete synthetic contract fixtures in `conftest.py`; unit tests explicitly bypass neither production provenance nor the final publisher's fixture rejection.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_v1_release.py`; expect failure before implementation.
- [ ] **3. Complete the release gate and operator documentation.** Required role case IDs are `join-nat`, `relay-path`, `controller-hosting`, `standalone-relay-hosting`, `both-hosting-roles`, `role-identity-restart`, `private-role-export`, `full-operator`. Require every base case from B10 as well. The membership core is:

```python
ROLE_CASES = {"join-nat", "relay-path", "controller-hosting", "standalone-relay-hosting",
              "both-hosting-roles", "role-identity-restart", "private-role-export",
              "full-operator"}
```

Match outcomes to actual role selection and supported topology; a site's lack of hosting eligibility is an expected installer outcome, not an overall product test failure, but the release still needs separate eligible hosting test deployments. Re-run negative hosting scenarios: no public IP, private static WAN only, CGNAT, DNS/TLS absent, verifier unreachable, conflicting public endpoints and lost independent test endpoint. Verify all report separate reasons while leaving local management, existing identities and remote-relay joining usable where their own checks pass.

Add a one-page wiring/setup path with roles explained in ordinary language, required routed allocation for DERP, authority ownership, certificate replacement/expiry workflow, password/export custody and independent-probe procedure. Include offline/no-WAN limitations, single-host failure domain and the distinction between useful connection and application deployment. Exercise the full released USB journey, join, reboot, chosen hosting roles, export and router repair with an operator other than the implementer. Do not publish or deploy to a user site as part of tests; release publication follows the repository's ordinary authorized delivery process.
- [ ] **4. Run** `.venv/bin/python -m pytest -q tests/appliance/`, `.venv/bin/python scripts/check_local.py`, `python3 scripts/ci_appliance_base.py --suite all --lab-config .work/appliance-lab.json` and `python3 scripts/ci_appliance_roles.py --suite all --lab-config .work/appliance-lab.json`. Complete fresh physical and independent-public-endpoint exercises with matching build hashes. Expected: full regressions and every acceptance case pass, or the report explicitly withholds the complete V1 label.
- [ ] **5. Commit** with `test: qualify complete network appliance v1`. Produce checksummed installer, input/output manifests, provenance notices, operator guides and redacted evidence together. Keep private site plans/exports and signing secrets out of reusable release artifacts.

## Acceptance coverage and handoff

| Approved specification exercise | Tasks |
|---|---|
| Offline USB; erase refusal; port mapping | B1, B2, B4, B5, B10 |
| WAN exposure; virtual routing/separation | B4, B6, B7, B8, B10 |
| Router stopped; boot without WAN | B4, B8, B9, B10 |
| Join behind NAT; selected relay path | R1, R2 |
| Controller hosting | R3 |
| Standalone relay hosting; both roles | R3, R4 |
| WAN loss/return; identity-preserving interrupted setup | B3, B8, R1, R2, R6 |
| Configuration export and isolated repair | B9, R5 |
| Unfamiliar operator on real hardware | B10, R6 |

Review both plans before implementation. The recommended execution method is a fresh implementer and reviewer for each task, because early disk/network mistakes can make later tests misleading or leave an operator without access. Tasks B1–B2 form the first execution batch; no later milestone should be marked complete from their feasibility evidence alone.

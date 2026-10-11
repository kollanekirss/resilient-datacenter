# Appliance V1 USB and two-port base Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a bootable USB image that safely installs Proxmox and an offline OPNsense router, with independent local management through the first of two physical Ethernet ports.

**Architecture:** Keep the new appliance in a small Python package within this repository, separate from the earlier service toolkit. Wrap a pinned official Proxmox installer with a custom live-media safety gate; install a local control menu and stage the OPNsense ISO on internal storage. Proxmox owns bridges and host access; the router VM owns guest routing and upstream access.

**Tech Stack:** Python 3 standard library on the installed Proxmox host; pytest for developer tests; official Proxmox installer and local `qm`/`pvesh` tools; Linux bridges and the release's supported Proxmox firewall; OPNsense community DVD ISO; systemd; pinned Restic for private exports; QEMU/KVM on a disposable Linux acceptance runner.

**Spec:** [Approved two-port network appliance V1 design](../specs/2026-10-11-two-port-network-appliance-v1-design.md).

## Global Constraints

The following requirements are copied from the approved specification; every task inherits them.

- “The appliance uses exactly two physical Ethernet ports: management and Internet/upstream.”
- “The installed host boots from internal storage; the USB is installation and repair media, not its permanent operating disk.”
- “The initial network profile supports Ethernet upstream access using DHCP or operator-supplied static IPv4 settings.”
- “IPv6 is explicitly disabled for this profile, including automatic host addresses on WAN and guest bridges, rather than silently bypassing IPv4 policy.”
- “Proxmox never obtains a temporary WAN address to download the router.”
- “No ordinary guest joins management or WAN.”
- “DHCP never serves the physical management or WAN segment.”
- “No shared password, controller private key, relay identity or enrolled client state is baked into a reusable image.”
- “A base-only build may be published as a preview, but must not be labelled the complete version 1 defined here.”

## Review Focus

1. A renamed disk, duplicated serial, stale confirmation or USB left inserted must not cause an unintended erase: B2 and B5 destructive-gate tests.
2. A live upstream offering DHCP and IPv6 router advertisements must never give the installer or host a WAN address: B2 live-boot capture and B4/B10 installed-host probes.
3. Power loss between writing configuration and confirming management must recover the last good configuration: B3 journal, B4 boot-time rollback and B9 repair tests.
4. A running VM with its live ISO still attached must not count as an installed router: B6/B7 disk-only boot tests.
5. A connection timeout against a nonexistent service must not count as firewall isolation: B8/B10 use known listening endpoints and positive controls on both sides.

---

## Delivery order and boundaries

Status: implementation plan prepared after specification approval on 11 October 2026. No installer has been built or qualified by writing this plan.

| Milestone | Work | Exit evidence |
|---|---|---|
| M0 — prove the media approach | B1–B2 | Pinned media boots a safe menu; cancellation leaves disks unchanged; an offline installed host boots after USB removal. |
| M1 — usable base preview | B3–B10 | Two-port installation, installed router, virtual routing, router-down management, export and repair pass in the lab and on real hardware. |
| M2 — join an existing network | [R1–R2 in the roles plan](2026-10-11-appliance-v1-roles-release.md) | Connector joins behind NAT; approved traffic and forced relay work; identity survives restart. |
| M3 — optional hosting and complete V1 | [R3–R6 in the roles plan](2026-10-11-appliance-v1-roles-release.md) | Separate controller/relay eligibility, remote proofs, private role-state exports and unfamiliar-operator acceptance pass. |

Implement M0 first. Its failure blocks production installer work, rather than allowing weaker disk or WAN safeguards. A revised upstream integration must pass the same gate. Do not silently substitute an online Debian bootstrap or let the stock installer run first.

Planning choices to qualify in M0: UEFI boot with Secure Boot disabled; one internal disk using the official installer's ext4/LVM-thin layout; exactly two selected wired NICs, with additional NICs left down. These narrow the first tested hardware profile; publish only modes actually qualified. Start the lab with 4 vCPU, 16 GiB RAM and a 128 GiB virtual target disk. These are test allocations, not advertised minimum requirements. Measure and record supported base and selected-role resource budgets before release.

The planning workstation can run pure tests and review documents. ISO assembly and nested boot tests run on a disposable x86-64 Linux machine with KVM and explicit lab configuration. Physical USB writing and physical installation require the operator to identify the target device; implementation must never infer permission to erase the development workstation.

## Evidence behind the installer choice

The upstream live launcher currently configures networking before starting installation; static installed settings alone do not prevent that. The first-boot hook runs on the installed system, after erasure. The appliance therefore needs a custom live entry before upstream networking and destructive execution. Pin and inspect the exact shipped source rather than assuming upstream `master` matches an ISO. [Proxmox live launcher](https://github.com/proxmox/pve-installer/blob/master/unconfigured.sh), [first-boot unit](https://github.com/proxmox/pve-installer/blob/master/proxmox-first-boot/etc/proxmox-first-boot-network-pre.service).

Use the official low-level installer through its automated front end, retaining its storage installation work. Generating answers, suppressing live DHCP, staging the large payload and guarding repair are appliance integrations. The first-boot executable is small; it is not the carrier for the OPNsense ISO. [Automated installer](https://github.com/proxmox/pve-installer/blob/master/proxmox-auto-installer/src/bin/proxmox-auto-installer.rs), [shared limits](https://github.com/proxmox/pve-installer/blob/master/proxmox-installer-common/src/lib.rs), [target mount helper](https://github.com/proxmox/pve-installer/blob/master/proxmox-chroot/src/main.rs).

OPNsense's live environment is not a completed persistent installation. Use the DVD installer and qualify a guided console path, including configuration import, against the selected release. [OPNsense installation](https://docs.opnsense.org/manual/install.html), [virtual machine guidance](https://docs.opnsense.org/manual/virtuals.html).

## File and ownership map

Paths below are relative to the repository root. New package code must not import the old `portable_plan` or its application topology. Reuse the durable-file, bounded-download and uncertain-operation algorithms from `scripts/portable_state.py`, `scripts/guest_media.py` and `scripts/guest_installation.py`, with appliance-specific contracts and tests. Leave existing behavior compatible.

| Path | Responsibility | Owner |
|---|---|---|
| `appliance/contracts.py`, `appliance/plan.py` | Strict JSON contracts, identities, site validation and resource accounting | B1 |
| `appliance/media.py`, `appliance/releases/v1.lock.json` | Verified input artifacts and provenance | B1 |
| `appliance/installer/media.py`, `appliance/installer/live.py` | ISO assembly and earliest live entry | B2, B5 |
| `appliance/installer/adapters/pve.py` | Exact-release upstream handoff and target staging | B2, B5 |
| `appliance/installer/first_boot.py` | Local installed-system handoff before networking | B5 |
| `appliance/state.py`, `appliance/runner.py` | Private durable records; bounded local command execution | B3 |
| `appliance/host_network.py`, `appliance/rollback.py` | Owned host configuration and management confirmation | B4 |
| `appliance/proxmox.py` | Owned VM allocation, media, fixed MACs and observed boot | B6 |
| `appliance/router_config.py`, `appliance/router.py`, `appliance/router/helper.php` | Router policy, restricted management channel, bootstrap and WAN activation | B7 |
| `appliance/checks.py`, `appliance/startup.py` | Fresh evidence and dependency readiness | B8 |
| `appliance/cli.py`, `appliance/__main__.py`, `rdc-appliance` | One menu and matching commands | B5, B8 |
| `appliance/export.py`, `appliance/repair.py` | Encrypted configuration export and guarded repair | B9 |
| `appliance/systemd/` | Exact units named in B4, B5 and B8 | Respective task |
| `tests/appliance/`, `tests/fixtures/appliance/` | New isolated test suite and sanitized fixtures | Respective task |
| `scripts/ci_appliance_base.py`, `tests/appliance/lab.py` | Disposable boot/network acceptance | B2, B10 |
| `docs/appliance/install.md`, `docs/appliance/repair.md`, `docs/appliance/evidence.md` | Released operator journey and evidence boundaries | B10 |

Public installed files live under `/usr/lib/rdc-appliance/`; immutable verified media under `/var/lib/rdc-appliance/media/`; root-private state under `/var/lib/rdc-appliance/private/` (0700 directories, 0600 files). Public status and attachment output are derived allowlists, never a private-state dictionary with selected keys removed. Do not put private state in `/etc/pve`, USB media or Git.

## Shared contracts

B1 defines `Json = dict[str, Any]`, with schema-specific aliases `SitePlan`, `ReleaseLock`, `Inventory`, `Evidence` and `VmSpec`. These are validated JSON records, not arbitrary dictionaries at mutation boundaries. `ApplianceError(code: str, message: str)` exposes a stable non-secret error code. `require(condition: bool, code: str) -> None` raises it on failure. `identity(record: Json) -> str` hashes canonical UTF-8 JSON (sorted keys, compact separators, no floats).

| Record | Required contents |
|---|---|
| `SitePlan` | `schema=1`, `site_id`, `revision`, `release_id`, `target`, `ports`, `networks`, `upstream`, `overlay_cidrs`, `vms`, `roles` |
| `target` | `by_id`, `serial`, `wwn`, `size_bytes`, `model`, `transport`; at least one independently usable serial/WWN plus stable path; reject absent/ambiguous identity |
| `ports` | `management` and `wan`, each `permanent_mac`, `pci_path`, `driver`; link-test result is separately timestamped evidence |
| `networks` | `management`, `infrastructure`, `workload`, optional `relay`; each `bridge`, IPv4 `cidr`, `gateway`, `allocation`; management additionally `host_ip`, `admin_ip`; no other host IP |
| `upstream` | `mode=dhcp|static`, known `cidrs`; static requires `address`, `gateway`, `dns`; newly observed DHCP routes trigger overlap revalidation before guest forwarding |
| `VmSpec` | `role`, `vmid`, `name`, `memory_mib`, `vcpus`, `disk_gib`, `storage`, `nics` with fixed MAC and zone; no secrets |
| `roles` | `connector`, `headscale`, `derp`: each `selected` and non-secret role settings; secret values travel separately |
| `ReleaseLock` | `schema=1`, `release_id`, `adapter_id`, exact `components`, tested `profile`, per-role `budgets`; artifact URL, version, byte limits, SHA256, signer/provenance reference for each component |
| `Inventory` | `boot_id`, `supported`, CPU/virtualization/memory/firmware, `disks` with an `identity` matching the target shape, `boot_media_ids` covering all boot-media backing disks, mount/storage ancestry, selected stable `ports`, NIC live addresses and conflicting/shared storage metadata |
| `Evidence` | `schema=1`, `capability`, `state`, `checked_at`, `plan_id`, `build_id`, `dependencies`, `observations`, `next_action`; state is `configured|verified|blocked|unknown|not-selected` |

Use production pins resolved from official release artifacts during B1, never synthetic hashes. Tiny fixture artifacts are explicitly marked test-only and cannot pass production build validation. Keep input artifact hashes separate from the output bundle manifest, which hashes the actual appliance source and generated files; avoid a self-referential image hash.

Bridge identifiers: `vmbr0` management, `vmbr1` WAN, `vmbr2` infrastructure, `vmbr3` workload, optional `vmbr4` relay. Names are stable product identifiers, not authorization to adopt existing bridges. Private subnet values are site inputs with overlap checks, not mandatory global defaults. Management reaches the host directly; its sole default route is the router management address.

## Task B1: Release lock, site contracts and verified media

**Files:** Create `appliance/__init__.py`, `appliance/contracts.py`, `appliance/plan.py`, `appliance/media.py`, `appliance/releases/v1.lock.json`, `tests/appliance/conftest.py`, `tests/appliance/test_contracts.py`, `tests/appliance/test_media.py`, `tests/fixtures/appliance/site.json`, `tests/fixtures/appliance/release.json`, `docs/appliance/release-inputs.md`.

**Interfaces:** Produce `validate_site(plan: SitePlan, release: ReleaseLock) -> SitePlan`, `validate_release(lock: ReleaseLock, *, production: bool) -> ReleaseLock`, `verify_file(path: Path, component: Json) -> Json`, `prepare_component(component: Json, cache: Path) -> Path`. Fixtures `site` and `release` return fresh parsed copies; media fixtures create bounded temporary files and matching test-only records. `verify_file` returns `{sha256, size_bytes}` only after verification.

- [ ] **1. Write rejection tests**, importing the declared functions from their owning modules. Include malformed/missing keys, unknown schema, duplicate VMID/MAC, host IP on WAN, overlapping upstream/overlay ranges, insufficient selected-role budget, truncated/compression-bomb media and a signature from an untrusted signer.

```python
def test_management_cannot_overlap_overlay(site, release):
    site["overlay_cidrs"] = [site["networks"]["management"]["cidr"]]
    with pytest.raises(ApplianceError) as err:
        validate_site(site, release)
    assert err.value.code == "subnet-overlap"

def test_production_rejects_fixture_release(release):
    with pytest.raises(ApplianceError) as err:
        validate_release(release, production=True)
    assert err.value.code == "test-artifact"
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_contracts.py tests/appliance/test_media.py`; expect collection/import failure before implementation, then assertion failures as functions are introduced.
- [ ] **3. Implement strict validation and bounded verified publication.** Use `ipaddress.IPv4Network`, compare every pair of declared routed networks, and refuse unknown keys at executable boundaries. Use this overlap core after parsing:

```python
def require_disjoint(networks: list[ipaddress.IPv4Network]) -> None:
    for index, left in enumerate(networks):
        for right in networks[index + 1:]:
            require(not left.overlaps(right), "subnet-overlap")
```

Resolve one compatible Proxmox ISO/installer-assistant pair, OPNsense DVD, Linux guest base image, neutral probe image, role binaries and Restic from official release metadata. The bundled probe image contains the tools needed for DNS, time, HTTPS and listener checks and is operable through its VM console; it requires no later role-provisioning code or download. Record independently trusted vendor signing keys or reviewed official checksum provenance; verify compressed and expanded OPNsense artifacts in the vendor's stated order. Publish by verified temporary file, fsync and atomic rename. Reject redirects to undeclared origins, size overruns, symlinks and archive path traversal. Inventory source/licence notices for redistribution. Document the exact downloaded artifacts and the source revision inspected for each installer adapter. The output lock records real values; release budgets remain explicitly unqualified until measured in B10/R6, and the release publisher refuses that condition. Distinguish an explicit disposable qualification build using provisional budgets from a publishable release; this allows M0 to measure the platform without pretending its minimum requirements are already proven.
- [ ] **4. Re-run the tests**, verify actual locked media in a disposable download job, and check that no test artifact or secret can enter a production bundle. Expected: unit tests pass; every input has a verified receipt, or the job fails with the component named.
- [ ] **5. Commit** the listed source, tests and provenance document with `feat: define appliance contracts and verified release inputs`.

## Task B2: Prove the custom live installer handoff

**Files:** Create `appliance/installer/__init__.py`, `appliance/installer/media.py`, `appliance/installer/live.py`, `appliance/installer/adapters/__init__.py`, `appliance/installer/adapters/pve.py`, `tests/appliance/test_installer_gate.py`, `tests/appliance/lab.py`, `scripts/ci_appliance_base.py`, `docs/appliance/installer-qualification.md`.

**Interfaces:** Consume B1 validation/media. Produce `build_iso(lock: ReleaseLock, payload: Path, output: Path) -> Path`; `live_gate(plan: SitePlan, current: Inventory, confirmed_identity: str | None) -> None`; `answer_bytes(plan: SitePlan, password_hash: str) -> bytes`; adapter `install(answer: bytes) -> Json`, `stage_target(receipt: Json, payload: Path, plan: SitePlan) -> None`. The install receipt binds target identity, root filesystem identity and completed upstream task. The adapter owns release-specific environment collection, stdin handoff, mount and cleanup, without performing its own partitioning.

- [ ] **1. Write gate tests and an executable lab recipe.** Fixture `inventory` is a fresh record derived from `site`, with a separate boot-media disk. Negative fixtures vary only the named property.

```python
@pytest.mark.parametrize("confirmation", [None, "", "old-plan-hash"])
def test_no_confirmation_never_reaches_installer(site, inventory, confirmation):
    with pytest.raises(ApplianceError) as err:
        live_gate(site, inventory, confirmation)
    assert err.value.code == "erase-not-confirmed"

def test_boot_media_is_never_an_install_target(site, inventory):
    inventory["boot_media_ids"] = [site["target"]["by_id"]]
    with pytest.raises(ApplianceError) as err:
        live_gate(site, inventory, identity(site))
    assert err.value.code == "target-is-boot-media"
```

The lab owns only disk image files in its explicit work directory, refuses block-device paths and existing non-lab images, and launches its own isolated virtual switches. Create two identifiable target/canary disks, a removable installer image, a management peer and a WAN DHCP/RA peer. Record initial/final full disk-image digests for every refusal case and for non-target disks during a successful install. Include a refusal case with an existing non-target `pve` LVM volume group and a successful-install case with a non-conflicting populated canary: neither canary may change. Test duplicate identity, changed capacity, hot removal, spanning storage, cancelled input and invalid media. Give each test a bounded timeout and preserve redacted serial logs and packet captures.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_installer_gate.py`; expect missing gate failure. On the disposable KVM runner, invoke `python3 scripts/ci_appliance_base.py --suite media-gate --lab-config .work/appliance-lab.json`; expect the unmodified upstream startup to fail the no-WAN-address assertion. The configuration declares owned image paths, firmware path, available KVM and release lock; absent prerequisites report NOT RUN with a nonzero exit, never PASS.
- [ ] **3. Implement the smallest exact-release integration.** The live image must boot into Install / Repair / Exit, with no timed destructive action and no alternate automatic entry that bypasses the gate. Disable IPv6 from initial kernel boot; suppress DHCP/SLAAC/time-sync startup before any selected port is brought up. Keep links down except controlled link identification. Refresh upstream inventory immediately before the official installer and check one exact disk/management-NIC match; the upstream first-match filter is insufficient. Core ordering:

```python
def live_gate(plan, current, confirmed_identity):
    require(confirmed_identity == identity(plan), "erase-not-confirmed")
    require(plan["target"]["by_id"] not in current["boot_media_ids"],
            "target-is-boot-media")
    matches = [d for d in current["disks"] if d["identity"] == plan["target"]]
    require(len(matches) == 1, "target-identity-changed-or-ambiguous")
    require(current["ports"] == plan["ports"], "port-identity-changed")
    require(current["supported"], "unsupported-hardware")
```

Inventory matching uses stable identities, never current device enumeration names. The confirmed plan includes the release and disk identity. Inspect all attached storage read-only; reject a non-target `pve` volume group, shared/spanning LVM/MD/ZFS membership or another layout that the selected installer could mutate. Report which non-target disk must be disconnected before trying again. Do not rely on the official installer's collision handling to preserve other disks; inspect its exact release behavior. [Proxmox storage installation source](https://github.com/proxmox/pve-installer/blob/master/Proxmox/Install.pm). Keep the generated answer and password hash in private RAM; do not embed an answer in the reusable image. Preserve upstream boot records while rebuilding; inspect actual ISO/initrd contents and pin the replacement entry's expected source hash. Unknown source layout fails the build. Invoke official installation with reboot held until verified staging completes; qualify this control against the selected adapter. Use the upstream mount helper only after checking that the mounted root belongs to the selected target. Stage local payload, ISO and plan; fsync a completion marker last. A failed staging step powers down or enters repair, never announces a usable install.

M0 supplies a minimal fixed lab payload and early safe-management configuration to prove staging without depending on the later product menu. Its Repair entry permits read-only identification and safe exit only. B5 replaces that lab payload with the production package; B9 adds actual recovery. Neither prototype is presented as the finished repair feature.
- [ ] **4. Run both tests again.** Add successful disconnected install, USB removal, reboot with USB retained, first-boot failure, and Repair entry cases. Capture WAN packets and all live interface addresses from earliest boot through installed-host boot; require zero host DHCP acquisition, IPv4 addresses or IPv6 link-local addresses on WAN. Confirm cancellation/Repair never partitions. The qualification report records exact firmware, versions, hashes and commands. M0 cannot pass on mocked installer calls alone.
- [ ] **5. Commit** the integration and evidence schema with `feat: prove guarded offline Proxmox installer handoff`. Store large media/evidence outside Git; commit sanitized result summaries and digests.

## Task B3: Durable state, ownership and local command boundary

**Files:** Create `appliance/state.py`, `appliance/runner.py`, `tests/appliance/test_state.py`, `tests/appliance/test_runner.py`; modify `tests/appliance/conftest.py` to add a scripted command runner.

**Interfaces:** Produce `read(path: Path) -> Json`, `write(path: Path, record: Json) -> None`, `lock(directory: Path)` context manager; `Runner.run(argv: list[str], *, stdin: bytes = b"", timeout_s: int = 30) -> CompletedProcess[bytes]`; `begin(directory: Path, operation: Json) -> str`; `finish(directory: Path, operation_id: str, observation: Json) -> None`. `begin` returns an operation ID and durably saves intent; repeated unresolved intent must be inspected, not replayed. The test runner queues expected argv/results and exposes `calls: list[list[str]]`; an unexpected command fails the test.

- [ ] **1. Write tests** for concurrent invocations, symlink/hardlink/private-mode violations, truncated records, intent persisted before a command, timeout after a completed mutation, and an unrelated VM with an identical friendly name.

```python
def test_unresolved_mutation_is_not_reissued(tmp_path):
    op = {"kind": "create-vm", "plan_id": "test-plan", "vmid": 101}
    first = begin(tmp_path, op)
    with pytest.raises(ApplianceError) as err:
        begin(tmp_path, op)
    assert err.value.code == "operation-needs-inspection"
    assert read(tmp_path / (first + ".json"))["phase"] == "pending"
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_state.py tests/appliance/test_runner.py`; expect missing-module failure.
- [ ] **3. Implement the extracted durable-file algorithms without old topology imports.** Add private ownership, single-link regular-file and size checks; protect parent paths against symlinks. Run commands with argument lists, a fixed environment, time/output bounds and no shell. Redact secrets structurally; never log stdin or arbitrary tool stderr containing credentials. The mutation core is:

```python
def begin(directory, operation):
    operation_id = identity(operation)
    path = directory / (operation_id + ".json")
    with lock(directory):
        require(not path.exists(), "operation-needs-inspection")
        write(path, {"phase": "pending", "operation": operation})
    return operation_id
```

An operation's intent contains a unique run nonce when a new action is actually required. Reconciliation compares exact observed ownership/configuration, then calls `finish`; a lost response is never treated as permission to create again. VM/bridge ownership binds site, role, fixed MACs and original allocation receipt, with mutable plan revision tracked separately so a legitimate plan update does not orphan resources.
- [ ] **4. Re-run tests** with failure injection before/after fsync, command dispatch and result persistence. Expected: no duplicate mutation, no secret output and clear pending-state repair guidance.
- [ ] **5. Commit** with `feat: add durable appliance state and command boundary`.

## Task B4: Host bridges, firewall and reboot-safe management rollback

**Files:** Create `appliance/host_network.py`, `appliance/rollback.py`, `appliance/systemd/rdc-network-rollback.service`, `appliance/systemd/rdc-network-rollback.timer`, `tests/appliance/test_host_network.py`, `tests/appliance/test_rollback.py`; modify `tests/appliance/lab.py`, `scripts/ci_appliance_base.py`.

**Interfaces:** Produce `render_host(plan: SitePlan) -> dict[str, bytes]`, `audit_host(plan: SitePlan, observed: Json) -> list[str]`, `apply_host(plan: SitePlan, root: Path, runner: Runner, *, now: int) -> str`, `confirm_management(transaction_id: str, challenge: str, *, now: int) -> None`, `recover_pending(root: Path, runner: Runner, *, now: int) -> None`. Rendered paths are from an explicit allowlist; never arbitrary plan-supplied paths. Host observations include live addresses/routes, forwarding sysctls, bridge members, firewall state and ownership.

- [ ] **1. Write tests** for live IPv6 link-local, no routing/NAT in the host, changed NIC identity, foreign bridge membership, firewall default management allowances broader than the chosen subnet, expired confirmation, and reboot during configuration replacement.

```python
def test_live_wan_ipv6_is_rejected(site):
    observed = {"addresses": {"vmbr1": ["fe80::1/64"]}}
    assert "wan-host-address" in audit_host(site, observed)

def test_guest_bridge_never_receives_host_address(site):
    files = render_host(site)
    interfaces = files["/etc/network/interfaces"].decode()
    assert "iface vmbr1 inet manual" in interfaces
    assert "iface vmbr2 inet manual" in interfaces
    assert "iface vmbr3 inet manual" in interfaces
```

Audit missing observation fields as unknown/failed; the first test's partial observation may produce additional failures, never a clean bill of health.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_host_network.py tests/appliance/test_rollback.py`; expect missing implementation failures.
- [ ] **3. Implement deterministic host configuration and rollback.** Resolve NIC names from permanent MAC plus PCI identity on each boot. Apply IPv6 disablement to physical ports, bridges and defaults for newly created links; retain the kernel-level disablement from B2. Bind host management listeners/firewall to the selected local subnet and ingress interface, disable forwarding and avoid host NAT. Test packets arriving on WAN addressed to the management IP, not only packets addressed to a WAN IP. Enable the pinned release's tested host firewall; do not assume rendered rules are active. The bridge template's core is:

```text
auto vmbr1
iface vmbr1 inet manual
    bridge-ports {resolved_wan_interface}
    bridge-stp off
    bridge-fd 0
```

Management alone gets the declared static address and router gateway; infrastructure/workload bridges use `bridge-ports none`. Separate the early stage, which restores local files and leaves all non-management links down without touching pmxcfs, from the post-PVE stage, which applies and verifies the host firewall before activating other bridges. Keep management daemons gated until the selected local access policy is active. Record an owned-file inventory. Before a change, save exact known-good bytes, durable pending metadata and a new challenge. Arm a 120-second rollback independently of the invoking terminal before reloading networking. A boot-time recovery unit restores any unconfirmed transaction before networking; the timer handles a live lost session. On the first install the fallback is static management plus every other link down, not an empty configuration. Confirm through a fresh management session carrying the challenge; local console recovery is an explicit separate action. After reboot, never extend an old confirmation deadline based on the current wall clock. Unknown NIC replacement leaves upstream down and requests local remapping.
- [ ] **4. Run unit tests and the lab suite** `python3 scripts/ci_appliance_base.py --suite host-network --lab-config .work/appliance-lab.json`. Extend the B2 harness with remote confirmation, deliberately broken management, process termination and cold reboot. Expected: last good management returns, WAN stays host-address-free, and router absence does not prevent direct numeric-IP access.
- [ ] **5. Commit** with `feat: protect two-port host networking with rollback`.

## Task B5: Production preflight, USB payload and first-boot menu

**Files:** Modify `appliance/installer/media.py`, `appliance/installer/live.py`, `appliance/installer/adapters/pve.py`, `tests/appliance/lab.py`, `scripts/ci_appliance_base.py`; create `appliance/installer/first_boot.py`, `appliance/systemd/rdc-first-boot.service`, `appliance/cli.py`, `appliance/__main__.py`, `rdc-appliance`, `tests/appliance/test_preflight.py`, `tests/appliance/test_first_boot.py`.

**Interfaces:** Consume B1–B4. Produce `inventory(runner: Runner) -> Inventory`, `preflight(plan: SitePlan, release: ReleaseLock, observed: Inventory) -> list[str]`, `install_site(plan: SitePlan, bundle: Path, confirmation: str, runner: Runner) -> Json`, `first_boot(root: Path, runner: Runner) -> None`, `main(argv: list[str] | None = None) -> int`. CLI commands initially: `menu`, `inspect`, `preview`, `install`, `resume`, `status`, `repair`. `install` is available only in the live-media environment and cannot be invoked against an already running host.

- [ ] **1. Write tests** for USB ancestry exclusion, ambiguous disks/NICs, unsupported firmware/CPU/resource budget, wrong cable role with stable hardware mapping, modified plan after preview, unreadable payload, absent staging marker and failure of the pre-network unit.

```python
def test_bad_staging_never_enables_upstream(tmp_path, runner):
    with pytest.raises(ApplianceError) as err:
        first_boot(tmp_path, runner)
    assert err.value.code == "staging-incomplete"
    assert not any("ifreload" in call[0] for call in runner.calls)
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_preflight.py tests/appliance/test_first_boot.py`; expect failure before implementation.
- [ ] **3. Connect the proven adapter to the product journey.** Show model, serial/WWN, size, existing partitions and exact erase effect; require a typed target identifier and current-plan confirmation. Run link/cable tests on selected identities without assigning WAN addresses. Select site networks and local credentials; generate per-install keys and password hashes using system-supported primitives, with no reusable defaults. Re-read inventory, verify the full offline payload and repeat the destructive gate immediately before installation. A confirmation is bound to this live session and is never stored on the generic USB for reuse. Core installed handoff:

```python
def first_boot(root, runner):
    marker = root / "var/lib/rdc-appliance/private/staged.json"
    require(marker.is_file(), "staging-incomplete")
    receipt = read(marker)
    require(receipt["complete"] is True, "staging-incomplete")
    # verify_file is called for every receipt entry before configuration apply.
    for item in receipt["files"]:
        verify_file(root / item["relative_path"], item["component"])
    recover_pending(root, runner, now=int(time.time()))
```

Validate receipt paths as relative owned paths before joining them to `root`. The unit applies the B4 safe configuration and local hostname resolution before normal networking; explicit systemd failure dependencies keep unsafe networking down if staging verification fails. It must not access pmxcfs or create VMs at this stage. A later menu starts after PVE services. Stage the ISO on internal storage before reboot, set restrictive permissions, and print a public connection card with numeric host IP, laptop settings, local-login instructions and the actual management certificate fingerprint. Keep passwords off that card. The menu remains available without DNS, gateway or external authentication.
- [ ] **4. Re-run tests and** `python3 scripts/ci_appliance_base.py --suite offline-install --lab-config .work/appliance-lab.json`. Expected: no download attempt, no USB dependency after installation, fresh credentials on two installs, repeat boot safe, and a failed first boot enters local repair without enabling upstream.
- [ ] **5. Commit** with `feat: deliver offline appliance installation and local setup menu`.

## Task B6: Owned Proxmox VM allocation and disk-only router installation

**Files:** Create `appliance/proxmox.py`, `tests/appliance/test_proxmox.py`; modify `appliance/cli.py` and `tests/appliance/lab.py`.

**Interfaces:** Produce `vm_spec(plan: SitePlan, role: str) -> VmSpec`, `ensure_vm(spec: VmSpec, runner: Runner, state: Path) -> Json`, `observe_vm(vmid: int, runner: Runner) -> Json`, `set_link(vmid: int, mac: str, connected: bool, runner: Runner) -> None`, `disk_boot(vmid: int, runner: Runner, state: Path) -> Json`. Mutations use B3 journals and exact owned configuration. Observed state includes disk volume IDs, boot order, ISO presence, MAC/bridge/link mapping, running state and a new boot identifier.

- [ ] **1. Write tests** for foreign VMID, modified MAC, unexpected NIC, wrong storage, response lost after creation, running ISO boot and existing unowned disk.

```python
def test_router_wan_starts_disconnected(site):
    spec = vm_spec(site, "router")
    wan = next(n for n in spec["nics"] if n["zone"] == "wan")
    assert wan["connected"] is False
    assert all(n["connected"] is False for n in spec["nics"])
    assert all(n["mac"] for n in spec["nics"])
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_proxmox.py`; expect failure before implementation.
- [ ] **3. Implement the local PVE adapter.** Use validated argv with `qm`/`pvesh`, not an API token or shell interpolation. Verify task completion and actual config before recording success. Allocate fixed MACs, supported virtual disk/NIC models, reserved resource budgets and an ownership marker. No guest gets management/WAN attachment except the router. Keep every router vNIC disconnected during console installation: its default LAN DHCP/RA must never reach the physical management segment. B7 enables management only after a separate console bootstrap check. The attachment permission core is:

```python
def allowed_zones(role: str) -> set[str]:
    return {"router": {"management", "wan", "infrastructure", "workload", "relay"},
            "connector": {"infrastructure"}, "headscale": {"infrastructure"},
            "derp": {"relay"}, "probe": {"workload"}}[role]
```

Guide the operator through the bundled OPNsense DVD installer. On completion stop the VM, detach the ISO, restrict boot order to the owned disk, reboot and observe a new running boot. Require guest-level installed-root/version evidence in B7; VM running alone reports only `configured`. Never reinstall or replace an existing disk on rerun. Keep the installer available in storage for explicit repair without restoring it to normal boot order.
- [ ] **4. Re-run tests; extend the offline lab run** to complete the guided router installer, remove its ISO and capture the subsequent disk boot. Expected: deterministic interfaces, no duplicate disks/VMs after interrupted commands, and no WAN connectivity yet.
- [ ] **5. Commit** with `feat: allocate owned router VM and verify disk boot`.

## Task B7: OPNsense configuration and guarded WAN activation

**Files:** Create `appliance/router_config.py`, `appliance/router.py`, `appliance/router/helper.php`, `tests/appliance/test_router_config.py`, `tests/appliance/test_router_gate.py`, `tests/fixtures/appliance/opnsense-config.xml`, `docs/appliance/router-console.md`; modify `appliance/cli.py`, `tests/appliance/lab.py`, `scripts/ci_appliance_base.py`.

**Interfaces:** Produce `render_router(plan: SitePlan, credentials: Json) -> bytes`, `audit_router(plan: SitePlan, config_xml: bytes, runtime: Json) -> list[str]`, `enable_router_management(plan: SitePlan, console_observation: Json, runner: Runner, state: Path) -> None`, `collect_router(plan: SitePlan, runner: Runner) -> Json`, `apply_router_policy(plan: SitePlan, stage: str, runner: Runner, state: Path) -> Evidence`, `router_ready(plan: SitePlan, runtime: Json) -> Evidence`, `enable_wan(plan: SitePlan, runtime: Json, runner: Runner, state: Path) -> None`. Policy stage is exactly `bootstrap` or `transit`. Private credentials are a separate input, never part of public `SitePlan`. Runtime evidence binds VM boot ID, active config digest, installed root device, OS version and active listeners/rules to the current plan.

- [ ] **1. Write tests** for interface enumeration changes, inherited broad LAN allow, default DHCP/RA preventing management-link activation, DHCP on management, WAN admin listener, missing unique credentials, IPv6 enabled, ISO/live-root evidence and mismatched active config digest. Test the management channel's host-key mismatch, arbitrary-command/forwarding refusal, lost apply response and fresh status/export after reboot. In the lab capture the management wire throughout first installation and require no router DHCP offer or RA at any point.

```python
def test_live_router_is_not_ready(site):
    runtime = {"root_kind": "live-iso", "vmid": site["vms"]["router"]["vmid"]}
    result = router_ready(site, runtime)
    assert result["state"] != "verified"
    assert "installed-disk" in result["next_action"]
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_router_config.py tests/appliance/test_router_gate.py`; expect failures before implementation.
- [ ] **3. Implement a release-specific configuration renderer and evidence collector.** First use the disconnected VM console to set unique credentials, assign interfaces by recorded MAC, set the static management address, disable DHCP/RA and IPv6 on management, and restrict initial administration. Record these console checks against the current VM boot before `enable_router_management` connects that link. Capture a sanitized export from the pinned OPNsense release as the schema fixture. Qualify its supported configuration import through the console/GUI, with management assigned LAN and guest zones assigned OPT interfaces. A generated per-site configuration carries unique credentials; it is never part of the generic ISO. Disable IPv6 and hardware offloading as qualified, preserve management anti-lockout, remove broad default LAN transit, and bind administration to management. Run DNS/time on each guest gateway; infrastructure is static, workload DHCP is virtual only. Use explicit allowed DNS, NTP and update/HTTPS egress, default-deny cross-zone access and no host forwarding. Adjust WAN private-network settings only when the declared upstream actually uses private addressing.

Use a guided console step to enroll a unique management-only operational SSH key and verify its host fingerprint locally; never accept a host key on first network contact without that comparison. Keep this channel available for fresh status, policy changes, DHCP observations and exports after reboot. Restrict it to the host's management source address, key-only authentication and a fixed forced-command helper, with shell, PTY, forwarding and agent forwarding disabled. The helper supports only bounded `inspect`, `apply-policy` and `export-config` requests; policy changes compare the expected active digest and carry an operation ID. It cannot execute caller-supplied commands or write caller-supplied paths. Install it through the initial console/bootstrap session; remove any temporary unrestricted bootstrap key after testing the restricted key. Restrict access to its private output and redact logs.

Implement the helper using the PHP runtime and configuration interfaces present in the locked OPNsense release, and qualify persistence across reboot/config reload. Its dispatch gate is:

```php
$request = json_decode(stream_get_contents(STDIN, 524289), true, 32, JSON_THROW_ON_ERROR);
if (!is_array($request) || !in_array($request['action'] ?? '',
        ['inspect', 'apply-policy', 'export-config'], true)) {
    exit(64);
}
```

Validate input size, schema, operation identity and every action's parameters before dispatch. Keep the privileged helper minimal and owned by root. Do not assume a QEMU guest agent exists on the OPNsense ISO. Qualify SSH restrictions, the exact collection/apply commands and the config fields in `router-console.md` against the release before enabling WAN; inability to enforce them blocks this adapter. WAN activation's core is:

```python
def enable_wan(plan, runtime, runner, state):
    result = router_ready(plan, runtime)
    require(result["state"] == "verified", "router-not-ready")
    spec = vm_spec(plan, "router")
    wan = next(n for n in spec["nics"] if n["zone"] == "wan")
    operation_id = begin(state, {"kind": "enable-wan", "plan_id": identity(plan),
                                 "boot_id": runtime["boot_id"]})
    set_link(spec["vmid"], wan["mac"], True, runner)
    finish(state, operation_id, observe_vm(spec["vmid"], runner))
```

Before calling this core, compare the fresh active XML and runtime checks against the plan and record the verified gate result. Use two stages: enable WAN with a bootstrap policy that still denies all guest forwarding, inspect the acquired upstream address/routes through the restricted channel, then activate the declared transit policy only after overlap checks pass. Qualify a router-local boot/lease-change hook that returns to bootstrap policy and checks the stored site ranges before releasing forwarding; it cannot depend on a successful host SSH session. A renewal/change repeats this check and leaves guest forwarding blocked on conflict. Collect final runtime evidence through the operational channel. Firewall truth is ultimately established by B8 packet tests, not by parsing XML alone.
- [ ] **4. Re-run unit tests and the lab's** `--suite router-policy`. Exercise DHCP and static upstream separately, including an RFC1918 upstream, missing upstream, overlapping DHCP lease, DNS/time loss and an active WAN listener probe. Expected: guest routing works only after policy readiness; administration stays private; numeric-IP management survives router stop.
- [ ] **5. Commit** with `feat: bootstrap OPNsense policy before enabling WAN`.

## Task B8: Status, startup readiness and one local operations menu

**Files:** Create `appliance/checks.py`, `appliance/startup.py`, `appliance/systemd/rdc-router-start.service`, `appliance/systemd/rdc-role-start.service`, `appliance/systemd/rdc-menu.service`, `tests/appliance/test_checks.py`, `tests/appliance/test_startup.py`, `tests/appliance/test_cli.py`; modify `appliance/cli.py`, `tests/appliance/lab.py`, `scripts/ci_appliance_base.py`.

**Interfaces:** Produce `evaluate(capability: str, observations: Json, plan: SitePlan, build_id: str, *, now: int) -> Evidence`, `current(evidence: Evidence, dependency_ids: Json, *, now: int, max_age_s: int = 300) -> bool`, `start_local(plan: SitePlan, runner: Runner, *, timeout_s: int = 120) -> list[Evidence]`, `attachment(plan: SitePlan) -> Json`. Add commands `router install`, `router verify`, `router enable-wan`, `diagnose`, `network confirm`, `export`, `repair`; reserve role subcommands for R1–R5. Both menu and CLI call the same functions.

- [ ] **1. Write tests** for stale config-bound evidence, WAN absent without blocking menu, unsynchronized clock, router restart changing boot ID, failed listener positive control and secret fields injected into diagnostic input.

```python
def test_changed_router_invalidates_saved_pass(site):
    evidence = evaluate("router", {"passed": True, "dependencies": {"boot": "a"}},
                        site, "build-one", now=100)
    assert not current(evidence, {"boot": "b"}, now=101)

def test_public_attachment_has_no_role_secrets(site):
    site["roles"]["connector"]["auth_key"] = "test-secret"
    assert "test-secret" not in json.dumps(attachment(site))
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_checks.py tests/appliance/test_startup.py tests/appliance/test_cli.py`; expect failure before implementation.
- [ ] **3. Implement independent capability records and bounded readiness.** Status distinguishes local management, router, upstream address/route, DNS, time, enrollment, controller and relay. Configuration is not verification; absent or failed positive-control evidence cannot yield a pass. Freshness core:

```python
def current(evidence, dependency_ids, *, now, max_age_s=300):
    age = now - evidence["checked_at"]
    return (evidence["dependencies"] == dependency_ids
            and 0 <= age <= max_age_s
            and evidence["state"] == "verified")
```

Bind dependencies to plan, build and relevant runtime identities, and show unknown when time cannot be trusted. Keep local management/menu independent of VM readiness. Use Proxmox startup order plus a bounded local router readiness check; prevent dependent guest autostart from bypassing the role-start service. No-WAN boots still start router/local facilities and report remote capabilities unavailable. Reverse the dependency order at shutdown; a stuck dependent guest cannot hang shutdown indefinitely. No network enrollment is retried by deleting state.

Export schema-versioned attachment metadata: site/network IDs, bridge/zone, allocation, gateway, DNS/time, enforced access rules and policy identity. Do not offer application plugin execution. A bridge is explicitly one trust zone. The menu explains the next action and supports resume/diagnosis without running setup mutations as a side effect of `status`.
- [ ] **4. Re-run tests and** `--suite base-operations` in the lab. Start a known TCP listener in each test zone and prove it responds locally before testing denial remotely. Separately test routing, DNS, NTP service versus external time synchronization, HTTPS and host/router administration. Expected: positive and negative controls pass; missing WAN never blocks the local menu.
- [ ] **5. Commit** with `feat: expose resumable appliance operations and fresh status`.

## Task B9: Encrypted export and non-destructive USB/router repair

**Files:** Create `appliance/export.py`, `appliance/repair.py`, `tests/appliance/test_export.py`, `tests/appliance/test_repair.py`; modify `appliance/installer/live.py`, `appliance/cli.py`.

**Interfaces:** Produce `collect_base(plan: SitePlan, state: Path, router_xml: Path) -> dict[str, Path]`, `seal(files: dict[str, Path], destination: Path, password_file: Path, runner: Runner) -> Json`, `inspect_export(source: Path, password_file: Path, output: Path, runner: Runner) -> Json`, `validate_repair_target(target: Json) -> None`, `repair_host(target: Json, export: Path, runner: Runner) -> Json`, `restore_router_isolated(plan: SitePlan, config: Path, runner: Runner) -> Evidence`. `seal` returns snapshot ID, component manifest and ciphertext digest; no password. Role collection extends the same file-map contract in R5.

- [ ] **1. Write tests** for wrong password, missing plan/VM/config manifest, truncated archive, path traversal, secret diagnostic leakage, repair target ambiguity and attempted live duplicate identity.

```python
def test_repair_refuses_ambiguous_target(tmp_path, runner):
    with pytest.raises(ApplianceError) as err:
        repair_host({"matches": 2}, tmp_path / "export", runner)
    assert err.value.code == "repair-target-ambiguous"
    assert runner.calls == []
```

- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_export.py tests/appliance/test_repair.py`; expect failure before implementation.
- [ ] **3. Implement a small pinned-Restic export adapter.** Reuse the earlier recovery package's checked seal/restore approach, not its Ubuntu-only host guard or application recovery scope. Include private plan, NIC/VM definitions, lock/build manifest, known-good host files and fresh router XML. Keep the decryption password separate from the export; require a independently supplied credential for the restore proof. Verify contents after restoring into a new private directory before publication. Archive activation and archive inspection are separate operations. Start the USB Repair branch with read-only discovery and exact existing-host identity selection; no repair command invokes the installer, partitioner or disk format path. Refuse missing/foreign ownership. Restore only allowlisted appliance files and keep other disks read-only.

```python
def validate_repair_target(target):
    require(target.get("matches") == 1, "repair-target-ambiguous")
    require(target.get("owned") is True, "repair-target-unowned")
    require(target.get("confirmed") is True, "repair-not-confirmed")
```

Call this pure gate before any repair command, then mount the identity-checked root, replace only the verified allowlisted files, fsync/unmount and report the actual result with a request to verify local management. Router recovery creates an explicitly isolated test VM with every external link disconnected, imports the exported configuration, proves installed boot/configuration, and shuts it down. Never bridge a copied management or identity-bearing VM into the live network. Normal repair reuses the original owned router, preserves keys and lets the operator recover via Proxmox console.
- [ ] **4. Re-run unit tests and** `--suite repair` in the lab. Corrupt host management, boot USB Repair, recover management, decrypt an export using a separately held password and perform isolated router reimport. Expected: unrelated disk hashes unchanged, no duplicate live identities and a specific report of what was repaired.
- [ ] **5. Commit** with `feat: export appliance configuration and guard local repair`.

## Task B10: Base acceptance, physical pilot and operator instructions

**Files:** Modify `scripts/ci_appliance_base.py`, `tests/appliance/lab.py`, `README.md`, `scripts/check_local.py` only if test discovery needs adjustment; create `.github/workflows/appliance-base.yml`, `tests/appliance/test_release_gate.py`, `docs/appliance/install.md`, `docs/appliance/repair.md`, `docs/appliance/evidence.md`.

**Interfaces:** Produce `base_release_allowed(results: list[Evidence], *, physical: bool) -> bool` in `appliance/checks.py`. The acceptance runner emits schema-1 JSON plus a redacted human report containing source tree hash, release/build hashes, hardware/firmware, topology, role selection, case IDs and PASS/FAIL/NOT RUN. `physical=True` requires actual physical evidence; unit tests use labeled synthetic records.

- [ ] **1. Write a failing release-gate test** requiring every base exercise, exact build identity and physical evidence. A skipped test cannot become pass.

```python
def test_nested_success_cannot_claim_usb_hardware_acceptance():
    assert not base_release_allowed([], physical=True)

def test_unrun_case_blocks_base_release(base_results):
    base_results[0]["state"] = "unknown"
    assert not base_release_allowed(base_results, physical=True)
```

Define `base_results` in `conftest.py` with one synthetic, current result for each required case below and `environment=physical-fixture`; the publisher rejects fixture markers in actual submissions.
- [ ] **2. Run** `.venv/bin/python -m pytest -q tests/appliance/test_release_gate.py`; expect failure before implementation.
- [ ] **3. Complete the acceptance runner and guides.** Use exact case IDs: `offline-install`, `erase-refusals`, `port-mapping`, `wan-exposure`, `routed-policy`, `router-down-management`, `no-wan-boot`, `wan-return`, `interrupted-resume`, `export-repair`, `physical-operator`. Each requires all subordinate assertions, not merely command exit zero. Match result build IDs and reject stale configuration dependencies. The implementation's membership core is:

```python
BASE_CASES = {"offline-install", "erase-refusals", "port-mapping", "wan-exposure",
              "routed-policy", "router-down-management", "no-wan-boot", "wan-return",
              "interrupted-resume", "export-repair", "physical-operator"}
```

Run safe unit tests in ordinary CI. Run destructive nested scenarios only on an explicitly configured disposable runner, with no production credentials or implicit self-hosted target. Include USB size calculation from actual payload plus filesystem overhead, checksum verification, deliberate USB target selection, disk-erasure warning at the decision point, firmware settings, cable labeling, laptop static IP setup, certificate check, console router install, rollback and repair. Create a neutral probe guest from a bundled pinned minimal test image so base routing acceptance is reproducible without downloading a router or test dependency. Document its content/hash in the release lock; it owns no persistent enrollment identity.

Measure memory, storage peak during installation, VM allocations and reserved host overhead in each selected-role combination; write exercised budgets into the release qualification record. Unknown NIC/firmware combinations remain unqualified. Remove USB and repeat full boot; leave USB inserted and prove the menu cannot reinstall automatically. Have an operator other than the implementer follow only the written guide on a real two-port machine. Capture failures and fix the owning task before repeating affected tests.
- [ ] **4. Run** `.venv/bin/python -m pytest -q tests/appliance/` and `.venv/bin/python scripts/check_local.py`, then `python3 scripts/ci_appliance_base.py --suite all --lab-config .work/appliance-lab.json`. Expected: new and existing regressions pass. Complete the physical checklist separately; unavailable physical hardware is recorded NOT RUN and blocks release claims, while allowing code review to proceed.
- [ ] **5. Commit** with `test: qualify two-port appliance base and operator journey`. Label passing artifacts `appliance-v1-base-preview`; continue to R1–R6 before a complete V1 label.

## Self-review and specification coverage

| Specification requirement | Owning tasks |
|---|---|
| Supported install, pinned offline media, actual installed router | B1, B2, B5, B6, B7 |
| Two physical ports, stable identities, overlap, virtual zones, no host WAN address | B1, B2, B4, B7, B10 |
| Router-independent local management, credentials, certificate card | B4, B5, B8 |
| Default-deny policy, virtual DHCP, DNS/time, layer-2 trust-zone boundary | B6, B7, B8, B10 |
| Resume, ownership, uncertain mutations, rollback and local controls | B3, B4, B5, B8, B9 |
| Startup order/readiness, missing and returning WAN | B8, B10, R2 |
| Joining, approval, forced relay, no subnet advertisement | R1, R2 |
| Separate hosting eligibility and independent proofs | R3, R4 |
| Encrypted exports, consistent role state, isolated repair | B9, R5 |
| Fresh status and public service attachment contract | B8, R1–R5 |
| Real hardware and unfamiliar operator; honest release label | B10, R6 |

Plan self-review completed on 11 October 2026: every specification section maps to the tasks above; all ten Review Focus items across the two plans have owning tests; shared interfaces and dependency order were checked. The review corrected non-target storage collision handling, disconnected initial router management, early-versus-post-PVE firewall work, the continuing router control channel and private snapshot transport. Documentation validation checked local links, task structure, placeholder patterns, balanced code fences and Python example syntax. These are plan checks, not executed installer or hardware tests. No base-only milestone substitutes for the approved optional hosting scope.

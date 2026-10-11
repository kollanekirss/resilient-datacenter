# Appliance V1 implementation evidence

Work is on the isolated `feat/appliance-v1` branch, separate from the earlier service toolkit. The initial preparation commits ended at `1ead0ce`. On 11 October the project owner explicitly authorized continuing all software work without a test machine, leaving hardware execution for later. That instruction supersedes the plan's M0 stop on further development; it does not satisfy an acceptance or release gate.

| Area | Implemented | Execution/acceptance still required |
|---|---|---|
| B1: inputs and contracts | Strict site/release validation; stable disk/NIC identities; overlap and resource checks; all four base inputs downloaded, hashed and assembled into an offline input bundle | Measured budgets, complete redistribution/source inventory, optional role inputs |
| B2/B5: USB installer | Exact-source live adapter; offline ISO remaster and content readback; closed console/serial menu; fresh disk/cable/boot consent; official installer handoff; verified internal staging; pre-network first boot; explicit repair console | Actual Linux ISO assembly, boot, cancellation/canary tests, offline target install and USB-removal/retention tests |
| B3: local execution/state | Bounded subprocess boundary; private durable journals, no implicit replay, explicit observed-outcome reconciliation | Power interruption exercises on the real host/guest tools |
| B4: host network | Exactly two physical port roles, virtual guest bridges, no host WAN address/forwarding, IPv6 disabled, early host guard, PVE activation gate, fresh-SSH confirmation and timed/boot rollback | Kernel/PVE rule behavior, physical port mapping, wire captures and recovery timing |
| B6/B7: OPNsense | Owned disconnected VM installation, DVD removal/disk boot, deterministic bootstrap/transit configuration, pinned restricted SSH channel, console attestation, live checks before WAN, lease/boot guard | Console import, OPNsense-generated configuration compatibility, helper persistence, actual lease transitions and positive/negative packet probes |
| B8: operations | Local menu/commands, observed host/router status, explicit unknown states for unmeasured capabilities, bounded local startup, public virtual-network metadata | Live DNS/NTP/HTTPS/isolation evidence; no-WAN and returning-WAN operation |
| B9: export/repair | Encrypted export and inspection, owned mounted-root repair, stable disk/NIC remapping, automatic isolated clone/import/disk-boot verification and observation-only reconciliation | Actual PVE copy, FreeBSD recovery boot, canary preservation and physical repair; whole-site restoration is outside this path |
| B10: evidence | Concrete isolated Linux/KVM driver, all 11 automated scenarios, real protocol clients and controls, eight process-interruption boundaries, strict assertion/evidence gate, private reports and operator guides | Actual execution of automated cases, physical operator exercise and measured supported hardware |
| R1: Linux roles | Pinned binary/image recipe, offline builder, stopped/disconnected VM import, fixed stdin-only guest API, runtime/identity checks and no automatic replay | Linux package preparation/image assembly, real guest-agent and boot execution |
| R2: joining | Explicit owner-approved enrollment, TLS identity checked before credential use, fixed no-route client policy, persistent identity, registered-key external challenges and controlled collectors | Actual NAT/relay path, restart/WAN-return and independent endpoint execution |
| R3/R4: hosting | Separate Headscale/DERP prerequisites, endpoint collision checks, real TLS validation, persistent authorities, narrow policy, routed/no-NAT relay and fail-closed verifier | Actual public profiles, client/relay protocol behavior, source preservation and new-session admission exercises |
| R5/R6: role export/release | Stopped-service private captures, bounded hashed transfer, encrypted readback, independent-case/resource/provenance release gate and operator documentation | Real daemon/database capture and recovery, full operator run; remaining DERP wire/fault acceptance adapter |

## Evidence actually obtained

The complete offline input directory `.work/appliance-inputs` contains the locked Proxmox ISO, expanded OPNsense DVD, Ubuntu probe image and Linux Restic executable. Every file was verified against the reviewed size and SHA256. It is **not a bootable image**. Its exact release identity and vendor provenance are in [release inputs](release-inputs.md).

The actual Proxmox ISO was inspected: its boot configuration, initrd, layered live filesystems, shipped launcher, low-level installer and Perl installer sources match the adapter's pins. Python is present in the base layer; no absent installer assistant is assumed. [Installer qualification](installer-qualification.md) records the exact observations. Linux remaster tools are unavailable on this ARM Mac, so assembly/readback process tests used a controlled process substitute and do not establish a bootable output.

The real native Restic 0.19.1 binary on this Mac encrypted six synthetic private configuration components, checked its repository, refused an incorrect password without publishing output, and restored the correct snapshot byte-for-byte. Production Linux pins were unchanged. Unit tests also exercise corruption, traversal, truncation, ownership and permissions. Neither form proves hardware recovery.

Local regression checks are run through `scripts/check_local.py`; no target inventory connections are made. The final integrated result below includes all independent-review corrections.

## Independent review and corrections

A fresh independent reviewer examined the complete continuation. Confirmed issues were reproduced and corrected with focused regression tests: the host guard needed gateway-only SSH access; repair needed a separate filesystem-UUID comparison and fresh stable disk resolution after USB renumbering; the router needed narrowly scoped host update forwarding/NAT; and the host collector needed positive kernel-disabled IPv6 evidence rather than requiring nonexistent sysctl keys. Lease revocation now withdraws forwarding and guest interfaces before selective state removal, verifies the loaded guard labels, removes states again, and only then restores interfaces. Management SSH is preserved. The final scoped review also corrected host audits to use the VM adapter's canonical NIC ordering and distinguished executed lab failures from unrun prerequisites.

The implementation keeps configuration evidence distinct from packet proof. A router configuration check returns `configured`, never a claim of tested routing or isolation. Supplied JSON, successful process exits and unit fixtures cannot become actual physical acceptance. Unavailable roles and uncertain operations remain explicit refusals.

No USB was written, physical disk erased, host installed, live host networking changed, guest booted, role enrolled or release published in this workspace. The first hardware execution must use a disposable machine and the [acceptance checklist](evidence.md).

## Previous base verification

On 11 October 2026, the final integrated check completed successfully: **1,333 tests passed**, all playbook syntax checks passed, and the infrastructure/independent/join host and task listings passed without target connections. The dynamic inventory-group warnings are expected because those groups are selected at runtime. `git diff --check` and the appliance documentation's relative-file link check also passed.

All eight confirmed independent-review findings were corrected and covered by regression tests before that run. The native Restic round trip described above separately passed. Actual Linux ISO assembly, ISO boot, guest packets and physical recovery remain **NOT RUN**; the subsequent continuation below implements acceptance-scenario automation and automatic cloned-router recovery. These results establish a software-tested development base, not an accepted V1 release.


## Acceptance and isolated recovery continuation

The full acceptance profile now launches a fresh Linux user/network namespace and
private disk copies for each case. Controlled peers provide DHCP, RA, DNS, time
and TLS traffic. Scenarios cover installation/refusals, port remapping, host and
router exposure, transit/isolation, no-WAN operation, lease return/overlap,
interrupted operations and encrypted export/repair. Local protocol tests use
actual loopback sockets, temporary certificates and Unix serial sockets; they do
not simulate a successful physical qualification.

The recovery command imports an inspected configuration into a copy of a stopped
owned router, checks it through private serial challenges, boots the copy with
its DVD removed, and leaves it stopped. Every NIC is disconnected on an owned
empty bridge, which is removed after shutdown. It supports the documented GPT/UFS
layout and never promotes the copied identity. The original disk is required;
the export is not a whole-machine backup.

The full driver and automatic router provisioning are software implementations,
with actual PVE/OPNsense execution still NOT RUN. First-boot model migration
compatibility is deliberately checked by the strict configuration audit; unknown
vendor-generated defaults cause an explicit refusal until reviewed. No release
qualification or supported-hardware claim follows from local tests.


## Final continuation verification — 11 October 2026

After the independent review and integration corrections, `scripts/check_local.py`
completed successfully: **1,522 tests passed**, all Ansible syntax checks passed,
and the infrastructure/independent/join task and host listings passed without
connecting to targets. The final appliance-only run separately passed 590 tests.
The suite includes real local PTY requests larger than 16 KiB, DNS/NTP/HTTP/TLS
socket exchanges, a CA-signed persistent TLS connection and Unix serial
handshakes, alongside explicitly synthetic hypervisor boundary tests.

Review corrections covered serial framing, fresh disks for interrupted cases,
observed response schemas, certificate preservation and trust, cold-boot probe
state, interface-name recovery, controller-held export credentials, direct WAN
frames to the selected physical NIC and accurate launch/failure classification.
The final scoped independent review reported no remaining blockers. Staged
whitespace checks and appliance documentation links passed.

Actual Linux ISO assembly, UEFI boot, PVE/OPNsense execution and packet behavior,
FreeBSD model migration compatibility, resource measurements and the physical
operator exercise remain **NOT RUN**. Those require the later disposable test
machine. No hardware was modified, and no release was published.

## Joining and independent hosting continuation

The connector, Headscale and DERP now have separate guest provisioning,
configuration and inspection paths. Enrollment requires owner approval and
verified controller TLS before using a single-use credential. Existing node,
authority and relay identities survive reconnection; uncertain mutations are
queried or reconciled without automatic replay. Headscale and DERP eligibility
are evaluated independently. Public hosting requires registered external probe
evidence in addition to local configuration.

The role image recipe pins the reviewed Tailscale and Headscale binaries and an
actually cross-built Linux DERP executable. Linux package preparation, offline
image assembly and boot remain unexecuted. The image builder records its actual
output digest and runtime-source receipt rather than using a placeholder hash.

Independent review corrected disconnected guest initialization, read-only
inspection accidentally blocking enrollment, unrelated-peer enrollment proofs,
snapshot failure/interruption recovery and compatibility between role exports
and isolated router repair. Targeted regression tests reproduce those failures.

The real native Restic binary on this Mac also encrypted and independently
restored nine synthetic private components, including all three role archives.
Every recovered byte matched; a wrong password published no output. No restored
identity was activated, and production Linux binary pins were unchanged.

The role acceptance preflight correctly reports every case **NOT RUN**. Complete
machine orchestration, the DERP wire-session and verifier-fault adapters, and
actual public-network qualification remain outstanding as detailed in the
[qualification record](qualification.md). The implementation is a development
candidate, not a qualified V1 release.

Final verification on 11 October 2026: `scripts/check_local.py` passed **1,696
tests**, all Ansible syntax checks and all read-only infrastructure/independent/
join host/task listings. The final scoped independent review found no remaining
confirmed blockers in the corrected code. Appliance documentation links resolve,
the role example previews without enabling destructive actions, and the role
preflight leaves all eight acceptance cases NOT RUN. Native Restic role-archive
encryption/readback passed separately as described above. No machine was
installed, joined or published during this continuation.

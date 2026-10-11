# Appliance evidence and outstanding acceptance

Evidence has distinct scopes. Do not promote one scope into another:

| Scope | What it establishes | What it does not establish |
|---|---|---|
| Input digest/source inspection | Selected bytes match reviewed pins; adapter paths match inspected media | The rebuilt ISO boots or installation completes |
| Unit/process tests | Parsing, command boundaries, ordering, journals and file behavior under controlled inputs | Hypervisor, firmware, NIC driver or guest behavior |
| Local Restic round trip | Actual encrypted capture, restore and wrong-password refusal | Recovery of a physical host or router |
| Assembled-image receipt | Build inputs/output hash and content readback | Safe boot, disk preservation or wire policy |
| Router configuration inspection | Current pinned management channel, guest boot/config observations | Allowed/denied traffic with working endpoints |
| Disposable lab and physical runs | Only the individual cases actually executed with captured evidence | Unrun cases, other hardware or optional roles |

The lab script defaults to read-only prerequisite checks. Explicit `--execute` with the full acceptance profile runs scripted installation, refusal, port mapping, routing, interruption and recovery cases in fresh disposable QEMU guests; see [lab setup](lab.md). A private Linux user/network namespace holds the two virtual physical wires and controlled DHCP, RA, DNS, NTP and TLS peers. Pinned regular input images remain read-only; only new copies are writable. Evidence includes bounded serial observations, raw packet/protocol observations, disk digests and actual resource journals. A new worker and private disk set are used for every case.

The `automated` suite covers every nonphysical case, including boot-menu cancellation. The `all` suite additionally leaves the physical operator exercise explicitly NOT RUN. Exact assertions, common build/plan/source/spec/run identities, unchanged captured files and a 24-hour evidence review window are required by the release gate. Failed attempts are never accepted as isolation unless source and destination controls work and the observed failure is a network refusal or timeout. Injected drivers always remain synthetic even if their assertions pass. Reports validate captured evidence; they do not authenticate user-supplied JSON, publish a release or certify unrun hardware.

Interruption automation exits a child without unwinding at eight real operation boundaries, observes the pending journals and reconciles only observed results. New allocation, start, policy and link commands during reconciliation are counted as replay. Installer uncertainty and interrupted USB repair can retain pending state with an explicit inspection step; they never silently restart disk installation. Automatic router recovery imports onto a copy of the stopped owned router disk, uses a temporary empty bridge with all links down, verifies disk-only boot and leaves the copy stopped. Neither path promotes a duplicate identity onto the network.

Required base cases are `offline-install`, `erase-refusals`, `port-mapping`, `wan-exposure`, `routed-policy`, `router-down-management`, `no-wan-boot`, `wan-return`, `interrupted-resume`, `export-repair` and `physical-operator`.

For later execution, capture the exact build/ISO digests, firmware and hardware identities, starting/final target and canary disk hashes, bounded console logs and WAN/management packet traces. Verify at least:

- Cancellation, identity changes, duplicate serials, unsafe shared storage and USB retained at reboot never trigger an unintended erase.
- No host WAN IPv4/DHCP or IPv6/link-local address appears from earliest live boot through installed boot.
- Offline installation stages all required base media and survives USB removal.
- Management works by numeric IP with router stopped, WAN absent and DNS unavailable; broken or interrupted changes recover after timeout and cold boot.
- Router defaults never emit DHCP/RA onto management; installed-root evidence survives DVD removal.
- Bootstrap denies guest forwarding; approved transit works only after fresh overlap checks. A conflicting DHCP lease or renewal returns to denial without stale states preserving access.
- Every denial test has independently working source/destination controls. Test router/host administration from both physical sides, not merely a nonexistent WAN address.
- Export decrypts with an independently held credential; mounted-root repair preserves unrelated disks; copied router identity is never activated on the live network.
- An unfamiliar operator follows only the guide on a real two-port machine, and measured memory/storage budgets replace provisional allocations.

Current hardware and guest-packet acceptance is **NOT RUN**. Optional network-role provisioning and complete V1 qualification remain in the separate roles plan.

The [neutral probe](probe.md) now has a private NoCloud seed, pinned offline image import, explicit disconnected startup and a console/runtime gate before its sole workload connection. Probe provisioning is software-tested; its actual cloud-init behavior and traffic probes remain NOT RUN.

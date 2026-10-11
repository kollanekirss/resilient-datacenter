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
| B9: export/repair | Encrypted Restic export with content restore proof, separate password, private archive inspection, exact owned mounted-root management repair, stable disk re-resolution and NIC remapping | Physical recovery, unrelated-disk canaries and isolated router configuration reimport; whole-site restore and automatic cloned-router recovery are not provided |
| B10: evidence | Private neutral probe seed/import and guarded workload attachment; unit-only CI, strict case membership/freshness gate, disposable boot/cancel runner and operator guides | All named complete acceptance scenarios, physical operator exercise and measured supported hardware |
| R1–R6 | Explicitly unavailable in this base | Connector joining, independently eligible Headscale/DERP hosting and complete V1 qualification |

## Evidence actually obtained

The complete offline input directory `.work/appliance-inputs` contains the locked Proxmox ISO, expanded OPNsense DVD, Ubuntu probe image and Linux Restic executable. Every file was verified against the reviewed size and SHA256. It is **not a bootable image**. Its exact release identity and vendor provenance are in [release inputs](release-inputs.md).

The actual Proxmox ISO was inspected: its boot configuration, initrd, layered live filesystems, shipped launcher, low-level installer and Perl installer sources match the adapter's pins. Python is present in the base layer; no absent installer assistant is assumed. [Installer qualification](installer-qualification.md) records the exact observations. Linux remaster tools are unavailable on this ARM Mac, so assembly/readback process tests used a controlled process substitute and do not establish a bootable output.

The real native Restic 0.19.1 binary on this Mac encrypted six synthetic private configuration components, checked its repository, refused an incorrect password without publishing output, and restored the correct snapshot byte-for-byte. Production Linux pins were unchanged. Unit tests also exercise corruption, traversal, truncation, ownership and permissions. Neither form proves hardware recovery.

Local regression checks are run through `scripts/check_local.py`; no target inventory connections are made. The final integrated result below includes all independent-review corrections.

## Independent review and corrections

A fresh independent reviewer examined the complete continuation. Confirmed issues were reproduced and corrected with focused regression tests: the host guard needed gateway-only SSH access; repair needed a separate filesystem-UUID comparison and fresh stable disk resolution after USB renumbering; the router needed narrowly scoped host update forwarding/NAT; and the host collector needed positive kernel-disabled IPv6 evidence rather than requiring nonexistent sysctl keys. Lease revocation now withdraws forwarding and guest interfaces before selective state removal, verifies the loaded guard labels, removes states again, and only then restores interfaces. Management SSH is preserved. The final scoped review also corrected host audits to use the VM adapter's canonical NIC ordering and distinguished executed lab failures from unrun prerequisites.

The implementation keeps configuration evidence distinct from packet proof. A router configuration check returns `configured`, never a claim of tested routing or isolation. Supplied JSON, successful process exits and unit fixtures cannot become actual physical acceptance. Unavailable roles and uncertain operations remain explicit refusals.

No USB was written, physical disk erased, host installed, live host networking changed, guest booted, role enrolled or release published in this workspace. The first hardware execution must use a disposable machine and the [acceptance checklist](evidence.md).

## Final verification

On 11 October 2026, the final integrated check completed successfully: **1,333 tests passed**, all playbook syntax checks passed, and the infrastructure/independent/join host and task listings passed without target connections. The dynamic inventory-group warnings are expected because those groups are selected at runtime. `git diff --check` and the appliance documentation's relative-file link check also passed.

All eight confirmed independent-review findings were corrected and covered by regression tests before that run. The native Restic round trip described above separately passed. Actual Linux ISO assembly, ISO boot, guest packets and physical recovery remain **NOT RUN**; complete acceptance-scenario automation and automatic cloned-router recovery are also outstanding. These results establish a software-tested development base, not an accepted V1 release.

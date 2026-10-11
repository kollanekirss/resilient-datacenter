# Disposable appliance acceptance lab

The software now includes concrete adapters for every nonphysical V1 acceptance
case. Actual Linux/KVM execution is still **NOT RUN**; unit tests and localhost
protocol tests do not qualify the installer or the appliance. Physical USB boot,
real cabling, and the operator exercise remain separate work for a test machine.

Preview performs read-only prerequisite checks. Execution requires `--execute`
and both opt-in configuration sections below:

```text
python3 scripts/ci_appliance_base.py --suite automated --lab-config /absolute/path/lab.json
python3 scripts/ci_appliance_base.py --suite automated --lab-config /absolute/path/lab.json --execute
```

`automated` requests every nonphysical case. Individual suites are `media-gate`,
`host-network`, `offline-install`, `router-policy`, `base-operations`, and `repair`.
`all` also requests `physical-operator`, which this harness always marks NOT RUN.
Exit 0 requires every exact requested assertion and its evidence to pass; exit 1
means failure, and exit 2 means missing or unrun coverage. Even a fully passing
virtual suite leaves hardware qualification NOT RUN.

## Owned execution profile

Use a dedicated x86-64 Linux machine with KVM, nested virtualization enabled,
user and network namespace support, `/dev/net/tun`, and matching OVMF CODE/VARS.
The outer guest needs 16–64 GiB RAM and 4–16 virtual CPUs to host Proxmox, the
router, and the neutral probe. Provision enough physical RAM for that allocation
and enough free storage for retained per-case image copies. No cloud account,
live bridge, host block device, public network, or existing router is used.

Create a dedicated 0700 workspace owned by the invoking user. The runner never
adopts an arbitrary directory. Its existing 0600 regular ownership marker,
`.rdc-appliance-lab.json`, must contain:

```json
{"schema":1,"owner_id":"my-disposable-appliance-lab"}
```

The complete configuration uses absolute paths and actual hashes. All images and
metadata below must be regular, single-link files within that private workspace.
Tool paths may name trusted system executables; they are independently pinned.
The placeholders below must be replaced before preview or execution:

```json
{
  "schema": 1,
  "workspace": "/absolute/path/to/private-lab",
  "owner_id": "my-disposable-appliance-lab",
  "build_id": "BUILT_ISO_RECEIPT_BUILD_ID",
  "spec_id": "SPEC_FILE_SHA256",
  "images": {
    "installer": {"path": "/absolute/path/to/private-lab/candidate.iso", "sha256": "ACTUAL_SHA256"},
    "target": {"path": "/absolute/path/to/private-lab/target-seed.raw", "sha256": "ACTUAL_SHA256"},
    "canary": {"path": "/absolute/path/to/private-lab/canary-seed.raw", "sha256": "ACTUAL_SHA256"},
    "uefi_code": {"path": "/absolute/path/to/private-lab/OVMF_CODE.fd", "sha256": "ACTUAL_SHA256"},
    "uefi_vars": {"path": "/absolute/path/to/private-lab/OVMF_VARS.fd", "sha256": "ACTUAL_SHA256"}
  },
  "build_receipt": {"path": "/absolute/path/to/private-lab/candidate.iso.json", "sha256": "ACTUAL_SHA256"},
  "plan": {"path": "/absolute/path/to/private-lab/site.json", "sha256": "ACTUAL_SHA256"},
  "spec": {"path": "/absolute/path/to/private-lab/spec.md", "sha256": "ACTUAL_SHA256"},
  "qemu_sha256": "DETECTED_QEMU_BINARY_SHA256",
  "execution": {"enabled": true, "timeout_seconds": 7200, "memory_mib": 16384, "vcpus": 4},
  "acceptance": {
    "enabled": true,
    "case_timeout_seconds": 7200,
    "tools": {
      "openssl": {"path": "/usr/bin/openssl", "sha256": "ACTUAL_SHA256"},
      "ssh": {"path": "/usr/bin/ssh", "sha256": "ACTUAL_SHA256"},
      "ssh-keygen": {"path": "/usr/bin/ssh-keygen", "sha256": "ACTUAL_SHA256"}
    }
  }
}
```

The QEMU executable is discovered as `qemu-system-x86_64` on PATH. The build
receipt must match the ISO and the complete current package source manifest.
Rebuild the candidate ISO after changing package code or units. Both timeout
values are bounded at 30–7200 seconds. The case timeout covers the whole case,
including setup and all its actions, with separately bounded process cleanup.

The pinned site plan must describe this exact disposable hardware profile:
`RDC-LAB-TARGET` and `RDC-LAB-CANARY` disk serials, management MAC
`52:54:00:77:00:01` at PCI address 0x5, and WAN MAC `52:54:00:77:00:02` at 0x6.
Use the complete stable identities reported by the pinned QEMU/installer,
including target capacity, by-id path, PCI path, and driver. The driver does not
silently rewrite a mismatching plan. The plan uses DHCP upstream with one
nonoverlapping private lab CIDR and has no optional Headscale/DERP roles selected.
Its target seed must satisfy the release's storage budget. All image inputs are
bounded at 128 GiB each and metadata at 1 MiB.

Preflight validates all configuration, ownership, hashes, source/build identity,
tools, KVM, and resource constraints before creating a run. Symlinks, hard links,
block devices, unsafe ancestors, changed pins, or a busy workspace stop it. A
missing kernel namespace capability stops the worker before any network setup;
there is no fallback to the machine's network namespace.

## What the driver executes

Each case gets a fresh worker, a new Linux user/network namespace, and private
regular-file copies of target, canary, and UEFI variables. QEMU receives held
file descriptors with explicit raw formats. It cannot open a backing image or
host disk through a supplied image path. The installer and firmware CODE remain
read-only. Repeated refusal variants retire only their own stopped copies after
recording their final hashes; final case copies and evidence remain available.

Two TAP endpoints exist only in the new namespace. They represent the physical
management and WAN ports. Controlled peers provide DHCP, DNS, NTP, verified TLS,
nonce listeners, and DHCP/IPv6-RA capture controls. They have no uplink, NAT, or
host bridge. Network captures start before QEMU starts. The Proxmox guest creates
its internal bridges through the production installer. Temporary internal probe
namespaces exist only inside that disposable guest and are removed before host
audits.

The source-pinned serial protocol verifies the fresh QEMU SMBIOS UUID and
`RDC Disposable Acceptance` marker. Frames have request sequence and token
bindings, explicit size bounds, and noncanonical terminal input so a large plan
cannot be silently truncated. It invokes the production installer, network
confirmation, router gates, probe, export, repair, and clone-recovery APIs.
Management confirmation uses an actual SSH/logind session from the management
peer, with the host key pinned from the local console.

The scenarios cover:

- Closed boot-menu cancellation, offline installation, disk-only boot, retained
  USB boot, installation resource observations, and erase refusal variants.
- Stable port identities, changed names with fail-closed boot and explicit USB
  repair, replacement NIC and wrong-cable refusal, and independent management
  rollback after timeout, process death, and reboot.
- Host WAN address exposure from early boot; physical DHCP/RA absence with live
  capture controls; router and host administration boundaries; DNS/NTP/HTTPS and
  cross-zone policy with working source and destination controls.
- Router-down management, no-WAN startup, first and renewed overlapping WAN
  leases, fresh explicit transit gates, and withdrawal of an already established
  TLS connection together with actual router state-table observations.
- Eight real interruption boundaries, durable journals, refusal to repeat unsafe
  work, encrypted export, wrong-key/corruption refusal, numeric-address management
  repair, and automatic isolated cloned-router recovery.

The OPNsense setup uses the pinned DVD's installer in a private GPT/UFS guest,
then verifies its console bootstrap and disk boot before opening product gates.
DVD remastering uses Proxmox's bundled `genisoimage`; no extra package download is
needed. Clone recovery uses a separate private DVD and a disk-only proof, leaves
the clone stopped with no network bridge attachments, and keeps the original
router stopped. See [router recovery](router-recovery.md) for its layout limits.

The export key is generated and held by the controller. The guest receives it
only for the requested sealing or inspection operation, removes its temporary
credential file afterward, and reports its digest and actual removal. Private
login keys and passwords are ephemeral lab data. Action evidence redacts them;
serial logging stops before credential and protocol exchange. Retain the whole
workspace as private because guest disk copies and private run files contain
lab credentials and exported configuration.

## Evidence and execution limits

Each run preserves `result.json`, a readable `report.txt`, per-case action
records with hashes, boot-console observations, worker diagnostics, and owned
image copies. Every accepted observation is bound to the run, plan, build,
specification, source, and current host boot identity. Assertions evaluate raw
commands, packet bytes, kernel state, and real receipts. A caller-supplied PASS
label or result JSON is never accepted as proof of execution. Test substitutes
are irreversibly marked `unit-fixture` and NOT RUN.

A real QEMU launch is reported immediately, before waiting for boot prompts.
A subsequent timeout, early exit, failed assertion, or cleanup error is FAIL.
Prerequisites that stop execution before launch are NOT RUN. The runner stops
its owned process groups and verifies cleanup; parent-death signals bound abrupt
controller loss. Original image hashes and package source identity are checked
again before completing the report.

The implementation has been exercised with unit tests and local PTY/socket/TLS
protocol tests. The first owned Linux run must still confirm actual OVMF/KVM
boot, the pinned installer and OPNsense release behavior, nested virtualization,
real timing and memory budgets, and end-to-end recovery. Software test success
does not replace those observations or the later physical operator exercise.

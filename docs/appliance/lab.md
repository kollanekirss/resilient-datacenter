# Disposable appliance boot lab

The lab command is read-only unless `--execute` is present. Execution is currently
limited to one real console scenario: `boot-menu-cancel`, included in
`media-gate` and `all`. No physical machine or QEMU guest has been qualified by
the implementation's unit tests.

```text
python3 scripts/ci_appliance_base.py --suite media-gate --lab-config /absolute/path/lab.json
python3 scripts/ci_appliance_base.py --suite media-gate --lab-config /absolute/path/lab.json --execute
```

Every current suite exits **2**, including a successful boot-menu observation.
That observation covers only a small part of the media gate. It cannot turn
offline installation, network policy, recovery, or physical tests into a pass.
Unsupported suites do not launch a guest.

## Owned execution profile

Use a dedicated x86-64 Linux machine with accessible KVM, a pinned QEMU binary,
and matching OVMF CODE/VARS files. The driver requires a private, already existing
0700 workspace owned by the invoking user. It will not create its ownership
marker or adopt an arbitrary directory. Create the marker deliberately as a
0600 regular file named `.rdc-appliance-lab.json`, containing:

```json
{"schema":1,"owner_id":"my-disposable-appliance-lab"}
```

The configuration keeps the original schema-1 preflight fields and adds explicit
execution limits and pinned metadata. Every `path` below is an absolute path to
an existing regular, single-link file inside that workspace. Supply actual hashes
and the actual built-ISO receipt; the example names are placeholders.

```json
{
  "schema": 1,
  "workspace": "/absolute/path/to/private-lab",
  "owner_id": "my-disposable-appliance-lab",
  "build_id": "COPY_THE_BUILT_ISO_RECEIPT_BUILD_ID",
  "spec_id": "SHA256_OF_THE_SPEC_FILE",
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
  "qemu_sha256": "SHA256_OF_THE_DETECTED_QEMU_EXECUTABLE",
  "execution": {"enabled": true, "timeout_seconds": 300, "memory_mib": 4096, "vcpus": 2}
}
```

The QEMU executable is discovered as `qemu-system-x86_64` on the process PATH;
its exact regular-file bytes must match `qemu_sha256`. Metadata and image hashes,
the ISO sidecar's build identity, image size/hash, approved installer adapter and
upstream source revision must match. The sidecar's runtime identity must match
the complete current appliance source manifest. Rebuild the ISO after changing
package code or units. The pinned plan is recorded for traceability; this
scenario does not submit it to installation or claim it was applied.

Execution accepts 30–900 seconds of guest observation, 1024–8192 MiB of guest
memory, and 1–4 virtual CPUs. Inputs are bounded at 128 GiB each and metadata at
1 MiB. Regular files and safe ancestors are checked again through descriptors
before mutation. Block devices, symlinks, hard links, writable inherited
directories, changed hashes, ambiguous ownership, and a busy workspace stop the
run. No downloads or host networking setup occurs.

## What execution does

The runner exclusively locks the workspace and creates a new 0700
`run-<random-id>` child. It copies the raw target seed, canary seed, and OVMF
variables there, checks their hashes, and keeps all outputs private. It never
reuses an existing writable guest disk. Firmware CODE and the installer image
are read-only; only the newly created copies can be written by QEMU. Explicit
raw formats prevent a seed from naming a QCOW backing file outside the run.

QEMU receives already opened regular-file descriptors, KVM acceleration, bounded
memory/CPU settings, a serial pipe, no display or monitor server, and two
disconnected virtual Ethernet devices. `-nic none` disables implicit networking.
There is no user-mode networking, NAT, port forwarding, tap, bridge, socket
network backend, host directory export, or PCI passthrough. This tests ISO/UEFI
boot behavior inside a VM; it does not test physical USB boot or live WAN traffic.

The console scenario performs only these actions:

1. Observe the closed GRUB menu and select its serial-console setup entry.
2. Observe the appliance menu, send an empty selection, and require its explicit
   “No action selected” response and return to the menu.
3. Select the explicit local recovery console, observe its prompt, send `exit`,
   and require the menu to return.
4. Stop QEMU, then compare the complete target and canary disk hashes. Both must
   be unchanged. Firmware-variable changes are recorded and allowed.

It never selects `Install`, enters a target identifier, submits an erase
confirmation, mounts a disk, or sends an installation plan. Prerequisite and
prelaunch failures leave the case `NOT RUN`. Once a real QEMU process launches,
missing prompts, unsupported console behavior, early exit, timeouts, cleanup
errors, and observed content changes make the case and report `FAIL`. Simulated
process boundaries always remain `NOT RUN`. Blank-menu cancellation does
not satisfy the separate `erase-refusals` case, which needs its own assertions.

The single-threaded process driver terminates the whole QEMU process group,
escalates to a kill after five seconds, and closes descriptors. On Linux, QEMU
also receives a parent-death signal before execution so an abruptly killed
harness does not leave it running. The race before signal registration is
checked. An interrupted or incomplete evidence directory is not acceptance;
retain it for inspection rather than replaying it.

## Evidence and remaining cases

Each run preserves `launch.json`, `serial.log`, `qemu.log`, and `result.json`
alongside its disposable image copies. The result includes:

- Build, plan, specification, exact lab configuration, current package source,
  built-ISO receipt and QEMU identities.
- Raw console and QEMU diagnostic file hashes, process cleanup outcome, and
  individual observed assertions.
- Initial/final hashes for each original image and each writable copy; source
  replacement or source-code drift prevents verification.
- Separate `NOT RUN` entries for every requested unsupported case.

A supported real observation may have case state `verified`, status `OBSERVED`,
and method `real-execution`. The overall status is still `PARTIAL` and
`qualification` remains `NOT RUN`. The driver never accepts a supplied result
JSON as evidence that it executed a guest. Its private test seams force method
`unit-fixture`, unknown case state and `NOT RUN`, even if a fake process emits
all expected prompts. `evaluate_results` remains an evidence-integrity helper,
not an authenticity check or a qualification authority.

Offline installation, target-selection and erase refusals, WAN DHCP/IPv6
exposure, installed-host management, router policy, interruption/reboot recovery,
export/repair, and the physical operator exercise still need real dedicated
scenarios. OVMF/serial behavior, QEMU seccomp support, the complete process-death
path, and actual media boot remain unqualified until this driver runs on the
owned Linux lab with the locked inputs.

The storage, network and sandbox switches follow the
[QEMU invocation documentation](https://qemu-project.gitlab.io/qemu/system/invocation.html).

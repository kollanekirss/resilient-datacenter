# Appliance V1 preparation tools

This is the first implementation batch for the [approved design](../superpowers/specs/2026-10-11-two-port-network-appliance-v1-design.md). It prepares and checks inputs. **It does not yet produce a bootable appliance USB or install Proxmox.** The upstream installer adapter, live boot test and physical two-port acceptance are still required; `install` fails explicitly and has no override.

The new `rdc-appliance` command is separate from the existing `rdc` service toolkit. It uses Python 3.11 or newer and the standard library. On the preparation computer it needs no administrator privileges and does not change network settings or open target disks.

## Check the release and proposed layout

From the repository root:

```sh
./rdc-appliance status
./rdc-appliance inspect
./rdc-appliance release-check
./rdc-appliance preview examples/appliance-site.json
```

The example is illustrative: its disk identifiers, port identities, addresses and VM assignments must be replaced with observations and choices for the actual machine. A successful preview validates that the plan is internally consistent. It does not prove that the machine or cables match it, and never enables installation.

The plan fixes the two ports by permanent MAC and PCI identity. It validates separate management, infrastructure and workload subnets against upstream and overlay ranges, VM resource budgets, fixed guest MACs, unique addresses and attachment permissions. Only the router may attach to management or WAN. Future live installation must refresh observations and recheck disk identity immediately before invoking the official installer.

An existing inventory can be checked without applying it:

```sh
./rdc-appliance preflight my-site.json --inventory my-inventory.json
```

This command remains blocked by the unqualified installer even when the supplied facts are consistent. User-supplied inventory cannot become boot evidence. `inspect` reports build-platform prerequisites only; automatic physical disk/NIC inventory and the cable-identification journey are not implemented yet.

## Prepare verified media

The [release input record](release-inputs.md) explains the exact versions and provenance. The lock pins both compressed and expanded artifact identities. The downloader bounds reads/decompression, verifies official checksum documents, rejects cache tampering and publishes only fully checked files. It does not execute downloaded software.

```sh
./rdc-appliance media prepare opnsense-dvd --cache .cache/appliance-media
./rdc-appliance media prepare restic --cache .cache/appliance-media
```

The first OPNsense preparation downloads roughly 494 MB and produces an approximately 2.1 GB ISO. Cached inputs are verified again before reuse. Arbitrary redirects and environment proxies are refused. The sole redirect exception is the official Restic release path on GitHub to its HTTPS release-assets host; the artifact and checksum pins still apply.

To verify an already held compressed artifact without downloading:

```sh
./rdc-appliance media verify opnsense-dvd --file /absolute/path/OPNsense-26.7-dvd-amd64.iso.bz2
```

Add `--expanded` when checking the decompressed file. That command establishes pinned-content integrity; it does not independently claim a vendor signature verification.

## Assemble an offline input directory

```sh
./rdc-appliance bundle prepare --cache .cache/appliance-media --output .work/appliance-inputs
./rdc-appliance bundle verify --output .work/appliance-inputs
```

Create the output's parent directory first. The bundle contains verified Proxmox, OPNsense, neutral probe and Restic inputs, the release lock and a completion manifest. It copies files into a separate directory, so later cache changes cannot change the bundle. Allow about 4.5 GB for the complete bundle in addition to the media cache, and additional space for later image construction.

**This directory is not bootable and must not be written to a USB as an installer.** Its manifest explicitly records `bootable: false`. An interrupted build leaves no valid completion manifest. A complete existing bundle is reverified; an incomplete or unrelated output is refused instead of overwritten. Preserve or remove that directory deliberately, then select a new output directory to retry.

Use `--json` before the subcommand for structured output. Exit 0 means that particular preparation/check command completed; exit 2 reports a refusal or unmet prerequisite. No preparation success implies installation acceptance.

## What must happen next

The [base implementation plan](../superpowers/plans/2026-10-11-appliance-v1-base.md) remains authoritative. Next is the exact-version live-media adapter: an Install / Repair / Exit menu before DHCP and destructive code, explicit disk confirmation, preservation of non-target disks, verified internal staging and safe first boot. The current lab tool checks prerequisites and returns NOT RUN; it does not launch or test VMs:

```sh
python3 scripts/ci_appliance_base.py --suite media-gate --lab-config .work/appliance-lab.json
```

A disposable x86-64 Linux/KVM machine is needed to develop and qualify those scenarios. A real two-port machine and another operator are required for the USB and wiring claims. Proxmox bridge/firewall application, OPNsense VM installation/configuration, the installed-host menu, rollback, role provisioning and private export remain subsequent work. The private state library already provides durable operation records for that work; its existence is not evidence that host operations are implemented.

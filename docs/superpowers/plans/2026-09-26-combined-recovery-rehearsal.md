# Combined Disconnected Recovery Rehearsal

> Execute inline with superpowers:executing-plans. Use a separate final reviewer.

## Approved objective and boundary

Exercise routing, DNS/time, one frontend and both applications together; recover
on fresh replacements from carried public/private material and measure interruption
and per-application backup age. No physical server is available. Production
OPNsense/Proxmox provisioning remains guided, so this acceptance uses a clearly
labelled Linux routing fixture and network namespaces for infrastructure. It must
never be reported as OPNsense, DHCP, Proxmox or physical complete-kit acceptance.

## Architecture

A disposable Ubuntu/KVM runner controls two pinned Ubuntu application guests.
Each guest has a restricted management console and one private TAP LAN. Separate
staff, routing, DNS/time and frontend namespaces share only declared bridges.
There is no uplink in any service/client namespace; guest management NAT is
restricted from first boot. The controller prepares artifacts while connected;
its GitHub control connection is outside the disconnected service boundary.

Use real Unbound/chrony and generated product configuration, production backend
and frontend installers, real Matrix/Nextcloud protocol clients, existing native
snapshot/restore transactions and the verified encrypted private package. Carry
native snapshots as hash-protected private tar files to retain numeric ownership;
extract into new staging with safe archive filtering, then run native validation.

Start baseline services; resolve names and use both applications. Capture both
snapshots without intervening client writes, then create one known later message
and one later file version. Seal the recovery inputs. Fence originals with QEMU
process termination checks before replacement creation. Remove fixture network
and frontend/DNS state; rebuild it from decrypted carried configuration. Install
new guests offline, restore exact native snapshots, then enable the shared
frontend and verify originals present/later writes absent. No live identity
promotion is exposed as a new operator command.

## Tasks

- [ ] Add failing tests for isolated guest command, safe snapshot archive handling,
  fencing requirement and honest measurement/evidence boundaries.
- [ ] Implement focused fixture network, guest-action and client modules. Preserve
  existing standalone application/network test semantics.
- [ ] Implement orchestration using existing public/private bundles and new guests.
  Record monotonic recovery duration and UTC per-role backup age; distinguish
  known test writes from a general data-loss guarantee.
- [ ] Add guarded disposable workflow, failure diagnostics and operator-facing
  evidence document. Run local checks, independent review and hosted rehearsal.

## Constraints and review focus

No server software on preparation Mac. No actual institutional data. No reuse of
existing host resources. No automatic cloud enrollment. Do not expose private
bundle contents or synthetic passwords in logs. No bypass of certificate checks.
Do not create a replacement while the original QEMU process remains alive.
Service access must use local DNS, not hard-coded frontend addressing. The test
must fail if a denied path unexpectedly works or saved data fails to restore.
Use bounded waits and report precise infrastructure/OS installation exclusions.

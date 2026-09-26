# Combined disconnected recovery rehearsal

This disposable acceptance joins local routing, Unbound DNS, chrony time service,
a shared HTTPS frontend, Matrix/Element and Nextcloud in one recovery exercise.
It is a **Linux service rehearsal**, not complete OPNsense/Proxmox or physical-kit
acceptance. Implementation and local checks alone are not a successful rehearsal;
a passing hosted run must be recorded below.

## What runs

Two pinned Ubuntu application VMs connect to an isolated application LAN. Separate
Linux network namespaces provide the routing fixture, DNS/time, frontend and staff
client. Staff can reach the frontend and DNS/time; only the frontend can reach
application HTTPS. The staff client uses the original DNS names and validates TLS
against the carried local CA. Chat and files use their existing local accounts.

Acquisition happens online on the disposable controller. Application VMs use
restricted QEMU networking from first boot, including replacements; the service
namespaces have no Internet uplink. The controller retains its GitHub connection
and private, pinned SSH consoles. This management connection is outside the
isolated service boundary. The workflow requires a fresh Ubuntu 24.04 KVM runner
with at least 12 GiB RAM; it must never run on a preparation workstation.

## Failure and recovery sequence

1. Build the verified public software bundle, then install real applications.
2. A staff client logs in, creates a chat message and uploads a file.
3. Capture and validate native application snapshots, then write one later
   message and overwrite the file. Those later writes are deliberately unbacked.
4. Encrypt the snapshots, configuration, trust/TLS material, synthetic credentials
   and client verification state using the private recovery package.
5. Start the recovery timer. Disable the routing fixture and verify staff access fails while independent
   management consoles remain usable.
6. Stop both original VMs, require confirmed process
   termination, remove their disks, remove the fixture infrastructure/frontend
   and delete the original plaintext recovery input.
7. Decrypt and verify the carried package. Rebuild infrastructure, create fresh
   Ubuntu guests, bootstrap software from the public bundle, and restore both
   native snapshots. Only then enable the shared frontend.
8. Repeat staff DNS/time, TLS and login checks. Require the saved message/file to
   survive and the two later writes to be absent. Require direct backend access
   and Internet access from the staff network to remain blocked.

The result reports measured recovery duration and each snapshot's age when the
recovery timer started. These are synthetic observations, not an RTO/RPO promise.
The timer includes decrypting the package, rebuilding infrastructure and fresh
application installation/restoration. It excludes initial artifact acquisition,
backup preparation. It includes detection of the simulated gateway failure.

## Evidence and boundaries

Hosted result: **pending**. Local contract tests cover fencing, restricted guest
networking, safe ownership-preserving snapshot extraction and evidence labels.

Infrastructure namespaces share the controller kernel and preinstalled packages;
application VMs start from a pinned, preinstalled Ubuntu image. This does not
exercise OS media installation, physical disks, UPS behaviour, VLAN hardware,
DHCP, OPNsense configuration import, Proxmox recovery or real relocation. The time
service uses the fixture host's RTC; successful NTP responses do not prove UTC
accuracy. No external SSO, partner federation or multi-site write merging is
claimed. Recovery package passwords remain independently held on the controller.

The next physical acceptance must replace the routing fixture with actual
OPNsense, deploy on Proxmox, prepare an ordinary staff device and repeat cold boot,
relocation and recovery using the printable operator runbook.

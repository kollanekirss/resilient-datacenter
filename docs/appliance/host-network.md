# Two-port host networking

This code implements the V1 host boundary. It has filesystem and scripted-command
tests; it has **not** qualified a bootable image, Proxmox firewall release, physical
NIC, or recovery time on hardware. The lab gate remains `NOT RUN` until a real
runner supplies the required observations.

## Configuration and activation

The host has one static IPv4 address, on `vmbr0`, and one default route through
OPNsense on that same management network. DNS and time use that router address.
The selected management Ethernet port is the sole physical member of `vmbr0`;
the selected WAN Ethernet port belongs only to `vmbr1`. `vmbr2`, `vmbr3`, and the
optional `vmbr4` contain guest links only. They have no host address or gateway.
The bridge renderer never imports inherited interface snippets. Host routing,
IPv6, router advertisements, and redirects are disabled. The live installer must
also retain its kernel-level IPv6 disablement.

`render_host(plan, resolved_ports, management_only=False)` returns only explicit
owned local files. `safe_management_files(plan, resolved_ports)` returns the
first-install fallback: static numeric management access, no default route, and
every other bridge inactive. Both profiles automatically start only loopback and
management. `resolve_ports` matches permanent MAC, PCI function, and driver;
`collect_ports(root, runner)` observes these through PCI sysfs and ethtool. Saved
interface names are not a substitute for fresh matching. Unknown replacements
or remapping require local repair.

The installer verifies staged software on every boot, restores pending local
files before networking, and loads the independent nftables guard before allowing
SSH or Proxmox management services to start. This early stage does not access
`/etc/pve`. Management is available without DNS, Internet, or the router VM.

The nftables guard applies to host input/output, not bridged guest forwarding.
Host input rejects other ingress interfaces before accepting established traffic;
new management access is limited to the declared subnet, host address, SSH and
Proxmox HTTPS. Host output uses only `vmbr0`; DNS/time and the restricted SSH channel target OPNsense; HTTP(S)
permits updates through its gateway. Its output hook runs after connection
tracking so replies to accepted management connections remain possible.

`rdc-host-policy.service` runs after PVE's cluster filesystem becomes available.
It reads and journals the standalone cluster/node firewall options, applies them
through `pvesh`, verifies the readback, compiles and checks the running legacy PVE
firewall, and verifies the complete live nftables guard. Only then does it bring
up WAN and internal bridges. It refuses foreign firewall rules and unexplained
options. It never writes pmxcfs files using POSIX rename/fsync. The independent
guard limits PVE's automatic management exceptions to the declared ingress and
subnet. Guest startup requires this policy unit.
The unit remains failed/inactive in management-only mode, deliberately preventing
guest startup while SSH and local recovery remain available.

## Change, confirm, and recovery

Use the installed `rdc-appliance network apply` action after the intended plan
has passed the installed release and ownership checks. The action journals the
exact previous bytes, original hashes, proposed bytes, a new transaction ID and
private challenge. It arms the independent rollback timer before publishing or
reloading any candidate files. The timeout is 120 monotonic seconds in the
current boot. Losing the terminal cannot cancel it. The timer service retries a
busy operation lock without extending the recorded deadline.

Open a **new SSH login to the numeric management address**, then use
`rdc-appliance network confirm` for that transaction and its challenge. Follow
the installed CLI's private challenge prompt; do not put the challenge in a
shared log or public status document. The implementation queries the current
logind session, requires a new remote SSH login from the management subnet, and
matches its leader's actual kernel socket to the host management IP and port 22.
It then audits live NIC identities, addresses, bridge membership, default route,
forwarding/IPv6 state, full nftables policy, PVE status, and both nftables and
legacy NAT rules. Missing or unfamiliar evidence cannot confirm the change.
Local terminal input or an arbitrary confirmation flag is not equivalent proof.

After a failed change, expiry restores the last confirmed bytes. On the first
change it restores the management-only fallback instead of an empty network.
Any reboot restores an unconfirmed transaction before networking, irrespective
of the old deadline. Foreign file edits stop recovery rather than being silently
adopted. Recovery can repeat after a partial file publication; mutations in an
incomplete PVE policy intent are not replayed. Readback that proves all desired
PVE options were already applied can reconcile that intent.

Management-only runtime recovery retains the strict nftables guard and stops
the legacy PVE firewall to remove exceptions compiled for a failed new management
subnet. It leaves WAN/guest links down. This is a recovery state; it is not a full
profile or a routing acceptance result. A subsequent full apply must pass the
post-PVE gate again. Confirmed configurations survive ordinary reboots.

Local `restore_known_good(root, runner, now=...)` requires a real local console
or serial terminal, never `/dev/pts/*` and never a caller-supplied boolean. Disk
repair from the installer is a separate, explicitly owned-target operation.

## Persistence and qualification

Private records reside under `/var/lib/rdc-appliance/private/network/`:

- `known-good.json`: schema, plan, resolved ports, profile, and base64 file bytes.
- `owned.json`: schema, profile, and each owned file's SHA-256 digest.
- `pending.json`: transaction phase, per-boot monotonic deadline, boot identity,
  private challenge, current/prior plans, exact before/desired bytes and original
  digests. Terminal phases are `confirmed` and `rolled-back`.
- `pve-policy/intent.json`: desired API options, original observations, and the
  `pending` or `complete` phase of PVE policy publication.

Directories are private and records are regular, single-link 0600 files. File
operations use bounded descriptor-relative reads, no-follow traversal, owned
ancestors, atomic publication and filesystem synchronization. Ordinary local
configuration files are 0644; generic helpers never adopt a symlink or hard link.
Production commands run only as Linux root against `/`. Tests require a runner
explicitly bound to their disposable temporary root; a normal real Runner cannot
be redirected at a test tree.

Remaining qualification must use the locked release on actual Linux/KVM and
hardware: nftables JSON serialization, PVE API/default-rule behavior, logind's
SSH leader socket ownership, ifupdown2 behavior, systemd ordering and restart
deadlines, power loss during every publication boundary, WAN DHCP/IPv6 leakage,
and packet tests addressed to the management IP while arriving from WAN. Unit
fixtures demonstrate rejection and control flow; they do not establish these
runtime results.

References: [nftables command and hook semantics](https://www.netfilter.org/projects/nftables/manpage.html)
and [Proxmox firewall documentation](https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html).

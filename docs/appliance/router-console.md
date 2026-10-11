# OPNsense console bootstrap and restricted management

This adapter targets the locked OPNsense **26.7** DVD and Proxmox local commands. Its configuration, interruption handling and channel restrictions have local tests. No physical installation, imported guest export, reboot persistence, DHCP transition or packet-isolation result has been captured yet. `configured` and `checks_passed` describe configuration readiness; `packet_tests: not-performed` remains explicit. The real guest qualification below is still required.

## Verified source contract

The renderer and helper were checked against these official **26.7** sources, not a guessed older OPNsense schema:

- [Configuration load/save API](https://github.com/opnsense/core/blob/26.7/src/etc/inc/config.inc): `load_config_from_file()` and `write_config()`.
- [Interface settings](https://github.com/opnsense/core/blob/26.7/src/opnsense/mvc/app/models/OPNsense/Interfaces/Settings.xml): IPv6 disable and checksum/TSO/LRO switches are under `OPNsense/Interfaces/settings`. The old `system/ipv6allow` field is insufficient.
- [Dnsmasq model](https://github.com/opnsense/core/blob/26.7/src/opnsense/mvc/app/models/OPNsense/Dnsmasq/Dnsmasq.xml) and [template](https://github.com/opnsense/core/blob/26.7/src/opnsense/service/templates/OPNsense/Dnsmasq/dnsmasq.conf): DHCP ranges are tagged by physical interface. The only range is reservation-only workload IPv4; management, infrastructure and relay explicitly disable DHCP. RA is off. Dnsmasq provides DNS on local gateways; NTP binds the same local zones.
- [SSH plugin](https://github.com/opnsense/core/blob/26.7/src/etc/inc/plugins.inc.d/openssh.inc), [account/key installation](https://github.com/opnsense/core/blob/26.7/src/etc/inc/auth.inc), and [web GUI listeners](https://github.com/opnsense/core/blob/26.7/src/etc/inc/plugins.inc.d/webgui.inc): SSH includes its configuration directory before generated defaults, authorized keys are base64 in the account record, and administration binds to LAN/loopback.
- [Firewall generation](https://github.com/opnsense/core/blob/26.7/src/etc/inc/filter.inc), [rule compatibility](https://github.com/opnsense/core/blob/26.7/src/etc/inc/filter.lib.inc), and [plugin dispatch](https://github.com/opnsense/core/blob/26.7/src/etc/inc/plugins.inc): the adapter uses the supported legacy filter/NAT input. The generation plugin executes before user rules.
- [Address-change handling](https://github.com/opnsense/core/blob/26.7/src/etc/rc.newwanip) reloads the firewall before its `newwanip` plugin event. An after-event hook alone therefore cannot provide the required protection. This adapter instead registers early blocking rules during firewall generation and invalidates previous PF states on revoked permission.
- [Filter rule rendering](https://github.com/opnsense/core/blob/26.7/src/opnsense/mvc/app/library/OPNsense/Firewall/FilterRule.php) emits descriptions as comments. The guard therefore uses explicit per-interface labels bound to the plan and boot, and verifies those labels in loaded `pfctl -sr` output.
- [FreeBSD pfctl(8)](https://man.freebsd.org/cgi/man.cgi?query=pfctl&sektion=8&format=html) documents source/destination `-k` pairs and `-M` for paired states. Cleanup targets guest CIDRs and host-forwarding destinations. IPv4 destinations are partitioned around the router management address, preserving host-to-router SSH; there is no global state flush.

The Proxmox [QM command source](https://github.com/proxmox/qemu-server/blob/master/src/PVE/CLI/qm.pm) confirms verbose status contains nested telemetry; only top-level PID/status scalars form process evidence. Storage checks use the [local storage API](https://github.com/proxmox/pve-storage/blob/master/src/PVE/API2/Storage/Status.pm). Actual installed package versions and output remain part of lab qualification.

## Install with all router links disconnected

1. Use the local appliance router installation flow to allocate the owned VM and attach the verified DVD. The fixed virtual MACs, bridges, disk and ownership receipt are checked before every mutation. Every virtual NIC starts disconnected; `onboot=0` prevents Proxmox startup bypassing the gate. Use the PVE console through the numeric host management address.
2. Complete the DVD installer onto the owned virtual disk using GPT/UFS if automatic cloned-router recovery is required. Shut down through the guest console. The disk-boot action refuses a running installer, detaches the DVD, sets disk-only boot and starts a new process. A running process reports configuration only; it does not prove installation.
3. In the **installed** guest console record `ifconfig -a` and match each MAC to the site plan. Management is LAN, WAN is WAN, infrastructure/workload/optional relay are OPT1/OPT2/OPT3. Supply that observed mapping to the renderer; do not infer `vtnet` numbering from enumeration order.
4. Create a unique root password hash with bcrypt cost at least 12 and a unique host management Ed25519 key. Keep its private key on the Proxmox host only. The private credentials JSON has exactly `root_password_hash`, `management_public_key` (algorithm and base64 key only), and `interface_map` (MAC to observed device). Plaintext passwords, default hashes, duplicate devices and extra credential fields are refused. Credentials are never added to the public site plan.
5. Generate the private bootstrap bundle through `router bootstrap-files`. Its files must remain owned by root with mode 0600 in a 0700 directory. It contains `bootstrap.xml`, `transit.xml`, `manifest.json`, `helper.php`, `rdcappliance.inc`, and `00-rdc-appliance.conf`. A config export contains authentication material; keep it private too.

Transfer the bundle using the isolated local console or local removable media. This is an explicit operator step; the adapter does not open an unrestricted network bootstrap account. On the guest create `/conf/rdc-appliance` and `/conf/rdc-appliance/operations` as root:wheel, mode 0700. Install the first four bundle files in `/conf/rdc-appliance/`, each root:wheel 0600. Install `rdcappliance.inc` into `/usr/local/etc/inc/plugins.inc.d/` and `00-rdc-appliance.conf` into `/usr/local/etc/ssh/sshd_config.d/`, also root:wheel 0600. The plugin is a `require_once` loader, avoiding duplicate PHP definitions when policy application invokes firewall generation.

From the disconnected guest root console, import the bootstrap file through the release's configuration API and perform its full service reload:

```sh
/usr/local/bin/php -r 'require_once("config.inc"); $config=load_config_from_file("/conf/rdc-appliance/bootstrap.xml"); if (!is_array($config) || write_config("Appliance console bootstrap", true) === -1) { exit(1); }'
/usr/local/etc/rc.reload_all
```

Do not connect any virtual NIC if either command fails. Inspect the effective config and local service listeners after the reload. Leave management anti-lockout enabled. Verify the global IPv6 disable, management DHCP/RA absence, unique credentials, restricted key and management-only administrative listeners in the console. No unrestricted temporary SSH key is needed; if one was used during manual repair, remove it before attesting the console checklist.

## Pin the channel before its first connection

Read the guest's Ed25519 host public key and fingerprint **in its local console**:

```sh
cat /conf/sshd/ssh_host_ed25519_key.pub
ssh-keygen -l -E sha256 -f /conf/sshd/ssh_host_ed25519_key.pub
```

Compare the complete public key/fingerprint with the record installed on the Proxmox host. Do not use `ssh-keyscan` as identity proof and do not accept a first-contact prompt. On the host, the known-hosts file is exactly one line, containing the router's management IPv4 address, a space, the `ssh-ed25519` public key without its trailing comment, and a newline. The private key and known-hosts file must be regular, single-link, root-owned 0600 files; their paths must be absolute with no symlink component.

`/etc/rdc-appliance/router-channel.json` is a private record with exactly these fields:

```json
{
  "schema": 1,
  "plan_id": "<canonical site-plan identity>",
  "address": "<router management gateway address>",
  "private_key": "/etc/rdc-appliance/router-management.key",
  "known_hosts": "/etc/rdc-appliance/router-known-hosts",
  "host_public_key": "ssh-ed25519 <console-compared host key>",
  "helper_sha256": "<SHA256 of the installed bundle helper.php>"
}
```

Use the appliance private record writer or root-only equivalent, mode 0600, with a private 0700 parent. The host refuses drift from the current plan, management address, helper source digest or known-hosts line. A plan revision requires reviewing and rebinding this private channel record; VM allocation ownership itself remains stable across a plan-only revision.

Run the management-connect action at the local console. It asks for all nine console checks and the exact text `CONNECT MANAGEMENT <VMID>`. That creates a short-lived in-memory attestation bound to the current QEMU process and config. A JSON file cannot replace this attestation. Only the management NIC is then connected. Verify the restricted channel before proceeding.

The operational key has a `from=` host-management source restriction, `restrict`, and a fixed command. Server policy separately disables passwords, keyboard-interactive authentication, PTY, TCP/Unix-socket forwarding, agent forwarding, X11, tunnels and user RC files. The host uses explicit SSH options, no user configuration or agent, and the pinned Ed25519 host key. Requests are JSON for only `inspect`, `apply-policy`, or `export-config`; arbitrary SSH commands and paths are refused. The helper accepts the fixed original command `rdc-router` only.

## WAN and transit are separate gates

`router enable-wan` rereads the owned running VM and fresh config/runtime over pinned SSH, regardless of any saved status input. It requires installed-disk root evidence, exact OS version, MAC mapping, active configuration digest, restricted SSH, administrative listeners, DHCP/RA/IPv6 checks, installed helper/plugin digests and a currently blocking bootstrap guard. It journals the WAN link change before dispatch.

WAN bootstrap permits the router to obtain an upstream address while guest forwarding remains blocked. The transit action then observes the actual WAN subnet and default route, requires a declared upstream subnet with no site/overlay overlap, applies the preinstalled transit policy with compare-and-swap digest and boot identity, and rechecks the resulting active rules. Only after confirmed success does it journal and connect infrastructure/workload/relay router NICs. Transit permits HTTPS from infrastructure/workload and HTTP/HTTPS updates from the declared host management IP, with explicit cross-zone blocks; DNS and NTP remain local gateway services. NAT is explicit for infrastructure/workload plus that single host IP `/32`. Relay has no automatic outbound NAT or broad Internet allowance.

A router-local permit binds the plan, boot and observed upstream subnet/gateway. Every firewall generation validates it. On revocation the helper disables IPv4 forwarding, administratively brings down the OPT guest interfaces, and selectively removes guest/host forwarding states before new rules are generated. Management LAN and WAN remain up for local access and DHCP lease stability. The guard blocks both guest and host transit while retaining router-local administration, DNS/time and workload DHCP exceptions.

The generation hook cannot assume its rules have loaded: OPNsense installs them later. Post-load `local`/`newwanip` hooks, and the explicit policy action, read the actual per-interface guard labels before proceeding. They remove the targeted states again, restore guest interfaces, recheck the guard, and only then restore IPv4 forwarding. A failed or uncertain load leaves transport withdrawn. Policy activation first establishes this deny guard and then validates the current upstream before installing transit permission. A reboot invalidates the old permit. The address-assignment-to-hook interval, kernel state behavior, positive controls and uninterrupted management SSH must still be exercised with real traffic in the guest lab; local tests do not constitute packet qualification.

On host cold start, the owned stopped router has WAN and internal links durably disconnected before QEMU starts; previously confirmed management remains connected. This restores local management without an upstream dependency. A fresh bootstrap/WAN/transit check is required to restore forwarding. Calling startup for an already running router never changes its links. An uncertain disconnection keeps the VM stopped until explicit reconciliation observes the intended state.

Policy mutations record durable private pending intent on host and guest before changing anything. A timeout is never automatically replayed. VM creation/start uncertainty has an explicit read-only `router reconcile` action: it publishes success only if the current resource exactly matches the recorded desired result. Configuration mismatch or missing resources remain blocked.

`router reconcile-policy` uses fresh pinned-channel observations plus the guest's completed operation receipt to settle a host-side lost response. The operation ID, plan, stage, boot and active config digest must match; a guest-side pending record remains blocked for console inspection. `router reconcile-link` observes the exact saved PVE config target and its current guest gate before publishing private receipts. It does not issue a link command. Neither action changes guest policy or activates additional interfaces. Do not delete pending records merely to retry.

## Qualification still to run

Capture a sanitized **actual imported export** from 26.7; no synthetic XML fixture is called a guest export. Prove cold disk boot after removing the DVD/USB, correct interface MAC mapping, and persistence of the helper, plugin and SSH include after reload and reboot. Test wrong host keys, arbitrary commands, PTY/forwarding requests and unknown-response recovery.

Capture the physical management wire throughout installation: zero router DHCP offers and RA before and after management activation. Probe WAN and every guest segment for administrative listeners with working positive controls. Test DHCP and static upstream, RFC1918 upstream, missing upstream, conflicting first lease, conflicting renewal while traffic/state already exists, router reboot and lost DNS/time. Confirm cross-zone denial, HTTPS/NAT behavior, local DNS/time availability and numeric-IP host management during router failure. Keep capabilities unverified until those real observations pass.

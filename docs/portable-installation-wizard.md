# Guided portable guest installation

This development iteration adds a resumable **Proxmox guest-installation wizard**. It prepares verified installation media, uploads it, starts each isolated installer and guides an operator through installing OPNsense and Ubuntu. It is a guided console workflow, not unattended installation.

The phase ends with operator-confirmed OS installation and console login on disk-only VMs. OPNsense routing, Unbound, NGINX, Synapse and Nextcloud configuration remain the subsequent phase. Do not enable the guest network links or describe this phase alone as an operational crisis datacenter.

## Before starting

- Prepare an independently administered Proxmox VE 9.x lab host and the existing bridges/storage described in [provisioning prerequisites](proxmox-provisioning.md). Live compatibility is not yet accepted.
- Have console access to Proxmox that does not depend on the OPNsense VM.
- Prepare the private API-token file and trusted Proxmox CA certificate. Never put token values in the site plan, command line or repository.
- Have a separate ISO-capable storage location, usually `local`, with space for the ISO files and upload temporary copies. VM disks still use the site's `lvmthin` or `zfspool` storage.
- Allow at least 10 GiB of free space on the preparation computer for media and temporary files. Guest disks, Proxmox temporary upload storage and user data need their own space.
- Use a reviewed development checkout. The earlier published 0.3.0-alpha.1 source archive does not contain this wizard.

Prepare dependencies using the repository's normal instructions, then start:

```sh
./rdc start --platform proxmox --output-dir /absolute/private/path/my-portable-site
```

The directory must be new or empty. The wizard asks for the site/recovery names, Proxmox endpoint/node/storage, WAN bridge, reserved network range, first VM ID and service domain. It previews resource defaults and saves `site.json` privately after you choose SAVE. Verify resources and all existing bridge names before allocation; the guided defaults do not inspect or configure your hardware.

Resume from the same record:

```sh
./rdc start --platform proxmox --resume /absolute/private/path/my-portable-site/site.json
```

No secrets are saved by answering these planning questions. Credential *file paths* are requested only when choosing a remote operation and retained only for that wizard session. Guest administrator passwords are set inside the guest console.

## Work through the menu

1. **Preview.** Review VMs, subnets, DNS intent and startup groups. Edit the private `site.json` before allocation if defaults do not suit the host. Once any remote progress exists, changing the plan invalidates its ownership binding; migration is a separate operation.
2. **Host check.** Check API access, candidate version, visible VM IDs, bridges and available resources. A read-only check cannot prove every subsequent mutation permission.
3. **Allocate shells.** Explicitly choose RUN. The six VMs are created with blank disks, autostart disabled and every NIC disconnected. It never changes host bridge configuration or overwrites existing guests. Complete this for all six VMs before starting their installers; the shell allocator intentionally refuses later modified/running guests.
4. **Fetch media.** Fetch OPNsense, then Ubuntu. Downloads occur during preparation while connected. Media stays in the workspace's `media` directory; the wizard never executes it on the preparation computer.
5. **Upload media.** Upload each kind once to the chosen ISO storage. Upload bytes are checksum-checked by Proxmox before use. Every upload uses a unique filename and retains its task receipt. Credentials never accompany vendor download requests.
6. **Guest installation.** Select edge, dns, nginx, chat, files or partner. Follow the actions below, one guest at a time. The same Ubuntu ISO is reused for all five Linux guests.
7. **Instructions.** Show the console procedure again. Quit at any point and resume later; progress is retained.

### Actions for each guest

| Action | What happens | What it does not prove |
|---|---|---|
| `attach` | Checks the owned stopped guest, attaches its verified uploaded ISO and selects installer-first boot | That an OS is installed |
| `start` | Records intent and starts the installer once | That the installer completed |
| Console installation | Operator installs onto the one planned disk and sets private credentials | Any service/network readiness |
| `finish` | Operator attests installation and credential setup with guest shut down; wizard detaches ISO and selects disk-only boot | Automatic OS identity verification |
| `boot` | Starts the disk-only VM and observes Proxmox reporting it running | That firmware actually booted the OS or a login succeeded |
| `confirm-login` | Operator records successful console login and correct installed OS/version while VM is running | An automated in-guest health probe |
| `status` | Rechecks ownership, expected devices, disconnected NICs and current VM power state | Application readiness |

The wizard shows last-recorded progress separately from live checks. A `guest-installed-attested` record means a person verified the guest. It is deliberately different from an automated OS probe or completed application deployment.

## Console procedure

Open the selected VM's console in the existing Proxmox web interface. Check its VM ID against the plan before any installer disk selection. There should be only the planned data disk and installation CD; unexpected disks are a reason to stop.

For **OPNsense**, use the vendor installation environment's `installer` account (initial password `opnsense`), select the planned disk, follow the installer and set a private root password. Do not leave default credentials in an installed guest. If interface assignment is requested, use explicit device names rather than automatic link detection: links are intentionally disconnected. The edge's NIC order is WAN, management, staff, frontend, applications and partner. Actual routing/IP/firewall setup belongs to the subsequent network phase. Shut down the guest after installation.

For **Ubuntu**, choose the server installation, continue without network configuration and skip online installer/mirror update steps. Install to the single planned disk and create an individual administrator account. Do not add extra disks, NICs or boot devices. Shut down after installation. Online package/security updates and service software will be part of controlled preparation before production use; base media is not a claim of a fully patched appliance.

Use `finish`, then `boot`. In the console, verify the installed OS and version and log in successfully using the new private account. Use `confirm-login` only after that check. Repeat for all six guests. Keep NICs disconnected; this phase intentionally does not enable OPNsense's default LAN/WAN policy on the institutional network.

## Verified media boundary

The checked-in [catalogue](../scripts/guest_media.json) pins Ubuntu 24.04.5 server amd64 and OPNsense 26.7 DVD amd64 to exact SHA256 values and download sizes obtained from the official HTTPS release metadata. URLs are not silently updated to “latest.” Upstream metadata references: [Ubuntu checksums](https://releases.ubuntu.com/24.04/SHA256SUMS), [OPNsense checksums](https://pkg.opnsense.org/releases/26.7/OPNsense-26.7-checksums-amd64.sha256).

This implementation verifies against repository-pinned checksums; it does **not** claim to validate vendor GPG/RSA signatures automatically. Trust begins with the reviewed project revision and its catalogue. Updating pins requires review. Hashes verify matching bytes, not absence of vulnerabilities or guest boot compatibility.

OPNsense's compressed image is checked before bounded decompression. Prepared ISO bytes are checked against the verified source again before upload. Ubuntu uses the pinned ISO directly. Proxmox receives the expected ISO checksum and validates the upload. Later attachment checks the completed task receipt and volume size, not a fresh remote cryptographic hash; the trusted Proxmox administrator must not modify staged ISO files out of band. Media files and receipts are kept private and symlinks are rejected.

## Resume and failures

- A completed matching media download is rechecked and reused. Corrupt or incomplete media is refused; never bypass the checksum.
- A saved upload task is polled rather than re-uploaded. If the HTTP response was lost before the task ID was received, inspect Proxmox tasks. To explicitly abandon only the local unresolved upload record, use `upload-abandon` below. Remote files remain for manual review; a new upload receives a new unique name.
- A lost VM configuration response can be reconciled from the expected remote marker and devices. A changed configuration or another owner's VM is refused.
- An uncertain installer start is never blindly replayed: the installer may already have written the disk and shut down. Inspect the console/task history. If installation completed, use `finish`; if it never started, start it manually in the Proxmox console and continue. Do not rerun the installer over an installed disk.
- The tool never deletes disks, resets guest credentials, enables NICs or rolls back installed data. Existing VMs and unrelated workspace files are not adopted.
- Keep the workspace and receipts with private operating records. Losing them requires a deliberate recovery/adoption procedure; reconstructing trust from filenames alone is not supported.

## Matching commands

All commands take the same `site.json`. `--state-dir` and `--media-dir` optionally override the default sibling `guest-state` and `media` directories; retain those choices consistently.

```sh
./rdc portable media-fetch /private/site/site.json --kind opnsense
./rdc portable media-fetch /private/site/site.json --kind ubuntu
./rdc portable media-upload /private/site/site.json --kind opnsense --iso-storage local --token-file /private/auth.json --ca-file /private/pve-ca.pem
./rdc portable guest-attach /private/site/site.json --role edge --token-file /private/auth.json --ca-file /private/pve-ca.pem
./rdc portable guest-start /private/site/site.json --role edge --token-file /private/auth.json --ca-file /private/pve-ca.pem
# Complete the console installation, set private credentials and shut down.
./rdc portable guest-finish /private/site/site.json --role edge --operator "Your Name" --token-file /private/auth.json --ca-file /private/pve-ca.pem
./rdc portable guest-boot /private/site/site.json --role edge --token-file /private/auth.json --ca-file /private/pve-ca.pem
# Verify the installed OS/version and successful console login.
./rdc portable guest-confirm-login /private/site/site.json --role edge --operator "Your Name" --token-file /private/auth.json --ca-file /private/pve-ca.pem
./rdc portable guest-status /private/site/site.json --role edge --token-file /private/auth.json --ca-file /private/pve-ca.pem
# Only after inspecting an unresolved upload; does not delete anything remotely:
./rdc portable upload-abandon /private/site/site.json --kind opnsense
```

For Linux guests upload Ubuntu and select the corresponding role. Omit `--ca-file` only when system trust already validates Proxmox. Add `--json` for machine-readable output.

API permissions extend shell allocation with `Datastore.AllocateTemplate` for upload, VM CD-ROM/configuration permissions for the selected guest properties and `VM.PowerMgmt` for start. Check the exact [Proxmox API permission definitions](https://pve.proxmox.com/pve-docs/api-viewer/) for the deployed version. The wizard never grants itself permissions or changes access-control policy.

## Acceptance status

Automated coverage includes pinned-media integrity, decompression bounds, private state handling, multipart upload checksums, uncertain responses, phase restrictions, foreign/drifted configurations, disconnected NICs and wizard preparation/resume. Hosted media verification downloads real vendor files without executing them. These do not replace a live Proxmox installation exercise.

Live Proxmox upload/configuration/start and both console installers still require a disposable host. No such host is connected to this development session. Physical hardware, local service operation and offline recovery remain separate acceptance gates. This iteration is ready for code review and lab use, not an operational crisis deployment.

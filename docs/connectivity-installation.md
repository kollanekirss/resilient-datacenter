# Separate connectivity installer

From this development checkout:

```sh
./rdc connectivity install --output-dir /absolute/private/path/my-connectivity
```

**Available now:** scope explanation, topology planning, private save/resume, read-only Proxmox inspection and explicitly confirmed allocation of stopped connectivity VM shells, followed by guided isolated OPNsense console installation. **Not available yet:** Linux guest installation, OPNsense network activation, field enrollment or partner-network activation through this new wizard. It does not produce a working datacenter yet.

Prepare the repository Python environment first. The opening screen appears before credentials or remote access. Starting the wizard makes no remote connection. Planning can run on a preparation computer, including macOS; guest/server installation commands are never executed there by this workflow. Only the explicitly confirmed OPNsense `prepare` checkpoint downloads installation media.

## Plan the network

Choose `start`, `resume` or `exit`. Name the institution/site, Proxmox HTTPS endpoint and node/storage, four distinct bridge names and a reserved RFC1918 IPv4 /16. The block is a planning reservation; this adapter does not assign guest addresses or prove it is free of conflicts with existing networks.

Choose each network's coordinator and relay placement:

- `local`: allocate a Linux VM shell on this Proxmox host.
- `external`: later deploy the role on another independently administered server; no local shell is allocated for it.
- `existing`: later connect to an already operated service; no local shell is allocated for it.

Provide distinct credential-free HTTPS hostnames and declare domestic/foreign placement. Domestic location does not prove domestic routing or independent power. The profile currently selects one coordinator and relay per network; it does not configure relay redundancy or controller continuity. Static WireGuard is future work and is not an executable option.

Proxmox accepts HTTPS on 443 or 8006; coordinator/relay URLs use 443. Prepare publicly trusted endpoint certificates and domains before crisis use. Planning does not verify service certificates or ownership. Creating disconnected shells does not expose those endpoints: public address assignment, port conflicts, forwarding, bootstrap DNS and access policy must be resolved before network activation.

During questions, use `:back` to correct and clear later answers, `:save` to save a draft, or `:cancel` to retain prior saved state. After the full preview, type `SAVE`. A complete saved plan opens the connectivity operations menu; a draft stops with its remaining work. No service installer is launched.

## Resume and operation menu

```sh
./rdc connectivity install --resume /absolute/private/path/my-connectivity/connectivity.json
```

Choose `resume`. Complete plans go directly to the operation menu; drafts return to the questions. The saved plan is intent, not a live deployment report. Older schema-v1 planning snapshots remain readable; runtime observations are separate.

The operation menu offers:

| Choice | Effect |
|---|---|
| `preview` | Show local VM roles, IDs, resources, bridges and target; no API connection |
| `settings` | Preview another first VM ID or management address; no API connection or immediate save |
| `check` | After typing `CHECK`, read host/task state and save the result; no remote mutation |
| `allocate` | After typing `ALLOCATE`, recheck prerequisites and create missing owned VM shells |
| `opnsense` | Open the separate guided edge installation checkpoints; no action occurs just by opening it |
| `exit` or blank | Retain private records and exit; no service installer follows |

Initially select the first VM ID (default 300) and the existing independent Proxmox management IPv4 address. The exact VM preview appears before confirmation and credential prompts. Settings changes can be confirmed while there is no recorded creation intent or observed owned shell. Once allocation has begun or an owned shell was observed, settings are bound to those resources; the tool does not migrate, rename or delete them.

## What gets allocated

| Local role | CPU | RAM | Blank disk | Network attachment intent |
|---|---:|---:|---:|---|
| OPNsense | 2 | 3 GiB | 20 GiB | WAN, management, services, partner transit |
| Naming/time | 1 | 1 GiB | 16 GiB | Services bridge |
| Partner gateway | 1 | 1 GiB | 16 GiB | Partner transit bridge |
| Disposable connectivity test target | 1 | 512 MiB | 8 GiB | Services bridge |
| Each coordinator/relay selected as local | 1 | 1 GiB | 16 GiB | Services bridge |

This gives four to eight VM shells, rather than the older six application VMs. After shell allocation, all guests are **stopped, autostart-disabled and have every virtual NIC disconnected**. Shell allocation performs no applications, backups, ISO attachments, public port forwarding or host-network changes. The subsequent OPNsense checkpoint explicitly attaches installation media and starts only that VM. Resource values are initial lab sizing, not production capacity acceptance. Naming/time and coordinator/relay roles on the services bridge still need guest firewall and exposure policy before activation; VM separation alone is not isolation.

## Guided OPNsense installation

After shell allocation choose `opnsense`. The submenu shows the exact host, node and VM ID, fixed media version, download size, private cache and next checkpoint. Opening the submenu does not fetch software or contact Proxmox. Every action has its own preview and uppercase confirmation; cancellation returns without executing it.

| Checkpoint | What it does and where it stops |
|---|---|
| `prepare` | Downloads/decompresses the pinned OPNsense DVD image on the preparation computer; verifies its size and SHA-256. No API credentials needed. |
| `upload` | Uploads to selected existing ISO-capable storage (default `local`), using a unique filename and server-side SHA-256 verification; retains the successful task receipt. |
| `attach` | Checks active owned VM configuration, rejects pending changes and checks disconnected NICs, then attaches the verified ISO with installer-first boot. VM remains stopped. |
| `start` | Starts the isolated installer VM and waits for an observed running state. **The operator still performs OS installation in Proxmox Console.** |
| `finish` | Requires operator confirmation that installation and a new private root password are complete, and observes that the guest was shut down. Removes the ISO and selects disk-only boot. |
| `boot` | Starts and observes disk-only VM execution. This alone does not verify OS identity or login. |
| `confirm` | Records the operator's name, observed OPNsense version and successful console login, after checking a running disk-only VM. This is explicitly **operator-attested**, not an automated OS probe. |
| `status` | Reads current configuration/power state; retains pending requests and separates current observations from historical checkpoints. |
| `exit` | Returns to the main connectivity menu with progress retained. |

All four OPNsense NICs remain disconnected and autostart remains disabled throughout. No public management interface is activated, no field device is asked to trust a self-signed certificate, and no certificates are issued here. The future activation adapter must prepare publicly trusted endpoints and verified policy first. Linux shells and application services remain untouched.

Console procedure: open the selected VM's Proxmox console; start the vendor installer using `installer` / `opnsense`; install to that VM's sole 20 GiB disk; set a new private root password; then shut down from inside the guest. Never paste the root password into this wizard. After `finish` and `boot`, check the installed version and console login before choosing `confirm`. Follow the [vendor installation procedure](https://docs.opnsense.org/manual/install.html); the wizard does not automate console keystrokes or infer success from the installer starting.

The current pin is OPNsense 26.7 DVD amd64, 494,298,945 compressed bytes, SHA-256 `95cafedda6d5b22ce832e249dc2309110fbee19f813ad78cf28bb3d387186bfb`. On 2026-09-27 it matched the [vendor checksum](https://pkg.opnsense.org/releases/26.7/OPNsense-26.7-checksums-amd64.sha256) and [separate vendor release announcement](https://github.com/opnsense/changelog/blob/master/community/26.7/26.7). This adapter uses that repository-pinned checksum; it does not implement the vendor's separate OpenSSL signature procedure or automatically select newer releases. Patch/update acceptance before production use remains outstanding.

In addition to shell privileges, review `VM.PowerMgmt` on the edge VM, `VM.Config.CDROM` and `VM.Config.Options` for attachment/boot changes, and `Datastore.Audit` plus `Datastore.AllocateTemplate` on ISO storage. VM-image storage such as `local-lvm` normally does not hold ISO files. The API token is not a browser console login: the operator also needs independent Proxmox console access with suitable permissions.

The private `provisioning/edge.json` journal is bound to the allocation settings and media pin. `provisioning/media/` holds the local verified image. The allocation journal records that guest installation has begun; a missing guest journal cannot silently reset the workflow. From then on, use the OPNsense checkpoints instead of `check`/`allocate`, which manage blank shells only. Retain the entire workspace together.

Uploads, configuration changes and starts record intent before submission and retain returned task IDs. Unknown uploads are blocked even if a similarly sized ISO exists. Known tasks must succeed before progress can advance. An unknown attachment/removal/start can reconcile only if the exact intended owned configuration/power state is observed; otherwise inspect the task/console manually. No automatic stop, reinstall, rollback or remote media deletion is performed. Uploaded media is trusted through the successful checksum-checked task and matching volume/size; it is not cryptographically read back on each later check. Proxmox administration/storage must remain trusted.

## Host prerequisites and permissions

The adapter targets Proxmox VE 9.x and active `lvmthin` or `zfspool` VM-image storage. It checks free capacity for missing disks plus 10 GiB and RAM for all planned guests plus 2 GiB. These checks do not reserve resources against concurrent administration.

All four selected bridges must already be active Linux bridges. A clean Proxmox installation commonly needs additional bridge preparation; **this adapter does not create or reconfigure those bridges yet**. Missing/invisible bridges stop allocation and point to `SDN.Use` permissions before suggesting host changes. A planned WAN bridge with a host address or gateway is refused. The declared management address must be observed on the selected management bridge. That observation does not prove an independent console or physical access path: test that separately before proceeding.

Use a dedicated privilege-separated API token, with effective grants on both user and token. The known working shell-allocation privilege set from the earlier nested Proxmox lab is not a proven minimum:

| Scope | Privileges to review |
|---|---|
| Intended node | `Sys.Audit` |
| VM disk storage | `Datastore.Audit`, `Datastore.AllocateSpace` |
| Selected VM IDs | `VM.Audit`, `VM.Allocate`, `VM.Config.Disk`, `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.Options`, `VM.Config.HWType`, `VM.Config.CDROM` |
| Selected bridges under `/sdn/zones/localnetwork` | `SDN.Use` |

Scope these grants to the intended resources; do not grant administrator-wide rights. `VM.Allocate` also permits deletion in Proxmox even though this tool never deletes VMs. A read-only check cannot prove all subsequent create permissions. The API may hide occupied VM IDs; the server must reject a conflicting create rather than overwrite it.

Keep the token outside the repository, in an owned regular file with mode 0600:

```json
{"token_id":"operator@pve!connectivity","token_secret":"REPLACE-WITH-YOUR-TOKEN-SECRET"}
```

Only the path is requested, after an operation is selected and confirmed. TLS hostname and chain validation remain enabled. Blank CA-file input uses system trust; an explicitly supplied management CA must be obtained and verified independently. There is no insecure mode. HTTP errors show status and recognized missing privileges without printing raw responses or credentials. The token and its path are not stored in the connectivity records.

## Checkpoints, interruptions and private records

After a successful check or allocation, the wizard stops at the menu and reports built resources, observations, remaining unavailable functions and the next step. Shell allocation completion explicitly directs the operator to the still-unimplemented guest OS/network phase. It never calls shell creation an operational network.

The workspace uses mode 0700 and records mode 0600:

- `connectivity.json`: schema-v1 planning intent, unchanged by host operations.
- `provisioning/settings.json`: selected IDs/resources and management address, bound to the plan revision.
- `provisioning/journal.json`: per-VM intent, returned task IDs, observed shell state and timestamped last-operation outcome.

History is displayed as historical evidence, not current health. Each allocation run performs fresh checks. A workspace lock prevents simultaneous operations and conflicting saves. Keep this complete directory private and out of Git. Do not delete or edit journals to force a retry, and do not assume copying the plan transfers ownership of a running installation.

Before each POST the tool durably records intent. If a task ID was returned, it is retained and can be polled on resume. If the response was lost but the complete matching stopped shell is visible, a subsequent explicitly selected allocation can reconcile it. If a previous attempt cannot be resolved or a recorded shell disappears, **all new creation stops**. Inspect Proxmox tasks/storage and the private records; there is no automatic retry, cleanup, adoption or rollback. Missing or inconsistent journals are refused.

Interrupted local settings/journal writes may require manual record inspection; the tool fails closed rather than guessing which state is authoritative. Changes to the institution topology after provisioning records exist require a separately reviewed migration or a new planning workspace. A new workspace does not authorize modification of old resources.

Exit code 0 means the workflow saved planning/progress and exited; it is not a deployment-health result. Checkpoint failures remain visible and recorded. Stopping before saving a plan returns 4; a recognized state/precondition failure that exits the workflow returns 3; unhandled local resource failures use the existing failure code 1.

## Acceptance boundary and next work

Tests simulate Proxmox responses, ownership, capacity, permission errors, partial allocation, lost responses, stale plans and resume/cancellation. They are not a new live-host result. The earlier lab report verified the old allocator on nested VE 9.2.20; the new variable-role allocator still requires its own lab acceptance. No lab host was accessed during this implementation.

Next: Linux guest installation and safe OPNsense/bootstrap network configuration, followed by Headscale/DERP activation, real field-device enrollment, partner exchange and domestic outage exercises. Services remain separately initiated and backups remain outside this milestone. See the [design](superpowers/specs/2026-09-27-connectivity-foundation-design.md).

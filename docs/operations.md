# Guided operations

The `rdc` command is the common interface to this experimental networking pilot. It prepares configurations, checks/deploys the offsite controller and relay, and installs/enrolls local Ubuntu nodes. The development source also includes experimental Matrix/Element, encrypted backups, guarded recovery and certificate workflows. Nextcloud, regional gateways and managed application upgrades remain in development. See [Matrix services](matrix-services.md), [backups](backups.md) and [managed infrastructure certificates](managed-certificates.md). These additions are not in the older 0.2.0-alpha.1 download.

Disposable Ubuntu tests exercise actual service startup and recovery; they do not establish home NAT traversal, physical site separation or institutional acceptance. Continue to treat this as a disposable pilot until the [live acceptance checklist](local-install-acceptance.md) has been exercised.

## Get started

Use Python 3.11+ on the operator computer. Clone the project, then prepare its own Python environment:

```sh
git clone https://github.com/kollanekirss/resilient-datacenter.git
cd resilient-datacenter
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./rdc
```

In a terminal, the last command opens a numbered menu. In a noninteractive session it prints help. The launcher never installs dependencies automatically. Use the real project path rather than a symlink to the launcher. Commands also work when invoked by their absolute path from another directory.

The menu uses the same operations as the commands below. Setup does not automatically install or enroll anything. Mac computers can prepare configuration and run controller diagnostics; installing a node requires Ubuntu 24.04 amd64 with systemd.

## Prepare a network or a joining node

```sh
./rdc setup
./rdc setup --resume inventories/lab/setup/draft.yml
./rdc setup --output-dir /absolute/private/setup
```

Choose independent for your own offsite controller/relay, or join for a local node requesting admission to an existing controller. The wizard supports `:back`, `:save` and `:cancel`. A saved draft is not a deployment input. Supply public DNS and certificates for controller/relay and the pinned relay artifact as described in the [setup guide](guided-setup.md).

Existing files require an explicit replacement decision. A node manifest is a configuration request, not permission to join a network; confirm its controller through a trusted channel and obtain approval.

## Offsite infrastructure: operator computer

```sh
./rdc infrastructure check inventories/lab/setup/infrastructure.yml
./rdc infrastructure apply inventories/lab/setup/infrastructure.yml
```

Check validates local inputs and inspects the controller/relay through read-only SSH. It uses existing SSH credentials and noninteractive remote privilege access; it cannot ask for passwords. If access is unavailable, resolve it through independent administration before rerunning. No synthetic example address is a valid target for this command.

Apply shows the reviewed targets, asks for confirmation and deploys through the guarded Ansible entry point. A private snapshot preserves the reviewed inventory even if the original file changes. If remote sudo requires a password, explicitly use:

```sh
./rdc infrastructure apply inventories/lab/setup/infrastructure.yml --ask-become-pass
```

Arbitrary Ansible arguments, partial target selection and user-supplied execution overrides are not supported. Only controller and relay are managed; planned local nodes are never SSH targets.

## Approve a device-to-service connection

Run this on the operator computer with the current infrastructure inventory. Both endpoints must be declared enrollment nodes with distinct tags:

```sh
./rdc access setup inventories/lab/setup/infrastructure.yml --output-file inventories/lab/setup/infrastructure-access.json
./rdc infrastructure check inventories/lab/setup/infrastructure-access.json
./rdc infrastructure apply inventories/lab/setup/infrastructure-access.json
```

The wizard asks for the connecting node, destination node, service and whether to allow or remove access. `https` allows TCP 443; `backup` allows TCP 2222. The first command only writes a private proposed inventory. Check and apply use the existing reviewed deployment process. Keep the new inventory as your current configuration; deploying an older one would restore its older access rules.

Each permission applies to the declared node tag. The administrator must assign tags only to their intended nodes. HTTPS access does not create an application account or grant room/file permissions. It does not grant reverse access or management SSH. Remove the permission through the same wizard and apply the resulting inventory to withdraw future network access.

For a joining organisation, its network administrator owns this step. A node manifest alone cannot authorize access. The current wizard requires the nodes to have been declared during infrastructure setup; it does not silently enroll an unknown device.

## Local node: run on the intended Ubuntu machine

Copy its manifest and a reviewed project copy to that machine. Create the Python environment there; do not copy a Mac .venv to Linux.

```sh
./rdc node check /absolute/path/node-NAME.yml
./rdc node apply /absolute/path/node-NAME.yml
sudo ./rdc node enroll /absolute/path/node-NAME.yml
sudo ./rdc node status /absolute/path/node-NAME.yml
```

Apply explicitly confirms this computer and uses normal sudo authentication. Enrollment remains a separate interactive action requiring administrator approval. Temporary registration information must not be saved to logs. Matching enrolled nodes do not re-register.

Check and status never request sudo themselves. If client state inspection needs root, deliberately rerun the read-only command through your existing local administration, as the status example demonstrates. An ownership mismatch is a blocked migration, not an invitation to delete client state.

Installed, awaiting approval and enrolled are distinct results. Even an enrolled node does not yet provide an application or data recovery.

## Understand a problem

```sh
./rdc doctor /absolute/path/node-NAME.yml
```

Doctor validates the local-node manifest, inspects applicable local state, and probes only the declared controller on HTTPS port 443. It does not install, start services, enroll, change DNS or ask for sudo. On unsupported local platforms it marks installation/service inspection not applicable while checking controller reachability.

DNS, connection and TLS verification have separate results. Dependent checks are not declared failed when an earlier step prevented them. The controller worker has a 15-second overall deadline, including DNS lookup; local service/state commands have their own bounded timeouts. Certificate validity is verified using system trust. A verified certificate with 14 days or less remaining is flagged for renewal. Local UTC time is shown only as a diagnostic, not proof of clock synchronization.

Examples:

| Result | Next action |
|---|---|
| DNS resolution failed | Check the controller DNS record and the computer's resolver |
| HTTPS connection failed | Check reachability, service listening and firewall rules |
| Certificate verification failed | Inspect trust, hostname, expiry and clock; do not disable verification |
| Ownership mismatch | Inspect the existing installation through local administration |
| Awaiting enrollment or approval | Ask the intended controller administrator to verify and approve the node |
| Unknown inspection state | Resolve local permissions or service availability before retrying |

### Optional private support report

Choose a new filename in an existing private directory you own:

```sh
mkdir -m 700 support
./rdc doctor /absolute/path/node-NAME.yml --report support/diagnostics.json
```

The report contains fixed diagnostic codes/explanations, source identity, broad platform labels and a UTC timestamp. It excludes manifests, names, domains, addresses, file paths, environment variables, raw logs, credentials and registration links. It is written atomically with mode 0600, refuses symlinks, and never overwrites an existing file. Review it before sharing; the version/platform/check results still describe your installation.

A report-writing error is separate from the diagnostic results already printed. Ordinary terminal output may contain operational details; share the allowlisted report rather than redirecting arbitrary installation or enrollment output.

## Know your version

```sh
./rdc version
```

This shows the declared project version, component pins, the Git commit when available, and whether tracked source differs from it. Ignored private configuration does not make the source dirty. Untracked source files are outside this tracked-difference check. An archive inside another Git repository does not inherit that repository's identity. Missing metadata is reported as unknown/unreleased.

Version labels and Git commit IDs are not verified build provenance. This increment has no self-updater or published binary downloader. Do not replace a running controller binary or database based solely on a newer version number. Reviewed release distribution, certificate renewal and supported upgrade/recovery procedures are subsequent increments.

## Automation exit statuses

| Code | Meaning |
|---|---|
| 0 | Requested action completed; inspect whether it was preparation, checks, installation or enrollment |
| 1 | Operational failure, network diagnostic failure or report-writing error |
| 2 | Invalid command or input |
| 3 | Unsupported platform, blocked prerequisite/ownership or required unknown state |
| 4 | Pending enrollment/approval or cancellation |

Doctor can complete its applicable checks on macOS with status 0 while local installation remains unsupported. Read its not-applicable outcomes; status 0 is not deployment readiness. Saving an incomplete draft also returns 0 because the save succeeded, not because deployment can proceed.

Original Python-script commands remain available with their original output and exit conventions. Use the common interface for the table above.

## Development checks

```sh
.venv/bin/python scripts/check_local.py
```

GitHub's Local checks workflow runs this command on a disposable Ubuntu runner with read-only repository permissions. It uses synthetic fixtures and loopback TLS tests; it does not deploy services or enroll real nodes. A green workflow is evidence of local consistency, not a successful live deployment.

## Verified downloads

`./rdc release fetch VERSION --commit FULL_COMMIT --output-dir NEW_DIRECTORY` verifies the fixed project publisher, workflow, source revision and artifact hashes before making release files available. It never installs them. See [release instructions](releases.md) for prerequisites and trust limits.

## Infrastructure certificate lifecycle

The wizard offers supplied certificates (existing schema 2) or explicit managed issuance (schema 3). See [managed certificates](managed-certificates.md) for operator terms acceptance, public port/DNS requirements, status and renewal recovery. No certificate mode is silently changed on an existing installation.

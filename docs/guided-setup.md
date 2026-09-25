# Guided network setup

This milestone provides a question-and-answer wizard, offsite controller/relay preparation and a dedicated local-node installer. It installs networking only. Matrix/Element, Nextcloud, backups, automatic recovery and regional gateways are not included yet.

**Status:** locally tested, including simulated enrollment and local TLS tests. Actual Ubuntu installation, real enrollment and home-NAT connectivity have not been tested. Use disposable pilot machines first; this is not a production-ready release or a completed beginner-usability validation.

Use the [common `rdc` interface](operations.md) for the menu, deployment commands, diagnostics and documented exit codes. The original Python/Ansible commands below remain supported as reference interfaces.

## Where each part runs

| Location | What you do there |
|---|---|
| Operator computer | Run the wizard; prepare private configurations; deploy the offsite controller/relay through SSH |
| Offsite Ubuntu controller and relay | Run the generated network infrastructure; administrator approves registration on the controller |
| Each home/private-network Ubuntu node | Run check, apply, enroll and status locally; no public management SSH is required by this flow |

The supported node platform is Ubuntu 24.04 amd64 with systemd. macOS can prepare configurations, but local apply is blocked there. ARM/Raspberry Pi support has not been implemented. Controller and relay are separate machines in this baseline; keep independent console/administration access.

## Obtain the project and local tools

Obtain the project from [kollanekirss/resilient-datacenter](https://github.com/kollanekirss/resilient-datacenter):

```sh
git clone https://github.com/kollanekirss/resilient-datacenter.git
cd resilient-datacenter
```

Review the code before applying it and record the commit you deploy with `git rev-parse HEAD`. The main branch is an experimental pilot, not a certified or live-validated release.

From the project directory on the operator computer, prepare Python 3.11+ tooling as described in the README. On each fresh Ubuntu node, install the required local tools through its console or existing local administration:

```sh
sudo apt-get update
sudo apt-get install -y python3-venv ca-certificates openssl
```

Copy the reviewed project onto the node, enter its directory, then create its own environment. Do not copy the operator computer's .venv directory between operating systems.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Do not run pip as root and do not pipe a remote installer into sudo. Network installation still needs access to the pinned upstream client archive and Ubuntu package repositories.

## Prepare configurations with the wizard

On the operator computer:

```sh
.venv/bin/python scripts/setup_wizard.py
```

Default output is the ignored private folder inventories/lab/setup/. To select another private directory:

```sh
.venv/bin/python scripts/setup_wizard.py --output-dir /absolute/private/setup
```

The wizard supports:

- `independent`: prepare your own offsite controller/relay and one or more planned local nodes.
- `join`: prepare one local node for a controller operated by you or another administrator.
- `:back`: revisit the previous answer.
- `:save`: save an incomplete draft and return later.
- `:cancel`: stop without installation or enrollment.

Saved answers appear in brackets when revisited; Enter keeps the saved value. If you change independent/join purpose or reduce the node count, irrelevant answers are discarded.

Resume a draft using the same output directory:

```sh
.venv/bin/python scripts/setup_wizard.py --resume inventories/lab/setup/draft.yml
```

A draft is not a deployment input. Missing certificate/artifact files produce a draft and a list of prerequisites, not an apparent installation success. Existing files require an explicit replacement choice. Symlink targets and unsafe output directories are rejected. Keep generated configuration outside a public repository even though node manifests contain no private keys.

The final BUNDLE.json lists the current files and their checksums. Its state is prepared or draft. If writing is interrupted, no completion record is produced. When replacing a bundle, older unlisted files can remain; use only files named in the current completion record. Checksums detect file changes; they are not a signed invitation or proof that a controller is trustworthy.

## Create your own offsite network

Before answering all independent-mode questions, obtain:

- Two fresh Ubuntu 24.04 amd64 servers for controller and relay, with public IPv4 addresses and independently verified SSH access.
- Two real DNS names resolving to those servers.
- Publicly trusted certificates with matching DNS SANs, full chains and corresponding unencrypted PEM private keys, stored securely on the operator computer.
- The pinned relay executable and checksum. Build it using `scripts/build_derper.py` as explained in the README; the wizard never builds/downloads tools as a side effect of a question.
- Names and unique requested tags for local nodes at your locations. You do not need their public IP addresses or public SSH access.

The wizard does not buy servers, configure DNS-provider accounts or issue/renew certificates. These remain operator prerequisites. Consult docs/networking.md for public ports, firewall rules and bootstrap dependencies. Follow your certificate issuer's supported process before applying; do not bypass TLS validation to continue.

The wizard generates infrastructure.yml, one node-NAME.yml per local node, NEXT-STEPS.md and BUNDLE.json. From the project directory on the operator computer:

```sh
.venv/bin/python scripts/validate_setup.py inventories/lab/setup/infrastructure.yml --kind infrastructure
.venv/bin/ansible-playbook -i inventories/lab/setup/infrastructure.yml playbooks/infrastructure-preflight.yml
.venv/bin/ansible-playbook -i inventories/lab/setup/infrastructure.yml playbooks/infrastructure-deploy.yml
```

These entry points manage only the controller and relay. Planned home nodes are tag/enrollment declarations, never SSH targets. No dummy public service node is required. The application policy initially denies inter-node application connections; enrollment alone does not grant access to a future chat or file service.

On the controller, check existing users and create the enrollment administrator once, using the name selected in the wizard:

```sh
sudo headscale users list
sudo headscale users create YOUR-ENROLLMENT-ADMIN
```

Do not recreate an existing user. Configuration and administrator creation remain explicit. Verify controller/relay reachability before moving to local node setup.

## Install each local node

Copy its node-NAME.yml to a private location on the intended Ubuntu machine. Confirm the controller's DNS name and requested tag with the administrator through a trusted channel. A manifest grants no admission and contains no reusable enrollment key.

From the project's directory on that node, use the actual manifest path:

```sh
.venv/bin/python scripts/local_node.py check /absolute/path/node-NAME.yml
.venv/bin/python scripts/local_node.py apply /absolute/path/node-NAME.yml
```

Check is read-only: it validates the platform, manifest, ownership, existing state and TLS connection. It reports a clock diagnostic but does not independently verify synchronization. If an existing client cannot be inspected due to permissions, use local administration to rerun the check with sudo; do not delete its state.

Apply shows the current machine and intended controller, requires an explicit yes, then uses normal sudo/become authentication. It installs only the client using a private snapshot of the reviewed manifest. It does not install controller/relay software, modify public SSH, change your router or enable network-wide routing. No applications or backups are installed.

Existing unowned/legacy/profile installations and ownership changes are rejected. This is an installer for fresh or matching local-managed nodes, not an automatic migration tool. A matching rerun preserves identity. A stopped daemon with persistent state requires inspection/start through local administration before continuing.

## Enroll and obtain approval

On the intended node, in an interactive terminal:

```sh
sudo .venv/bin/python scripts/local_node.py enroll /absolute/path/node-NAME.yml
```

Enrollment may display a temporary registration link/ID. Do not redirect this command to logs, paste its output into public tickets or save it in Git. Native registration requires an interactive terminal; status checking can be noninteractive.

The controller administrator must authorize the requested tag and register the independently verified pending node. On the controller:

```sh
sudo headscale auth register --user ADMIN-NAME --auth-id=PENDING-ID
```

For an independently created environment, this is your configured administrator. For an existing network, its operator performs the approval under their policy. The local installer cannot authorize itself or modify that controller's policy.

The enrollment command waits a bounded time. Pending approval is a normal intermediate state. If you cancel, the installer stops only its foreground registration command and preserves the daemon/state. After approval:

```sh
sudo .venv/bin/python scripts/local_node.py status /absolute/path/node-NAME.yml
```

Require status enrolled, the intended node identity, exact tag and valid overlay address. If still pending, contact the administrator or rerun enroll to display the existing pending request. Matching enrolled nodes do not launch registration again. Expired/unusable pending requests may need administrator inspection; automatic forced reauthentication is intentionally not included.

Run this flow separately at each location using different manifests. Never clone an already enrolled node's persistent identity onto a second active machine.

## What success means

At this stage, success means the intended machine is installed and approved in the intended network. It does not mean another node is authorized to use an application, that a direct NAT path works, that data is backed up, or that the second site can take over a service.

The controller/relay still have their documented dependencies. DERP admission is fail-closed when controller verification is unavailable. Real direct/relay behaviour must be tested on the target networks. Follow docs/local-install-acceptance.md before claiming this workflow supports your home environment.

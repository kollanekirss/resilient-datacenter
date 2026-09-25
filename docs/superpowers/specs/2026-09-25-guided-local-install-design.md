# Guided setup and local node installation

Date: 2026-09-25. Status: implemented and locally verified; actual Ubuntu installation and network acceptance remain NOT RUN.

## Purpose and completion boundary

A user can prepare an offsite network and install its client on a home/private-network machine without editing YAML or exposing public management SSH on that machine. Existing institutions can use the same local-node flow to join an approved controller.

This milestone installs the networking foundation. It does not install Matrix, Element, Nextcloud, replication, backups or a regional gateway. Completion messages must say 'network node enrolled', not 'resilient services ready'. Personal, institutional and regional application goals remain defined in the expanded product specification.

Supported machines remain Ubuntu 24.04 amd64 with systemd. The configuration wizard can run in the existing supported operator Python environment; applying a local node installation is permitted only on the supported Linux target. Do not install or start a network client on the developer's Mac while implementing/testing this feature.

## Selected approach

Use one command-line wizard with separate preparation and application steps. It generates strictly validated configurations for existing reusable Ansible roles. A dedicated local execution path installs only the current node. It never interprets an arbitrary downloaded Ansible inventory as permission to run local tasks.

Alternatives considered:

- Require remotely reachable SSH for every service node: simpler reuse, but it fails the home-user requirement.
- Build a custom ISO or a permanently privileged web installer: potentially convenient later, but introduces hardware/platform or web-administration scope before the installation model is proven.

The selected approach retains ordinary Ubuntu installations, keeps application and network privileges explicit and provides a single backend for a future graphical interface.

## Guided user journeys

### Create my own network

1. Choose 'Create my own network'. Explain that the initial topology requires one offsite controller and a separate reachable relay; neither node is automatically purchased or provisioned.
2. Collect an environment name, controller/relay SSH addresses and users, DNS names and local certificate paths. Explain which DNS records and certificates must exist before deployment.
3. Collect names and tags for the intended local service nodes, such as home-services and recovery-services. These are enrollment requests, not SSH targets; do not ask for their public IP addresses.
4. Build or select the pinned relay executable and validate its checksum. Dependency preparation is a separate explicit action, never a side effect of answering a question.
5. Show a readable deployment summary, validate prerequisites and save the offsite configuration plus one local-node manifest per intended node.
6. An explicit apply action deploys only the offsite controller and relay through SSH. It installs tag ownership and default-deny application policy for the planned nodes.
7. Display instructions to create the enrollment administrator once, then transfer each local-node manifest to its intended machine and follow local installation.

Offsite controller and relay deployment must work before any service node is enrolled. A dummy publicly reachable peer is prohibited.

### Join an existing network from this machine

1. Choose 'Join an existing network' or import a local-node manifest.
2. Enter/confirm the institution identifier, node name, controller DNS name and administrator-approved tag. Explain that these labels do not prove identity or authorize admission.
3. Display the current machine name, operating system, architecture, intended controller and planned changes. If the machine is unsupported, offer configuration preparation only.
4. Run read-only checks: installed software/ownership, network reachability, controller TLS trust, clock and privileges. Never disable certificate verification.
5. On explicit apply, use sudo for the local client installation. Preserve independent local/console administration; do not alter SSH settings, open router ports or replace host firewalls.
6. Ask whether to start enrollment. Show the pending registration information and tell the user which administrator must approve it. Do not request a reusable network key or the controller's root credentials.
7. After approval, verify the actual controller, exact approved tag and overlay address using the existing state-inspection logic. If approval is pending, save that status and provide a resume command.

A user can run the same flow at the second location with a different node manifest. Each node has its own identity; the wizard must warn against copying an enrolled machine's persistent state to create a second active node.

## Configuration contracts

Preserve the existing legacy and schema-version-1 workflows. Introduce a separate infrastructure inventory contract with `schema_version: 2`, `deployment_mode: independent` and groups containing only controller and relay. Each group has exactly one host.

Retain existing controller/relay inputs and add `enrollment_nodes`, a nonempty list of mappings containing only `name` and `node_tag`. Names and tags are unique. These nodes are not inserted into Ansible's managed-host groups. Generate their tag ownership under the configured enrollment administrator and an explicit empty grants list. No test-pair or application-access grants are included in this milestone's infrastructure-only profile.

Reject schema-version-2 infrastructure input in the version-1 entry points and vice versa. Reuse shared parsing, identifier, TLS and checksum validation primitives; do not create conflicting definitions of valid input. Infrastructure ownership records use the new schema version so an older workflow cannot silently claim the deployment.

A local-node manifest is a separate document kind, not an Ansible inventory. It contains exactly:

```yaml
kind: local-node
schema_version: 1
institution_id: my-home
node_name: home-services
headscale_hostname: control.example.com
node_tag: tag:home-services
```

The example hostname is intentionally nondeployable. A manifest contains no host list, SSH connection options, executable paths, shell commands, certificate private keys or registration secrets. Reject unknown keys, duplicate YAML keys, aliases, template expressions, invalid identifiers and placeholders on apply. A manifest is configuration, not a trusted invitation: the operator must confirm the controller and requested tag independently, and the controller must approve enrollment.

The local installer internally generates its own localhost-only Ansible input. It cannot install controller/relay roles or target another machine. Do not add `ansible_connection: local` as an accepted setting to the existing remotely managed inventory validator.

## Ownership, privilege and resume

Use the existing `/etc/server-connectivity-profile.json` ownership location, with an explicit new record shape for local installation: schema_version 2, deployment_mode join, institution_id, role peer, controller_hostname, node_name, node_tag and install_method local. Compare the full expected record before modification. The local document schema and on-host ownership schema are separate contracts and must be named clearly in code/tests.

Reject existing unowned Tailscale installations and legacy/version-1 managed hosts. Changing controller, node identity or management method requires a separately reviewed migration. Do not reset enrollment, delete persistent state or reinterpret an existing managed node as a fresh installation.

Preparation writes user-owned private output only. Applying installation uses the existing pinned client role with a local-specific guard. After installation, the daemon runs under its normal service permissions. The wizard itself does not remain as a background administrator service.

The local apply action checks the repository/release tooling path rather than executing commands supplied in a manifest. Administrative actions require the user's normal sudo mechanism; never collect or save a sudo password in a configuration file. Subprocess calls use argument arrays rather than shell interpolation.

Resume detects installed-but-unenrolled, awaiting-approval, enrolled and stopped/mismatched client states. Already enrolled matching nodes do not run enrollment again. Existing persistent state with an unavailable daemon requires independent inspection/start, matching the conservative safeguard of the existing profiles. Cancellation during enrollment must not delete machine state or create a second identity on retry.

## Files, questions and incomplete prerequisites

The wizard asks one understandable question at a time, supports going back and displays a final summary. It does not overwrite an existing configuration without explicit user choice. Write finalized output atomically with restrictive permissions inside a user-selected local directory; refuse unsafe symlink overwrite targets.

Default generated output belongs under the ignored private inventory/output area, never among public examples. A complete independent setup emits the infrastructure inventory, node manifests and a plain-language next-steps file. Joining emits only the local-node manifest and instructions.

If DNS, certificate files, relay artifact or a required answer is unavailable, allow saving an incomplete draft and returning later. Drafts are clearly distinct from validated deployment inputs and cannot be applied. Do not silently fill missing fields with values that appear deployment-ready. Certificate issuance and DNS-provider automation are not implemented here; guidance and validation must make those remaining tasks explicit.

The operator must still be able to install Ubuntu, obtain offsite servers/domains and follow terminal instructions. Do not advertise the complete product as beginner-ready until a new colleague completes the documented installation and enrollment without editing YAML or receiving undocumented assistance.

## Connectivity and trust

Local nodes initiate controller HTTPS and relay HTTPS/STUN connectivity through their existing internet connection. No public management SSH or manual router port forwarding is required by the local installation flow. Direct peer connectivity depends on actual NAT/firewall conditions; a working relay fallback must be tested rather than assumed.

Management reachability for offsite controller/relay remains an independent prerequisite. Use existing source-limited SSH administration and TLS rules. The relay's fail-closed controller verification behaviour is unchanged, and outages may prevent fresh relay admission. This milestone does not remove the controller, relay, public DNS or certificate dependencies.

The local installer does not ask the regional operator to administer the institution's internal controller. A local join is one-network membership. Connecting both an internal and regional network still requires the separately designed gateway.

## Acceptance criteria

- Wizard answers produce valid infrastructure and local-node outputs; the user need not edit YAML.
- Infrastructure deploys without managing or requiring a service-node SSH target.
- Imported manifests cannot add remote targets, privileged commands, controller roles or inventory execution settings.
- Unsupported OS/architecture blocks local apply before mutation; configuration preparation remains possible.
- Drafts, unsafe paths, existing-file collisions and invalid/duplicate inputs have clear actionable outcomes.
- An existing enrollment with a different controller/identity is rejected; matching reruns preserve identity and skip registration.
- Pending approval, cancellation and resume do not report success prematurely or leak temporary registration material into saved logs.
- Actual local installation is tested in disposable Ubuntu VMs, not on the developer workstation.
- Two real test nodes behind private networks enroll without public SSH; record direct versus relay connectivity separately.
- All existing 121 tests and supported legacy/profile workflows remain valid; any intentional compatibility change requires its own migration design.
- Public instructions distinguish network enrollment from application installation and resilience.

Local unit tests, generated-output checks and nonmutating command tests can run before servers exist. Local package/service installation, real NAT traversal and administrator-approved enrollment remain NOT RUN until suitable Ubuntu test machines and offsite infrastructure are available.

## Implementation boundary and next handoff

This specification authorizes planning for the wizard, infrastructure-only preparation and dedicated local-node installation as one coherent networking milestone. The implementation plan must keep their interfaces explicit and test each privilege boundary. Review this written design before implementation planning. No product code, host networking, cloud resources or publication is changed by this document.

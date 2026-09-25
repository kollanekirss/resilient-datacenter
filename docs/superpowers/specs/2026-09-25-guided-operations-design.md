# Guided installation and maintenance

Date: 2026-09-25
Status: approved; increment A implemented with local verification. B/C/D and live acceptance remain separate work.
Repository: https://github.com/kollanekirss/resilient-datacenter
Baseline: published commit 6a0a2ce, 184 local tests, 16 playbook syntax checks. No live deployment evidence.

## Intended outcome

An operator who did not build the project can prepare a network, deploy its infrastructure, install local Ubuntu nodes, understand failures and identify exactly which software version is in use. The same installation foundation serves individuals, institutions and later partner networks.

The user approved pursuing guided installation and maintenance before packaged chat. This design decomposes that milestone into independent increments. It does not treat all increments as delivered by a common command name.

## Approach and alternatives

Extend the existing Python/Ansible implementation with one command-line entry point. Reuse strict validators, ownership guards, the configuration wizard and enrollment state inspection. Keep existing public scripts and document formats compatible.

An ISO would add hardware/image distribution and upgrade responsibilities before the deployment model is proven. A privileged web interface would add authentication, session and network-exposure responsibilities. Neither is needed for this milestone. The selected command-line interface can later serve as the backend for a graphical interface.

## Delivery order

| Increment | Deliverable | Completion boundary |
|---|---|---|
| A — common interface and diagnostics | Launcher, readable checks, private support reports, source identity and local-check CI | All supported actions use existing guarded backends; preparation and read-only actions cause no installation |
| B — versioned distribution | Reviewed release workflow, source archives, verified relay binaries, provenance and checksums | A tagged prerelease can be downloaded and verified without building the relay locally |
| C — certificate lifecycle | Explicit issuance, renewal, service activation and failure reporting | A supported certificate mode renews and is activated on disposable Ubuntu targets without bypassing trust |
| D — managed updates | Version comparison, compatibility decision, backups and explicit upgrade procedure | Each supported upgrade path has installation and recovery evidence; unsupported paths are blocked |

Implement A first. B, C and D need their own focused implementation plans against the interfaces introduced by A. This sequence covers the previously proposed milestone without hiding certificate or upgrade work inside a wrapper.

## Increment A: user interface

Add a repository-root executable named `rdc`. Resolve the repository from the launcher's own location, not the caller's working directory. Use that repository's .venv Python. If dependencies are absent, print the exact preparation commands and exit; never install packages automatically or fetch and execute a remote script.

The command surface is:

| Command | Behaviour |
|---|---|
| `./rdc` | Show an understandable menu and the supported commands; no mutation |
| `./rdc setup` | Existing independent/join wizard, including save/back/resume and explicit output replacement |
| `./rdc infrastructure check INVENTORY` | Existing complete infrastructure preflight, including read-only SSH target inspection |
| `./rdc infrastructure apply INVENTORY` | Show controller/relay targets, then explicit confirmation before existing complete deployment |
| `./rdc node check MANIFEST` | Read-only local installation prerequisites |
| `./rdc node apply MANIFEST` | Existing local-only guarded installation and normal sudo authentication |
| `./rdc node enroll MANIFEST` | Existing explicit terminal-only registration and administrator approval |
| `./rdc node status MANIFEST` | Inspect verified local enrollment state |
| `./rdc doctor MANIFEST` | Explain local prerequisites and failures, with optional private support-report output |
| `./rdc version` | Show project source identity and pinned component versions |

Menu choices dispatch through the same parser and backend as explicit commands. Do not create a second installation implementation or infer an installation target from menu context. Show whether an action runs on this computer or on the offsite controller/relay. Keep the current independent and join terminology in help text.

Infrastructure operations accept only infrastructure schema 2 and the existing validators. Local-node operations accept only the six-field local manifest. Do not accept arbitrary Ansible options, extra variables, connection overrides, executable paths or shell snippets. Existing legacy/schema-1 workflows remain accessible through their original scripts and documentation; no automatic migration.

An infrastructure inventory is parsed once, validated and written to a private snapshot before confirmed apply, so changes to the source file cannot substitute targets after review. The snapshot retains validated absolute certificate/artifact paths. Existing backend guards still run independently. Backend subprocesses use argument arrays, trusted project paths and project configuration, with inherited Ansible execution overrides removed.

## Action results and exit status

Human output must distinguish: preparation complete, checks passed, installed but not enrolled, awaiting approval, enrolled, blocked, cancelled and failed. A successful process is not necessarily a working service or resilient deployment.

New launcher exit status: 0 for the action's defined success, 1 for an operational failure, 2 for invalid arguments/input, 3 for a blocked prerequisite or ownership conflict, and 4 for pending approval or cancellation. Document these values; preserve existing direct-script exit behaviour for compatibility. Pending enrollment must not be presented as a completed enrollment in automation.

Avoid interpreting human stdout to determine state. Extract small reusable backend result functions where needed and preserve old script interfaces. Native registration display remains confined to the explicit interactive enrollment action; diagnostics and status cannot initiate registration.

## Read-only diagnostics

Use structured checks with a stable code, outcome, plain-language explanation and next step. Outcomes are pass, fail, unknown and not-applicable. A dependency failure must not create a misleading cascade of unrelated failures.

The initial checks cover:

- Manifest format and supported schema.
- Current OS, CPU architecture, Python/tooling availability and systemd where applicable.
- Installed ownership and persistent identity, without replacing or starting services.
- DNS resolution, connection timeout/refusal and verified TLS handshake as separate outcomes where evidence permits.
- Certificate expiry and hostname/trust problems when determinable; preserve an unknown trust error if the TLS API cannot classify it safely.
- Current client service state and exact intended enrollment, when platform, ownership and privileges allow inspection.
- Project source identity and pinned component versions.

Preparation is supported on the operator computer, including macOS. Doctor may explain DNS/TLS prerequisites there but must explicitly mark Linux installation/service checks not applicable. Unsupported-platform installation remains blocked. Doctor never attempts sudo interactively, starts a daemon, rewrites DNS, changes the clock, clears state or weakens TLS validation.

Report local clock time as a diagnostic only, not proof of time synchronization. Use bounded subprocess and network timeouts, provide Ctrl-C cancellation, and cap total sequential network probing. Do not scan subnets or probe destinations not derived from the validated manifest.

## Support report

`./rdc doctor MANIFEST --report PATH` writes an opt-in, private JSON report. Default doctor produces terminal output only. A report contains report schema version, UTC generation time, project identity, supported platform metadata, check codes/outcomes and fixed explanations/next-step identifiers.

The shareable report excludes raw manifests, personal or institution names, hostnames, DNS names, IP addresses, usernames, file paths, raw subprocess output, preferences, environment variables, enrollment URLs, authentication data, key contents and traceback text. Check details for local display and report serialization are separate allowlisted structures. Do not rely on regex replacement over arbitrary logs as the privacy boundary.

Refuse unsafe/symlink destinations and accidental overwrite. Write atomically with mode 0600 using the established private-file approach. A failure to write the report does not change the diagnostic outcomes or any installed state. Test with secret and identifying sentinels in every error source.

## Source identity

The version command reads the repository's supported version metadata and component pins. A Git checkout also displays commit identity and whether tracked source differs from that commit. Do not include private ignored files when computing dirty status. A source archive without release metadata must say unknown/unreleased; never fabricate a version or claim verified provenance.

Increment A does not add a self-updater or silently replace the working tree. It identifies what is installed and links the operator to release information. Application of updates belongs to D.

## Local-check continuous integration

Add a pull-request and push workflow that creates a clean Python environment on a disposable Ubuntu runner and executes the existing local check suite plus new interface/diagnostic tests. Pin third-party actions to reviewed commit SHAs. Use read-only repository permissions, bounded job duration and no production secrets. Do not use pull_request_target to execute contributor code.

The first CI job does not install services, enroll nodes or contact public fixture addresses. Existing test TLS listeners remain loopback-only. A clean checkout passing this workflow is local implementation evidence, not runtime installation evidence. Display that boundary beside any status badge.

A future disposable systemd/Ubuntu installation job must be separately designed. Container-only checks cannot substitute for systemd, TUN, NAT, approval or cross-site fault tests. Skipping rented servers does not turn those checks into passing evidence.

## Increment B boundary: distribution and verification

Build the pinned Linux/amd64 relay using the existing source/toolchain constraints in a controlled release workflow. Publish a source archive, relay binary, build metadata, dependency/license notices and checksums tied to the exact tag and commit. Validate upstream redistribution obligations before shipping binaries.

Use GitHub artifact attestations to establish the producing repository/workflow and source revision. Checksums alone detect mismatches but do not authenticate a publisher. The future downloader must verify both integrity and expected provenance before making an executable available for explicit deployment. It must reject unsupported platforms, unrelated repositories/workflows and mismatched source identity.

Release publication is an explicit maintainer action. Never publish a release simply because a pull request or main-branch test passes. Mark releases experimental until live acceptance has actually been performed. Source/binary availability is distinct from a supported upgrade path.

## Increment C boundary: certificates

Keep the current operator-supplied certificate mode working. Add one explicit managed issuance mode for fresh, supported controller/relay hosts only after its design defines issuer, account/terms handling, challenge method, DNS/public-port requirements, ownership, storage and service activation.

Private keys should be generated and retained on their target hosts in managed mode. Validate certificates before activation; preserve existing working files if issuance/renewal fails. Renewal must activate the replacement certificate in the actual controller/relay service and verify it. Scheduling renewal without service activation is incomplete. Announce expiry/renewal failure through a documented status path.

This requires a new validated configuration contract and changes to the roles' current local-file copy model. It cannot be safely implemented by an extra wizard question alone. Do not reinterpret existing schema-2 supplied-file inputs or accept DNS-provider API credentials inside public configuration. Issuance failure cannot trigger self-signed fallback or disabled trust checks.

## Increment D boundary: updates and recovery

Separate a read-only update check, a reviewable update plan and an explicit application action. Record current and target project/component versions and support only reviewed transitions. Check platform, full ownership, available storage, configuration compatibility and backup prerequisites before mutation.

Backups must cover relevant databases, configuration and node identity with restrictive access. Never promise that replacing an older binary reverses a database migration. Recovery documentation must define restoration of compatible data/configuration and guard against two active machines using the same identity.

No unattended upgrades, automatic controller migration, forced enrollment reset or generic downgrade command in the first maintenance milestone. Stop with an actionable reason when compatibility or recovery is unknown.

## Acceptance for increment A

1. A clean checkout offers one entry point and exact dependency instructions without modifying the machine.
2. Menu and explicit commands route to the same guarded implementations; invalid inputs cannot invoke installation.
3. Infrastructure operations target only the declared controller/relay; node operations target only the local machine.
4. Existing ownership protections, enrollment cancellation, private output handling and all baseline tests remain intact.
5. Every diagnostic result has a stable code and useful next step; unsupported and unperformed checks are accurately labelled.
6. Report tests prove that identifying/private sentinels never enter saved output, including exception paths.
7. Known installed, pending, mismatched and unavailable states produce documented launcher exit statuses without parsing human logs.
8. Read-only actions never install, enroll, reset identity, restart services or prompt for privilege escalation.
9. CI passes from a clean checkout with no private artifacts or developer-specific paths.
10. Documentation explicitly lists remaining certificate, distribution, update and live-acceptance work. No claim of beginner readiness is made without a colleague completing the process.

## Implementation handoff

Increment A is the next implementation unit. Prepare its written plan after this design is reviewed. That plan should identify the smallest backend refactoring, failure-first tests for dispatch/privacy/result handling, launcher and docs changes, CI validation and the final publication boundary. Work remains inside this repository; no developer-Mac client installation, cloud provisioning or subagents.

## References

- Existing guided setup design: 2026-09-25-guided-local-install-design.md in this directory.
- Current operator guide: ../../guided-setup.md.
- GitHub build provenance: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- GitHub attestation generation/verification: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

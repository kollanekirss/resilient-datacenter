# Validation status — 2026-09-25

**Legacy/profile workflows, guided local installation and unified operations: implemented and locally checked. Live deployment: NOT RUN.**

| Check | Status | Evidence / boundary |
|---|---|---|
| Python unit and local integration tests | PASS | 356 tests: legacy/profile coverage plus common CLI, structured diagnostics, private reports, source identity, snapshots, wizard and enrollment boundaries |
| Ansible syntax | PASS | All 16 playbooks; infrastructure-only and both original profiles passed host/task listing without target connections |
| Example inventory refuses deployment validation | PASS | CLI exits 1; no connections attempted |
| DERP cross-build | PASS | Linux/amd64 ELF, source v1.102.4, Go 1.26.6, artifact SHA256 recorded in provenance.md |
| Independent agent review | NOT RUN | This side conversation prohibits subagents; final review was performed inline |
| Headscale runtime configuration | CI PASS | Disposable pinned controller starts with the rendered configuration and relay map; administrator deployment still requires target preflight |
| Target OS/package/service installation | NOT RUN | No VPSs supplied |
| Public DNS and controller/relay TLS trust | NOT RUN | Real domains/certificates required |
| Node registration/tag acceptance | NOT RUN | Administrator approval on live controller required |
| Actual inter-server HTTPS and denied ports | NOT RUN | Local TLS tests do not prove overlay enforcement |
| Private relay path and return to direct | NOT RUN | Requires controlled live fault injection |
| Controller/relay outages | NOT RUN | Requires separate existing/fresh connection experiments |
| Deployment rerun and reboot identity preservation | NOT RUN | Persistent paths are tested structurally; operational result remains unverified |
| Controller backup restore | CI PASS | Disposable exact-version restore, actual database content, ingress isolation, rollback and interrupted recovery; live site loss remains untested |

Reproduce local checks from the project directory:

```sh
.venv/bin/python scripts/check_local.py
```

No test connects to the synthetic IP addresses in unit fixtures. The HTTPS integration test listens on local loopback solely within the test process; the deployed executable rejects loopback/public bind addresses and accepts only overlay addresses. It does not change host networking.

## Review outcomes

- Controller policy and relay map are staged, and the target's pinned binary validates the staged configuration before activation. Package auto-start is suppressed during install. Certificate renewal changes still require the documented operator workflow.
- The relay explicitly fails closed when the Headscale verification callback is unavailable. No public fallback relay is silently added.
- Private keys are excluded from task logs and stored with service-account access only. No enrollment secrets or real institutional inventories have been created.
- Deployment roles do not run enrollment, reset node identity, advertise subnets or enable exit-node access.
- Negative tests require known working listeners, clean up in an Ansible `always` block, and have a 120-second service time limit. Timeouts require firewall attribution review before claiming Headscale policy enforcement.
- Live reports contain a UTC generation time and leave untested outage/restore scenarios marked `not-run`. A report from a previous successful invocation is not evidence for a later failed run.
- Application federation, production HA, autonomous operations and uninterrupted relocation are outside this first connectivity milestone.

Local checks are useful evidence of implementation consistency, not a production readiness certification.

## Profile milestone evidence

The full `scripts/check_local.py` run on 2026-09-25 passed **121 tests**, syntax checks for **13 playbooks**, rejection of all three public example inventories by deployment validation, and independent/join task and host listings. Local integration tests replace SSH with a nonconnecting stub when testing complete entry points; no synthetic public fixture IP is contacted. Separate localhost-only Ansible runs exercise policy rendering, exact pair selection and rejection of each ownership-field mismatch.

Three syntax checks warn that `profile_test_peers` does not yet exist. This is expected because the optional group is created from the validated pair at runtime; local execution tests verify that creation excludes an unrelated third node. Syntax success is not runtime proof of deployment.

Review fixed three observed failures: integer values being accepted as IP addresses, legacy installation potentially overwriting versioned-profile ownership, and unsupported tag filters silently skipping validation. Regression tests failed before each fix and passed afterward. Ansible's run-tag value is a tuple in this environment; the guard now normalizes it before checking supported execution mode.

Implementation decisions:

- Work remained inside the existing standalone directory, with a private source snapshot for review; there is no Git repository or worktree to commit. GitHub publication remains separate.
- Review was performed inline because this side conversation prohibits subagents. This provides no independent reviewer assurance.
- A peer with persistent state and an unavailable daemon is rejected by preflight until an operator inspects/starts it through management access. This adds an operator step but avoids guessing the enrolled controller or resetting state.
- Positive/negative verification tasks were extracted into shared files. Legacy tests follow those imports and retain their original behavioral checks.

New profiles and the legacy workflow reject ownership crossover. The original schema-version-1 profile workflow does not provide private/home-network installation or a beginner wizard. The separate guided milestone below adds those local installation interfaces; automatic migrations, Matrix/Element, Nextcloud, regional gateways and application recovery remain absent. See [profile instructions](deployment-profiles.md) for the supported operator workflow.

## Guided/local installation milestone evidence

The final full local check on 2026-09-25 passed **184 tests**, syntax checks for **16 playbooks**, invalid public-example rejection, and infrastructure-only/independent/join host and task listings. The new infrastructure entry point manages only the controller and relay. Planned local nodes are enrollment declarations, never remote SSH targets.

Review regressions cover malformed registration URLs leaking private text, redirected enrollment output, and final-review back/save controls. Each regression failed before its fix and passed afterward. Registration flags were checked against the locally cached pinned Tailscale v1.102.4 source. No client was installed or started on the developer Mac and no host networking was changed.

Shared schema-version-1 validators, Ansible guards and templates retain their original regression coverage. New tests exercise schema separation and normalized infrastructure policy; existing localhost Ansible tests cover shared template rendering. No second independent reviewer was used. Private bundle checksums indicate completeness and file integrity, not publisher authenticity.

Read the [operator guide](guided-setup.md) and [live acceptance checklist](local-install-acceptance.md). Ubuntu package/service execution, real approval, NAT traversal, rerun/reboot behaviour, outage recovery and beginner usability remain **NOT RUN**. The initial public source publication does not add live deployment evidence. DNS, certificates and relay artifact preparation still require operator work.

## Publication check

Before the initial public source upload, the local check suite was rerun: 184 tests and all 16 playbook syntax checks passed. Live tests were deferred at the project owner's request. Only source, public examples and documentation are included; generated inventories, certificates, build artifacts, caches and execution logs are excluded. Historical planning documents describe their original phase and do not change current support boundaries.

## Unified operations milestone

The common `rdc` launcher, menu, infrastructure/node commands, doctor, private support reports and source identity are implemented. The local suite passes **245 tests** and syntax checks for **16 playbooks**. The infrastructure and original profile task/host listings pass without target connections. The complete suite also passed from a clean tracked-source export with a fresh dependency environment. Only the three expected dynamic-group warnings remain.

Review added regression coverage for noninteractive status, exact runtime node name, pending-enrollment visibility, malformed runtime data and absent project-local Ansible runtime directories. No client was installed or started on the developer computer. No production infrastructure was contacted.

The read-only GitHub Local checks workflow is configured with reviewed immutable action pins and an Ubuntu 24.04 / Python 3.12 runner. Consult the actual pull-request checks for hosted execution results; workflow configuration alone is not a passing CI run. See [operations](operations.md) for the command and exit-code contract.

Certificate issuance/renewal, verified binary distribution, managed upgrades, application services and live acceptance remain outside this increment. No automatic release or main-branch merge is included.

## Verified-release increment (2026-09-25)

The release downloader rejects source/publisher mismatches, failed attestations, corrupt hashes, missing/unexpected files and unsafe filesystem entries. The relay cross-build and dependency-license collection ran locally. These checks do not yet constitute verification of a published artifact; that requires the tagged GitHub release workflow followed by an actual download and attestation check. The release remains experimental and does not alter the unperformed deployment/recovery acceptance tests above.

Verified release evidence: [v0.2.0-alpha.1](https://github.com/kollanekirss/resilient-datacenter/releases/tag/v0.2.0-alpha.1) was built and attested by [run 36123391525](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36123391525), then downloaded using `rdc release fetch` and verified against source commit `f6bff457bf2d925d24e39fea6301ca7f96c6bc50`. No downloaded program was executed on the developer computer.

Managed certificate lifecycle: [disposable Ubuntu run 36124194530](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36124194530) passed initial trusted TLS, certificate replacement and injected restart-failure rollback for actual Headscale 0.29.4 and DERP 1.102.4 services. Public ACME issuance and real operator infrastructure remain untested.

## Backup and fenced recovery increment

Local checks pass **354 tests**, including consistent snapshot capture, component identity, strict backup contracts, private restore staging, interruption journals, rollback and the no-rollback-after-commit boundary. The disposable [encrypted transport run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36127299422) passed with actual pinned Restic 0.19.1 and a restricted SSH/SFTP target. It checks exact restored bytes, encrypted storage, rejection of the wrong repository password and actual SSH rejection of a different pinned host key. Its synthetic overlay address is assigned only inside the disposable runner; it does not prove VPN routing or physical offsite storage.

The [real controller and relay recovery run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36127299427) passed for both pinned services. It captures service data, promotes a snapshot while isolated, retains the current certificate, verifies the real HTTPS service, rolls back an injected validation failure, blocks service startup after interruption and recovers using the journal. This evidence is service-level recovery in a disposable Ubuntu runner. Real enrolled client recovery, independent fencing, public DNS changes, physical outages and end-user operations remain **NOT RUN**.

No application backup, automatic retention, unattended update, storage immutability or zero-downtime recovery is claimed. Follow the [backup guide](backups.md) for the supported commands and topology limits. Later changes must retain passing checks; consult the current commit's CI rather than treating this historical result as proof of untested changes.

The strengthened [recovery run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36127740610) verifies actual non-loopback ingress denial during isolation and restored Headscale user records. It caught an nftables command that created a table without its nested rules; the runtime now uses explicit commands in one atomic batch and checks the installed rule structure. Local checks subsequently pass **356 tests** and all **16 playbook syntax checks**. Backup timestamps now represent quiesced data capture, not the later upload start.

## Opt-in scheduled-backup increment

The installed systemd backup entry point passed against the actual controller and encrypted SFTP storage in the [disposable scheduler run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36128533462). It verifies successful capture/upload, a failed attempt preserving the last success, and a successful retry. The timer executes a root-managed code copy and performs no automatic upgrades or pruning. Physical offsite operation and alert delivery are not established by this test.

Subsequent local checks pass **362 tests** and all **16 playbook syntax checks**, including overdue exit status and graceful termination that runs cleanup. Combining recovery and scheduling also added rejection of an existing shared recovery-journal parent. Actual scheduled runs use the same serialized backup path and refuse a pending restore.


## Matrix/Element application increment (development source)

The [application and issuer run 36133719119](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36133719119) passed actual pinned PostgreSQL, Synapse, Element and Caddy startup; trusted HTTPS; local account creation and login; private-room denial before invitation; message and media operations; and blocked external administration/federation routes. Enforced AppArmor remained active on all four containers.

The same run exercised a frozen scheduled backup against real restricted SFTP storage, network-to-application backup scope transition, selected snapshot restoration, preserved credentials/sessions/media/signing identity, certificate activation/rollback and repeated installation. Actual Chromium verified Element login, restored chat history and sending. A fresh browser recovered encrypted history using an independently held recovery key; the server-held event remained encrypted. No recovery key was printed to CI output.

The installed certificate timer activated a new trusted leaf and reported a simulated provider outage while retaining current HTTPS. DNS/provider/ACME issuance was simulated at the external boundary. It has not been demonstrated against an operator's real provider account.

The [controller run 36133848306](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36133848306) accepted the guided HTTPS and backup grants through the actual pinned Headscale policy parser. This proves syntax/controller acceptance, not VPN packet enforcement. Local checks at this increment pass 415 tests; the 16 playbook syntax checks also passed.

An intermittent restart failure in runs 36132971329 and 36135765895 occurred while inspecting a container after shutdown. The runtime now retains stopped containers and explicitly validates/removes them before launch, eliminating competing automatic removal. The [updated runtime run 36137009834](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36137009834) passed 20 consecutive verified proxy restarts, ten real failed TLS activations with recovery of the previous live certificate, and the complete application/browser/backup/issuer suite. Its restore service verification took 12.76 seconds in this fixture; this is not a site-recovery guarantee.

These fixtures do not demonstrate real VPN enrollment, home NAT, physical site separation, Nextcloud, regional gateways or beginner acceptance. The older network-only statements above describe their historical increments.


## Nextcloud application increment (development source)

The [file-service run 36137540936](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36137540936) passed real pinned Nextcloud 35.0.1, PostgreSQL and Caddy with enforced container confinement, trusted HTTPS, two accounts, exact uploaded/downloaded bytes, another user's access denial, approved local sharing and revocation, background jobs and repeat installation. It also rejects an outgoing unapproved federated share.

The installed scheduled backup entry point captured the database, instance credentials and files into encrypted restricted SFTP storage. Fenced restoration recovered original bytes and account access, removed files created after the selected snapshot, preserved the instance identity and changed the client recovery fingerprint. Promotion and service verification took 52.88 seconds in this disposable fixture; that excludes replacement provisioning and snapshot download, and is not a site-recovery guarantee. A Chromium browser then logged in and displayed the restored file.

Actual TLS activation failure restored the previous live certificate. The frozen certificate timer installed a new trusted leaf and retained it during simulated provider failure. Public DNS/ACME issuance, real VPN/home NAT, physical offsite placement, controlled upgrades, regional sharing and colleague acceptance remain NOT RUN.

Review additionally corrected the effective public-link setting and removed bootstrap credentials before making the pinned code tree readable. The [final file-service run 36138208645](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36138208645) passed the expanded acceptance suite, including public-link creation denial. Earlier runs are not evidence for that assertion. Local checks pass 438 tests and all 16 playbook syntax checks.

### Regional gateway transport boundary (development branch)

The disposable [gateway boundary run 36140820264](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36140820264) passed with the pinned Envoy image and real Linux network namespaces/nftables: trusted upstream TLS, restricted Matrix federation paths, blocked client/admin routes, denied unapproved peer/source/destination, and revocation/expiry stopping already-open streams in both directions. Namespace links are explicit transport fixtures, not real Tailscale memberships. This does not establish Matrix room federation, Nextcloud federation, gateway installation/recovery, or a supported regional journey. Gateway lifecycle acceptance is being added separately.

The later [gateway lifecycle run 36141569056](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36141569056) also passed actual local installation, a hash-checked frozen runtime, repeated installation, systemd restart, interrupted revocation, closed restart, explicit resume and replay denial. Its VPN status is an explicit synthetic fixture. This adds local lifecycle evidence, not real Headscale or application federation acceptance.


## Regional gateway development evidence

The [gateway guard run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36144496279) passed actual Envoy/nftables/systemd installation, restricted destinations and routes, interruption recovery, revocation of existing streams, expiry, backward-clock closure and periodic detection of abandoned changes. Its VPN facts are explicitly synthetic.

The [independent network run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36143267057) separately passed three actual Headscale authorities and seven single-membership Tailscale clients, including overlapping institutional address ranges without cross-controller peer visibility. The [Matrix package run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36144496260) passed actual restricted LAN connector activation and persistent suspension after restoration, alongside internal application/browser/recovery acceptance.

The [actual regional Matrix run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36145734658) passed cross-institution room invitation/join and messages in both directions through real independent networks and restricted gateways. It denied an admitted but unapproved regional node and client/admin routes, blocked new event delivery after transport revocation, preserved already delivered messages, and verified local chat in both institutions after regional controller/gateway shutdown. The discovery failure in earlier runs was fixed by using the complete system CA trust store; TLS verification remains enabled.

This establishes the tested Matrix API exchange, not encrypted cross-institution browser recovery. Nextcloud federation, gateway certificate renewal and gateway-specific recovery remain unfinished. Physical sites, home NAT, public provider issuance and beginner acceptance remain untested; the complete regional product journey is not yet supported.

The [Nextcloud connector and recovery run](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36149242378), at `f9b2238`, passed native attachment after injected validation failure, exact LAN source/path restrictions, encrypted snapshot restoration with persistent connector suspension, browser login and restored file visibility, and real TLS activation rollback. Its installed frozen renewal timer also passed replacement and simulated provider failure. Restore promotion/service verification took 59.15 seconds in that disposable fixture, excluding provisioning and download. The browser regression was a typed-string configuration write incompatible with Nextcloud's boolean sidebar reader; the compatible settings interface corrected it. Later sharing changes still require their own passing native runs.

Regional file exchange at `e1b9dec` passed disposable run [36150800731](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36150800731): three actual Headscale authorities, seven distinct single-membership clients, internal Nextcloud upload, bilateral share creation, explicit recipient acceptance and exact bytes read. Unrelated DAV/admin routes, an unapproved regional node and unsigned OCM requests were denied. Share revocation blocked access; partnership revocation blocked subsequently created content. Both institutions retained internal file operations after regional controller/gateway loss. This remains a candidate route catalogue pending additional application-client destination and escaped-path denial checks; it does not establish physical-site, home-NAT or beginner acceptance.

Expanded file acceptance at `ebab6cf` passed [36151160141](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36151160141), including Nextcloud's actual HTTP client denying unknown destinations, alternate ports, HTTP fallback and literal regional/private/loopback addresses while the approved HTTPS peer succeeds. Escaped and traversing paths did not reach administration routes. The default gateway catalogue is consequently enabled for the two reviewed application protocols; each deployment still requires its own exchange check.

Nextcloud lifecycle at `e1b9dec` passed [36150800696](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36150800696): forced background-job activation during actual systemd shutdown no longer cancels the stop, failed connector activation resumes internal service, current attachment survives repeat installation, encrypted restore preserves accounts/files and suspends partner access, browser login succeeds, and certificate replacement/provider-failure recovery remain verified. The timer race was observed in run36149617436; its `Requisite` verification job is removed while the fixed cron runner retains the application lock and owned-running-container check.

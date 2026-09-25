# Detailed implementation plan: institutional server connectivity pilot

**Audience:** technical colleagues and the pilot sponsor.
**Prepared:** 24 September 2026.
**Status:** planning only. Servers, automation, domain names and live test results do not exist yet as deliverables of this project. The steps below describe the work to perform.

## Pilot objective and boundaries

Connect two institutional Linux servers through a self-hosted Headscale network. Prove controlled enrollment, encrypted application access and private relay fallback, then document restart and recovery behaviour.

This is the first networking milestone. Application federation, replicated storage, SSO integration, automatic controller failover and physical site relocation come later. Network connectivity alone proves none of those capabilities.

Use four VPSs:

| Name | Function | Software |
|---|---|---|
| control-01 | Membership, discovery and access-policy coordination | Headscale |
| relay-01 | Encrypted relay when direct peer connectivity is unavailable | DERP with STUN |
| server-a | Institution A test endpoint | Tailscale client and HTTPS test service |
| server-b | Institution B test endpoint | Tailscale client and HTTPS test service |

Choose Ubuntu Server 24.04 LTS, initially amd64, as the proposed common target. Verify compatibility with the exact package releases before installation. Proxmox is not needed on these VPSs. Use an administrator workstation to run Ansible over management SSH.

One person can hold several responsibilities, but record a name for each: sponsor, technical lead, infrastructure operator, security reviewer and test owner.

## Sequence

Steps 1–5 prepare the project without live servers. Steps 6–8 create and configure the lab. Steps 9–11 collect evidence and decide whether to expand. Do not skip the checks at the end of each step.

## 1. Agree what we are building and who owns it

**Owner:** sponsor and technical lead. **Prerequisite:** participating colleagues agree to explore the pilot.

### 1.1 Write the use case

Record this first use case: “Server A can call an approved HTTPS service on server B, and vice versa, without exposing that service to the public internet.” Identify why each institution needs the connection and who owns each endpoint.

### 1.2 Define the scope

Include four VPS roles, one test service per peer, explicit access rules, deployment automation and a recovery exercise. Exclude real institutional records, public user onboarding and production service commitments. Use synthetic responses such as a server name and test identifier.

### 1.3 Assign people and access

Name the person who can approve cost, the person who can administer hosting/DNS, the developer maintaining automation, and the reviewer checking results. Document who may enroll a server, change policy and retrieve backups. Agree a method for contacting the operator during an outage exercise.

### 1.4 Define success before implementation

Agree that completion requires all of the following: permitted requests work in both directions, unapproved requests fail against a known working listener, private DERP fallback is observed, identities survive client restarts, and a controller backup can be restored. Keep “automation passes syntax checks” separate from “the deployed network works.”

### 1.5 Set spending and cleanup ownership

Set a maximum authorised pilot spend, a billing owner and a date to review whether the machines are still needed. Record who will remove temporary VMs, test credentials and backups when the pilot ends. Do not commit to a delivery date until the team has assessed the work.

### 1.6 Create the decision record

Store scope, owners, agreed tests, budget authority and exclusions in `docs/pilot-charter.md` in the future repository. Use names rather than leaving roles unassigned.

**Deliverable:** a pilot charter. **Check:** a colleague can explain the intended outcome and what it does not yet cover. **If incomplete:** resolve ownership and scope before buying infrastructure.

## 2. Create the shared repository and working environment

**Owner:** technical lead. **Prerequisite:** the charter names the repository owner.

### 2.1 Choose where the project lives

Use an approved GitHub organisation or another institutional Git service. Agree private/public visibility. Invite colleagues individually. Give write access only to contributors who need it. The choice of repository and its creation are future team actions, not actions performed by this document.

### 2.2 Create the project layout

Prepare these directories and explain each in the README:

```text
inventories/example/    Nonsecret four-host example
playbooks/              Entry points for each deployment stage
roles/controller/       Headscale configuration
roles/relay/            DERP configuration
roles/client/           Tailscale installation
roles/test_service/     Overlay-only HTTPS endpoints
policies/               Access-policy templates
scripts/                Local input and configuration checks
tests/                  Automated tests
docs/                   Installation, networking, tests and recovery
```

This tree is a proposed structure, not a claim that these files are already implemented.

### 2.3 Define the change workflow

Work on short-lived branches. Describe what a change does, how it was checked and any deployment consequences. Require a colleague to review access-policy changes. Record a Git commit or release tag for every live deployment so the operator can identify exactly what is running.

### 2.4 Keep deployment secrets out of the repository

Ignore real inventory directories, private keys, certificate private keys, enrollment credentials, local environments and captured logs. Keep public example configuration separately. Choose the team's approved secret store. If a credential enters Git history, revoke or rotate it; deleting the current file alone is insufficient.

### 2.5 Prepare the administrator workstation

Select a supported Python version for the pinned Ansible release. Create a project virtual environment and install pinned dependencies there. Keep SSH host-key verification enabled. Record OS and tool versions. Do not install Headscale or alter workstation routing for this pilot.

### 2.6 Create one issue per work package

Create issues for inventory validation, controller installation, relay installation, client enrollment, test service, verification and recovery. Each issue must name an owner and its acceptance evidence. Link issues to the relevant sections below.

**Deliverable:** a reviewable repository with a README and reproducible local tooling. **Check:** another colleague can obtain the project and run its documented local checks. **If incomplete:** fix setup documentation before adding remote deployment steps.

## 3. Specify identities, networking and permitted traffic

**Owner:** technical lead and security reviewer. **Prerequisite:** the four roles are agreed.

### 3.1 Create the machine inventory schema

For each machine record its role, hostname, provider, region, OS, architecture, management address, SSH user, SSH key reference and owner. Leave unknown values explicitly unset in the example. The validator must reject deployment with unset or documentation-only values.

### 3.2 Separate management and application paths

Ansible and emergency SSH use the management path. Application requests use the overlay. Keep provider console access available independently of Headscale. Neither institution gets SSH access to the other institution merely by joining the network.

### 3.3 Choose names and DNS ownership

Choose controller and relay fully qualified domain names under a domain the team controls. Assign an owner who can create and update records. Use unique peer names. The controller and relay names must resolve and be reachable before an endpoint joins the overlay.

### 3.4 Check addresses for overlap

List existing LAN, VPN and provider-private address ranges. Compare them against the intended overlay allocation. Resolve conflicts before deployment. Never assume that a provider-private address is reachable across providers. Do not preassign overlay addresses that the controller has not actually allocated.

### 3.5 Agree the access matrix

| Source | Destination | Protocol/port | Decision |
|---|---|---|---|
| server-a | server-b | TCP 8443 | Allow test application |
| server-b | server-a | TCP 8443 | Allow test application |
| server-a/server-b | Other peer services | Other new connections | Deny unless separately approved |
| Approved administrator | Management interfaces | SSH as documented | Restrict by management design |
| Enrolling peers | Controller | HTTPS/TCP 443 | Allow bootstrap |
| Peers | Relay | HTTPS/TCP 443 and STUN/UDP 3478 | Allow relay operation |

Direct peer transport also needs appropriate UDP reachability. Document its chosen configuration separately from the application ports. The table is not a complete provider firewall rule set.

### 3.6 Define server identity and enrollment authority

Assign `tag:institution-a-server` and `tag:institution-b-server`. Identify which administrator may assign each tag. Choose administrator-approved enrollment for the first run. Later automation may use narrowly scoped, short-lived, single-use credentials. Document enrollment credential expiry separately from node-key expiry.

### 3.7 Choose the TLS procedure

Require trusted HTTPS for the controller, relay and test application. Decide how public certificates are issued and renewed. For private test endpoints, a dedicated lab CA is acceptable if both peers explicitly trust it and verify endpoint names. Keep its signing key off the service VMs. Document certificate renewal and service reload ownership.

### 3.8 Define relay and controller-outage behaviour

Use only the private relay map for the private-relay acceptance test. Decide whether other operating profiles may use public relays. If DERP admission calls the controller, choose explicit fail-closed behaviour for this pilot and record that fresh relay admissions may fail while the controller is unavailable. Existing sessions and new admissions are separate test cases.

**Deliverable:** inventory schema, access matrix, DNS/TLS plan and public-port list. **Check:** every open path has a purpose and an owner. **If incomplete:** do not compensate with an allow-all policy.

## 4. Build each part of the deployment automation

**Owner:** technical lead. **Prerequisite:** the network and identity decisions above have been reviewed.

### 4.1 Lock the software inputs

Select exact stable versions of Headscale and Tailscale, the DERP source/build and local automation dependencies. Record artifact URLs, checksums and the source of each checksum. Obtain configuration examples from the selected release, not an unrelated latest development branch. If compiling DERP, record the exact source version and build toolchain.

### 4.2 Implement the inventory validator

Check required role counts, unique machine identities, usable management addresses, valid names, required certificate references and complete version/checksum fields. Reject sample values in deployment mode. Validate inputs before making remote changes. Error messages should identify the field without displaying passwords or private keys.

### 4.3 Implement read-only remote preflight

Check SSH access, sudo privileges, OS, architecture, disk availability, system time and required executable support. Check existing service ownership and occupied ports. Refuse to overwrite an unrelated existing Headscale deployment or repoint an enrolled client without an explicit migration procedure. Preflight must not modify firewall rules or restart services.

### 4.4 Implement the controller role

Install the verified package. Ensure configuration and explicit policy exist before the service admits enrolled nodes. Configure HTTPS, persistent database/key paths, the relay map and restricted diagnostic endpoints. Validate configuration before restart. Preserve existing managed state on reruns. Stage changed files so invalid configuration does not replace the last known working set.

### 4.5 Implement the relay role

Install the verified DERP binary as a managed system service with the minimum privileges required by its listeners. Install certificate material with restricted permissions. Configure the public hostname, STUN and the chosen client-verification behaviour. Keep log output free of credentials. Confirm startup and required listeners after changes.

### 4.6 Implement the client role

Install the pinned Tailscale client and start its service. Preserve its state directory. Do not enroll, log out or reset identity automatically on every deployment. Do not enable subnet routing, exit nodes or Tailscale SSH. If a client already belongs to a different coordination service, stop with a clear diagnostic.

### 4.7 Implement enrollment as a separate operator procedure

Document the user creation, tag ownership, client login request and administrator approval sequence for the selected release. Explain how to identify the requesting machine before approval and how to revoke/remove it later. Enrollment should leave a record of node name, tag and operator, without committing transient credentials.

### 4.8 Implement the HTTPS test service

Return a small fixed response identifying `server-a` or `server-b`. Run as an unprivileged service. Bind to the discovered overlay address on TCP 8443, not every public interface. Refuse to start if the required address or valid certificate is missing. Make startup/restart behaviour explicit when the overlay takes time to become available.

### 4.9 Implement verification and result reporting

Check application identity, TLS validation and expected access. Record `pass`, `fail` or `not-run`, with versions and timestamps. Keep diagnostic path observations separate from application results. Verification must not silently broaden permissions or apply disruptive fault injection.

### 4.10 Add operator documentation alongside the code

Document each playbook's inputs, changes, failure behaviour and recovery action. Explain what happens on the second run. Document certificate rotation, log inspection and package updates. Provide a sample inventory that is harmless and deliberately rejected for live deployment until completed.

**Deliverable:** runnable automation and operator documentation. **Check:** code review confirms the automation follows the agreed scope and preserves identities. **If incomplete:** fix the role that owns the failure; do not bypass validation to continue.

## 5. Validate the kit without servers

**Owner:** technical lead and test owner. **Prerequisite:** the relevant automation exists.

### 5.1 Run language and playbook checks

Run Python tests, YAML parsing and Ansible syntax checks using a nonsecret fixture inventory. These are future project commands once the named files and dependency environment exist:

```bash
python -m pytest
ansible-playbook -i inventories/example/hosts.yml playbooks/preflight.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/deploy.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/test-services.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/verify.yml --syntax-check
```

### 5.2 Exercise invalid inputs

Test a missing role, repeated address, unknown architecture, empty domain, absent certificate, missing checksum and client assigned both institutional tags. Each case should stop with an understandable message. Ensure unit-test fixtures cannot accidentally become live deployment inventory.

### 5.3 Render and inspect access policy

Confirm both intended TCP 8443 directions exist and that no wildcard or accidental administrative grant widens access. Confirm the service actually references this policy file. An empty JSON object is not a deny-all Headscale policy. Where possible, run the selected Headscale release's own policy/configuration validation; otherwise record that check as pending.

### 5.4 Review service and secret handling

Inspect permissions, systemd commands, certificate paths and listener addresses. Check that secrets do not appear in task output, rendered public examples or tracked files. Verify that state directories are never deleted as part of normal deployment.

### 5.5 Exercise the verification logic

Test incorrect server response, TLS failure, timeout, absent negative-test listener and missing path evidence. Those must fail or remain inconclusive, not pass. Confirm that offline validation cannot mark a live connectivity test as passed.

### 5.6 Record a candidate release

Record the Git commit, dependency versions, checks performed, results and remaining live tests. Ask a colleague to repeat the local setup from the README. Correct any undocumented assumptions.

**Deliverable:** a locally checked candidate and a validation record. **Check:** all applicable offline tests pass. **If incomplete:** keep live deployment blocked on the specific failed check. A local pass does not certify Ubuntu installation or network operation.

## 6. Obtain and prepare the four VPSs

**Owner:** infrastructure operator. **Prerequisite:** authorised cost, candidate release and DNS ownership.

### 6.1 Choose hosting placement

Put server-a and server-b in different regions, preferably different providers. Place the coordinator and relay independently where practical. Record provider, region and any known shared dependencies. Four VMs in one physical facility do not demonstrate geographic resilience.

### 6.2 Create the machines

Use clean images of the agreed OS and architecture. Give each machine its agreed hostname. Record public IPv4, working IPv6 if used, provider ID, billing owner and console link. Take note of transfer allowances for relay traffic.

### 6.3 Establish management access

Create named administrator accounts with SSH keys and the required sudo access. Verify SSH host keys through a trusted provider-console channel. Test a second session before tightening management rules. Confirm recovery-console access works before relying on it.

### 6.4 Apply basic OS maintenance

Install required security updates, reboot when required and check system time. Record resulting OS/kernel state. Inspect existing listeners so an unexpected web server or agent does not conflict with the proposed services.

### 6.5 Apply the reviewed provider firewall rules

Allow management SSH only through the agreed management paths. Permit the required controller/relay traffic and direct peer transport. Keep test-service public ports closed. Account for IPv6 as well as IPv4. Do not expose metrics or debug ports because an example configuration happens to mention them.

### 6.6 Create and verify DNS

Create controller and relay records pointing at their real public addresses. Publish an IPv6 record only if that path works. Check resolution from the administrator workstation and both peers. A record visible in the DNS management page is not sufficient evidence of external resolution.

### 6.7 Issue and install certificate inputs

Obtain certificates using the chosen procedure. Verify hostname coverage, expiry, trust chain and private-key pairing. Securely deliver key material. Record renewal owners and expiry dates. Do not copy the lab CA signing key to all four VPSs.

### 6.8 Fill in real inventory and run preflight

Store the actual inventory outside tracked examples. Confirm role/address mapping together with a second person. Run local validation and read-only remote preflight. Save the redacted report.

**Deliverable:** four prepared targets with working bootstrap connectivity. **Check:** preflight succeeds on every role. **If incomplete:** repair DNS, TLS, SSH, OS or firewall prerequisites before starting application deployment.

## 7. Deploy Headscale and the independent relay

**Owner:** technical lead and infrastructure operator. **Prerequisite:** successful preflight.

### 7.1 Freeze the candidate inputs

Record the exact repository commit, manifest and inventory revision. Keep a secure copy of the intended configuration. Confirm nobody is simultaneously editing the same running services.

### 7.2 Deploy the controller first

Run the controller role. Inspect the generated configuration and explicit grants before enrolling peers. Check service status, logs, file ownership and persistent state paths. Confirm the controller listens on the expected HTTPS endpoint and diagnostic services remain private.

### 7.3 Verify bootstrap TLS externally

From the peers, verify controller DNS and the HTTPS certificate. Confirm that the check succeeds without disabling TLS verification. Correct time, DNS, trust-chain or hostname errors at this stage rather than blaming enrollment later.

### 7.4 Deploy the relay

Run the independent relay role. Confirm HTTPS and STUN listeners and readable certificates. Verify the chosen client-admission setting and the controller URL it depends on. If admission is fail-closed, record that behaviour in the outage test sheet.

### 7.5 Apply the private relay map

Configure Headscale to distribute the intended region and relay hostname. For private-relay testing, remove default public fallback from that test profile. Validate and reload the map using the selected release's supported procedure.

### 7.6 Check restart behaviour

Restart each service separately while no application traffic depends on it. Confirm it starts with the same configuration and persistent state. Save redacted logs and the installed versions.

**Deliverable:** running coordination and relay services. **Check:** the public bootstrap endpoints work and the intended policy/map are loaded. **If incomplete:** inspect configuration validation and service logs, then restore the last valid configuration. Do not enroll peers into an unverified permissive policy.

## 8. Enroll both servers and install test services

**Owner:** infrastructure operator and enrollment administrator. **Prerequisite:** coordinator, relay and access policy checks passed.

### 8.1 Install the clients without resetting identity

Run the client role on server-a and server-b. Inspect client state first. If either is already enrolled elsewhere, stop and agree a migration or use a clean test machine. Do not copy a working client's identity to save setup time.

### 8.2 Create the enrollment administrator

On the controller, create the agreed lab administrator identity and confirm that policy allows that identity to assign the intended tags. Current stable documentation uses `headscale users create` and tag ownership in policy. Verify commands against the selected version.

### 8.3 Initiate and approve server A

From server-a, initiate login against the actual controller URL while advertising only Institution A's tag. Review the generated registration request on the controller and approve it for the designated administrator. Confirm hostname, requesting machine and assigned tag before approval.

### 8.4 Repeat independently for server B

Enroll server-b using only Institution B's tag. Do not reuse a copied client-state directory or a single shared machine identity. Record the two controller node entries and actual overlay addresses.

### 8.5 Inspect the distributed network configuration

Check peer visibility, the selected coordination service and the received relay map. Confirm no unexpected exit-node or subnet-route settings. Record node-key expiry policy so later outages are interpreted correctly.

### 8.6 Configure test-service certificates and name resolution

Give each test endpoint a distinct DNS name covered by its certificate. Configure an explicit test resolver mapping or a validated internal DNS mechanism to the actual overlay address. The application test must connect to the overlay while validating the expected service hostname. Do not disable certificate verification to avoid configuring names correctly.

### 8.7 Deploy each HTTPS endpoint

Bind the service to its own overlay address on TCP 8443. Start it and verify its identifying response locally. Confirm it is not listening on a wildcard public address. If the overlay is unavailable, startup should fail safely or wait for the address, never fall back to public binding.

### 8.8 Make the first cross-server requests

A retrieves B's expected response and B retrieves A's. Verify certificate trust and hostname, response identity and port. Record results before starting fault injection.

**Deliverable:** two uniquely enrolled servers and working permitted application requests. **Check:** requests succeed in both directions with TLS verification. **If incomplete:** check in order: local listener, certificate/name, overlay state, effective tags/policy, then network path.

## 9. Verify security boundaries and path selection

**Owner:** test owner and security reviewer. **Prerequisite:** baseline cross-server requests succeed.

### 9.1 Open a test record

Assign an ID and record date, operator, Git commit, installed versions, nodes, expected result and cleanup procedure. Use `pass`, `fail` or `not-run`. Record the cause when a test is inconclusive.

### 9.2 Recheck allowed traffic

Send requests in both directions. Confirm the expected server identity and validated TLS. Retain response status and a nonsecret sample. A successful TCP connection alone is weaker evidence than the actual expected response.

### 9.3 Test a denied connection against a real listener

Start a temporary controlled listener on the overlay address at TCP 8444 on B. Confirm it responds locally at that address. Check that host/provider rules are not independently causing the intended overlay-policy denial; otherwise record only end-to-end denial, not proof of which layer enforced it. Attempt A-to-B access and require failure. Confirm approved TCP 8443 still works as a control. Repeat B-to-A and remove both temporary listeners.

### 9.4 Check public exposure

From a machine outside the overlay, test each peer's public addresses at the application and temporary test ports. Check IPv4 and IPv6 if configured. Verify service bindings locally. Do not use a host inside the same private overlay as the only evidence of public isolation.

### 9.5 Record a direct path

Use client diagnostics to observe whether the current peer path is direct. Send a real application request and record the observation. If the provider topology prevents a direct path, report that condition; do not relabel a relayed request as direct.

### 9.6 Force the private relay path in a controlled experiment

Prepare narrowly scoped temporary rules that prevent direct peer transport while preserving management SSH, controller HTTPS and relay HTTPS/STUN. Keep console access and a timed rollback mechanism. Apply them only to the test machines and only during the agreed window. Confirm the client selects the configured private relay and repeat application requests. Capture the actual relay identity. Restore the temporary rules and verify normal connectivity returns.

### 9.7 Rerun automation

Run the ordinary deployment again with identical inputs. Compare node identities, policy and persistent controller state. Investigate unnecessary restarts or repeated changes. The run must not create duplicate nodes, replace keys or require fresh enrollment.

### 9.8 Clean up and review evidence

Remove temporary listeners, firewall rules and test credentials. Verify SSH, controller health and baseline application access. Have the reviewer check that failed requests were not merely certificate errors or dead listeners and that relay traffic genuinely used the private endpoint.

**Deliverable:** access-control and transport evidence. **Check:** expected results reproduce without weakening policy. **If incomplete:** fix the implicated layer and repeat the failed test plus its control cases.

## 10. Exercise outages, backup and restoration

**Owner:** infrastructure operator and test owner. **Prerequisite:** baseline tests pass, console access works and each experiment has a recovery action.

### 10.1 Prepare a reversible test window

Notify the team, confirm nobody relies on the lab and assign one operator to restore services. Record baseline connectivity. Run one disruption at a time so causes remain distinguishable.

### 10.2 Stop Headscale and separate the observations

With baseline peer traffic active, stop the controller. Check existing application traffic, a new application connection between enrolled peers and a new enrollment attempt separately. If DERP admission checks depend on Headscale, test a fresh relay connection separately too. Record results and duration. Restart the controller and verify recovery. Do not extrapolate a short test into indefinite operation without key refresh or revocation.

### 10.3 Stop the single relay

First observe traffic with an available direct path. Then, in a separate controlled test, observe what happens when direct connectivity is unavailable. Relay-dependent access is expected to fail when the sole relay is down. Restart it and restore temporary network restrictions. This is a failure-boundary test, not a redundant-relay failover demonstration.

### 10.4 Restart each peer

Restart A, verify the same identity and test-service recovery, then repeat for B. Record time from restart to successful application request. Identify any certificate, service ordering or overlay-address dependency that prevents recovery.

### 10.5 Create a consistent controller backup

Document the actual database, keys, policy, service configuration and TLS/recovery material in use. For the lab, briefly stop Headscale before copying persistent state, or use a verified database-consistent backup mechanism. Include SQLite auxiliary state where relevant to the selected method. Restart the service promptly and confirm health. Encrypt the backup and store it outside the controller, with separately controlled access and a checksum.

### 10.6 Restore into an isolated environment

Use a temporary isolated VM or schedule a controlled replacement of the lab controller. Confirm which original instance is stopped and prevented from returning. Restore the selected software version, files, permissions and service configuration. Validate state before making the recovery endpoint reachable. Never allow two independent active controllers to use the same restored identity simultaneously.

### 10.7 Verify the restored service

Check expected node entries, tags and policy. In a controlled cutover, verify existing clients can use the recovered controller without unintended duplicate enrollment. Check permitted/denied application traffic again. Record what data and configuration were actually recovered and any loss since the backup.

### 10.8 Record recovery limitations

Record backup age, measured recovery duration, operator actions and remaining uncertainties. Distinguish a successful manual restore from automatic failover. Clean up isolated recovery VMs and temporary copies of private material after retaining the approved backup.

**Deliverable:** outage report and a tested recovery procedure. **Check:** a colleague can repeat recovery with the documented materials. **If incomplete:** keep the recovery criterion failed and retain the working lab state while correcting the procedure.

## 11. Hand over the pilot and decide what follows

**Owner:** sponsor, technical lead and reviewer. **Prerequisite:** test and recovery records exist, including failures.

### 11.1 Assemble the evidence package

Include topology, actual placements, software manifest, deployment commit, redacted inventory, access matrix, installation guide, test results, known limitations and recovery instructions. Keep passwords and private keys in the approved secret store, not in the report.

### 11.2 Perform a colleague handover test

Ask someone who did not write the automation to follow the README and explain the running system. Have them execute a read-only health check and identify how to restore controller access. Record and fix instructions that rely on undocumented knowledge.

### 11.3 Review operating effort and cost

Record actual hosting and traffic charges, time spent maintaining the lab, certificate renewals and backup tasks. Assign ongoing owners and an update cadence. Decide whether the existing deployment is maintainable by the participating institutions.

### 11.4 Compare results with the original acceptance criteria

List each criterion as passed, failed or not tested. Explain observed controller and relay failure boundaries. Avoid replacing the agreed criteria with easier ones after seeing the results.

### 11.5 Choose the next work package

If core connectivity is reliable, add a second independent relay and test relay loss with direct paths blocked. Next, design controller recovery/availability. Then add one application, with its own identity, backup and restore design. Add site-level replication and relocation tests only after application recovery works.

### 11.6 Publish a release or close the experiment

Tag the tested repository commit, document supported combinations and keep the test evidence with the release. If the team stops, export approved documents/backups, revoke pilot credentials and remove billable resources. Record the decision and its owner.

**Deliverable:** a pilot review and a decision with named follow-up owners. **Check:** claims made to institutional stakeholders match demonstrated behaviour.

## Practical checklists to copy into the team's task board

### Before live deployment

- [ ] Scope and named owners agreed.
- [ ] Repository and secret storage established.
- [ ] Software versions and artifact provenance recorded.
- [ ] Explicit policy and tag ownership reviewed.
- [ ] DNS, TLS and renewal method documented.
- [ ] Local tests pass; live tests remain marked not-run.
- [ ] VPS budget and hosting placement approved.
- [ ] Console access, SSH and preflight work on all four hosts.

### Before calling the pilot successful

- [ ] Validated HTTPS test requests succeed both ways.
- [ ] Denied-port tests use known working listeners and positive controls.
- [ ] Application services are not unintentionally public.
- [ ] Direct-path behaviour is recorded.
- [ ] The private DERP path is demonstrated.
- [ ] Restarts and repeated deployment preserve identity.
- [ ] Controller and relay interruption behaviour is recorded.
- [ ] Backup restoration is demonstrated.
- [ ] A colleague can follow the operational documentation.
- [ ] Remaining single points of failure appear in the report.

### Per-test record

```text
Test ID and title:
Operator and reviewer:
Date and start/end time:
Repository commit and software versions:
Machines and network conditions:
Expected behaviour:
Exact actions performed:
Observed application response and path:
Evidence location (redacted):
Result: PASS / FAIL / NOT RUN
Cleanup and baseline-restoration result:
Follow-up issue:
```

## References and terminology

Headscale is the coordination service. Tailscale is the endpoint client. DERP relays encrypted traffic when direct connectivity is unavailable. Ansible applies repeatable configuration. Federation means application-level communication between independently operated services; it is a later step than this network pilot.

Use the exact selected releases' documentation when converting this plan into executable commands:

- [Headscale requirements and ports](https://headscale.net/stable/setup/requirements/)
- [Headscale official installation](https://headscale.net/stable/setup/install/official/)
- [Headscale enrollment and tags](https://headscale.net/stable/ref/registration/)
- [Headscale policy and default behaviour](https://headscale.net/stable/ref/policy/)
- [DERP configuration and admission verification](https://headscale.net/stable/ref/derp/)
- [Coordination-server outage behaviour](https://tailscale.com/docs/reference/coordination-server-down)

The engineering work breakdown is in `superpowers/plans/2026-09-24-server-connectivity.md` relative to this file. Both documents describe proposed work. Neither certifies that the network or deployment kit has already been built.

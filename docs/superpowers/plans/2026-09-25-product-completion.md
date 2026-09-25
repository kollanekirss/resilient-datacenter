# Product completion ledger and remaining implementation order

This follows the active resilient-services product design. User authorization is to continue through the goal, without another approval pause at each increment. Work stays in isolated checkouts; privileged acceptance uses disposable GitHub-hosted Ubuntu, never the developer computer. Reviews here are author reviews, not independent reviews.

## Verified foundation

- Guided independent/join networking, local node installation and explicit enrollment.
- Attested experimental networking release, infrastructure certificate replacement and guarded recovery.
- Consistent encrypted offsite transport, opt-in scheduled backups, fenced and journaled restoration.
- Matrix/Element and Nextcloud packages with private HTTPS, account separation, real operations and replacement recovery. Browser recovery of encrypted Matrix history is separately tested.
- Bilateral signed approvals, restricted regional gateway transport, expiry/revocation including established streams, interrupted-change recovery and periodic clock/membership checks.
- Actual Matrix exchange across two independent internal networks and one regional network; internal chat after regional loss. Evidence: run 36145734658. Actual Nextcloud federation, destination restrictions and internal file use after regional loss are also verified (run 36151160141).

These are bounded disposable acceptance results. Consult validation-status.md for evidence and limitations rather than inferring complete product support.

## Regional increment — implemented and merged in PR #8

Items 1–6 below are complete within their documented disposable boundaries. Physical sites and public issuance remain external.

1. Finish Nextcloud's generated private connector configuration and startup controls. Preserve original identity/configuration in backups, keep public links and automatic acceptance disabled, and prevent recovered databases from reopening old partnerships. Validate actual startup, account maintenance, scheduled jobs, TLS rotation and backup/restore after runtime changes.
2. Complete actual file federation: signed OCM discovery/exchange, explicit recipient acceptance, byte-for-byte read, unrelated-file denial, share revocation, partnership revocation and internal file operations after regional loss. Keep candidate routes disabled in the normal gateway until these checks pass.
3. Expose the reviewed file connector through the same public service-link export and guided local attachment flow as chat. Verify interrupted attachment resumes safely and internal files remain available after failed activation. Use one backup-first operation lock for each application.
4. Add gateway certificate lifecycle using the existing validated generation/activation mechanism. Test expiry reporting, actual certificate replacement, failed activation and retained working material. Real DNS-provider issuance still requires external credentials and acceptance.
5. Add gateway backup/recovery. Restore public approval identity, monotonic revocation history and owned secrets under a closed transport boundary. Require current local partnership review before reopening; a historical backup cannot prove no later revocation existed.
6. Close the fresh-replacement network bootstrap gap documented in the peer-recovery-bootstrap design. A prepared-host restore cannot establish the ability to reconstruct a fresh installation with its original VPN identity. Review the complete increment, update current CLI/docs/evidence, then merge passing source. Do not describe a passing Matrix test alone as a complete regional journey.

## Complete operator lifecycle and infrastructure resilience

7. Implemented and accepted in PR #9: an ordinary-purpose installation entry point covering personal, institution and regional journeys. Reuse existing validated commands; show machine roles, prerequisites, what belongs on each machine and each next action. Discover local facts where possible; retain explicit identity/secret inputs and exact resume behavior.
8. Implemented and accepted in PR #9: unified read-only status with separate network, application, certificate, backup age, restore evidence and partner dimensions. Missing evidence means unknown or untested, not healthy. Surface actionable next commands. Do not make a single green “resilient” badge.
9. Implemented in PR #10; both native paths passed run 36163148509, with current integration checks required before merge. Define reviewed product upgrade paths, compatibility manifests and preflight checks. Require a usable recent snapshot and stage verified artifacts. Preserve identities; serialize with certificate/backup changes; journal interruption; refuse unsupported application/database version jumps. Test the actual supported before/after path and injected failure, without running downloaded deployment artifacts on the developer computer.
10. Implemented and merged in PR #11; final-source native run 36163466460 and all regression checks passed. Add additional relay locations and controller recovery acceptance with actual enrolled clients. Verify useful traffic under loss of one relay and controller replacement. Explain which existing flows survive a control outage and which enrollment/policy operations require restored control. Do not claim shared regional coordination is decentralized control.
11. Exercise installation behind simulated home NAT without inbound management SSH, then service use, encrypted remote backup and fenced replacement. Report the simulation boundary clearly; physical home routers, power/site independence and public DNS remain external acceptance items.

## Release and external acceptance

12. Run the required current-source checks once after final relevant changes; fix failures and review the final diff. Refresh plain-language GitHub instructions, role diagrams, recovery/upgrade guidance, prerequisites and known limits. Remove stale historical claims from current-start instructions.
13. Publish a versioned experimental artifact with checksums, provenance and verified download. The released instructions and artifact must match the exact reviewed source. Source publication alone is not deployment acceptance.
14. Complete real provider/domain and physical-site acceptance when the required infrastructure/credentials are available, and have a colleague unfamiliar with the project follow only the released guide through installation and recovery. Those human/external exercises cannot be claimed from CI. A supported release waits for every advertised journey's acceptance; optional SSO, ARM, seamless live migration and overlay-only dual-connector topology remain separately designed/tested capabilities.

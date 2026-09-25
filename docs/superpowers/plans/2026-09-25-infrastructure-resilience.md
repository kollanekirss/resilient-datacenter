# Infrastructure resilience implementation

Spec: ../specs/2026-09-25-infrastructure-resilience-design.md. Execute inline under the continuous goal mandate, in the isolated infrastructure checkout. Native execution is restricted to disposable GitHub-hosted Ubuntu.

1. Add failing contract tests for legacy compatibility and additional relay locations. Reject ambiguous hosts, duplicate DNS/IP/region IDs, unsupported keys and partial certificate data. Normalize a complete catalogue and per-host DNS identities.
2. Render the complete controller DERP map and derive each relay's validated hostname before certificate preflight/deployment. Verify rendered YAML and all existing inventory/task checks.
3. Extend guided setup with relay count and additional relay questions, validation and resume/back compatibility. Update setup documentation with independent failure-domain requirements.
4. Build a guarded native acceptance fixture with actual controller, production relay binaries and clients. Force relay traffic, remove the selected relay, verify recovery through the survivor and report interruption honestly.
5. Add actual enrolled-client controller backup/fenced recovery acceptance, preserved authority and post-recovery enrollment. Use independent encrypted backup credentials and a reachable protected destination; do not assume infrastructure roles belong to their own client overlay.
6. Run local and native checks, inspect failures, author-review the complete diff, update evidence and merge passing source. Continue the separate home-NAT/replacement and release milestones.

Preflight interfaces: schema validation feeds normalization, which feeds template rendering and hostname ownership; every consumer must use the same validated location list. Wizard-generated input passes the same schema, with no bypass. Recovery must preserve existing backup ownership formats.

## Execution record

- Tasks 1–3 implemented: strict relay input/normalization, rendered map and per-host preflight, guided count and resumable endpoint identity. Contract/render tests failed first, then passed; current local suite is 610 tests with 16 playbook checks.
- Tasks 4–5 accepted on source 2e19b0d in run 36163225492: actual relay loss (10.09 s observation), existing HTTPS during short control loss, encrypted routed-SFTP state recovery (5.75 s restoration/enrollment observation), preserved authority/client identity and fresh admission.
- Native first run rejected malformed fixture nft syntax before exercising failover. Corrected to newline-delimited rules; the actual rerun passed. No product firewall bypass was added.
- Ruling: controller recovery retains the prepared OS/TLS baseline and uses a separately routed storage namespace — this tests the existing owned recovery contract without inventing a fresh-host installer — cost if mistaken: an operator might overestimate disaster rebuild readiness; documentation explicitly preserves that external exercise.
- Ruling: retain the original strict validator and validate each controller/relay projection, then enforce topology-wide uniqueness — avoids widening arbitrary inventory privileges — cost if mistaken: cross-projection validation gaps; duplicate host/IP/DNS/region and unsupported-field tests cover the shared boundaries.
- Author review completed inline; no subagents or independent review. Final regression completion and integration remain pending.

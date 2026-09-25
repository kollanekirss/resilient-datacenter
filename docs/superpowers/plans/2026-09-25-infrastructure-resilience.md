# Infrastructure resilience implementation

Spec: ../specs/2026-09-25-infrastructure-resilience-design.md. Execute inline under the continuous goal mandate, in the isolated infrastructure checkout. Native execution is restricted to disposable GitHub-hosted Ubuntu.

1. Add failing contract tests for legacy compatibility and additional relay locations. Reject ambiguous hosts, duplicate DNS/IP/region IDs, unsupported keys and partial certificate data. Normalize a complete catalogue and per-host DNS identities.
2. Render the complete controller DERP map and derive each relay's validated hostname before certificate preflight/deployment. Verify rendered YAML and all existing inventory/task checks.
3. Extend guided setup with relay count and additional relay questions, validation and resume/back compatibility. Update setup documentation with independent failure-domain requirements.
4. Build a guarded native acceptance fixture with actual controller, production relay binaries and clients. Force relay traffic, remove the selected relay, verify recovery through the survivor and report interruption honestly.
5. Add actual enrolled-client controller backup/fenced recovery acceptance, preserved authority and post-recovery enrollment. Use independent encrypted backup credentials and a reachable protected destination; do not assume infrastructure roles belong to their own client overlay.
6. Run local and native checks, inspect failures, author-review the complete diff, update evidence and merge passing source. Continue the separate home-NAT/replacement and release milestones.

Preflight interfaces: schema validation feeds normalization, which feeds template rendering and hostname ownership; every consumer must use the same validated location list. Wizard-generated input passes the same schema, with no bypass. Recovery must preserve existing backup ownership formats.

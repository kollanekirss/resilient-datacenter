# Integrated personal journey implementation

Spec: ../specs/2026-09-25-home-nat-recovery-design.md. Inline execution under the existing goal mandate, in this isolated checkout. Privileged runtime executes only on disposable GitHub-hosted Ubuntu.

1. Add a fixed, guarded VM harness with pinned dated Ubuntu image, KVM requirement, private per-guest host keys and loopback-only console forwarding. Tests verify command construction never exposes credentials or public forwarding and refuses non-disposable hosts.
2. Add an in-guest driver that invokes the existing local installation checks/engine, one-use enrollment, package setup and full encrypted backup. Keep control and application identities explicit; use actual client transport.
3. Add fresh replacement/bootstrap/restore phases using independently retained credentials and the selected full snapshot. Enforce old QEMU process exit before launching recovery. Assert original network/application identities and authenticated user data.
4. Run both package cases in disposable Ubuntu. Diagnose actual failures, add focused regression tests for product fixes, then run relevant existing acceptance.
5. Author-review, record source-specific evidence and honest simulation boundaries, refresh personal instructions and integrate passing source. Continue the remaining ingress review, final documentation and experimental release tasks.

Preflight interfaces: VM console transport must be independent of the network identity that bootstrap replaces; backup credentials must outlive the fenced guest; exact source/image pins and application ownership must match the staged snapshot. Never downgrade these contracts to make a fixture pass.

Execution record: run 36165726657 at 596e4aa passed both real guest journeys. Matrix recovery took 149.58 seconds with a 13.13-second-old snapshot; files took 237.15 seconds with a 10.22-second-old snapshot. These measured boundaries are documented, not SLAs. The daemon path and readiness defects found by real guests have regression tests. Main's controlled upgrades and interface guard are merged into this checkout; 635 combined unit tests pass. Native combined-source checks and integration follow. Review is inline author review.

# Portable network implementation plan

Spec: ../specs/2026-09-25-portable-network-design.md
Execution: native inline; side conversation prohibits subagents. User authorised continuing the modular implementation. Preserve earlier worktrees. No application migration or live infrastructure changes in this iteration.

1. Add strict network settings and derived policy in `scripts/portable_network.py`. Tests first: network membership/collisions, DHCP gateway exclusion, interface syntax, hostname hierarchy ambiguity, source clock and management independence.
2. Add pure renderers in `scripts/portable_network_render.py` and `scripts/portable_network_guide.py`. Emit Netplan, Unbound, chrony, dedicated nftables, role variables and exact OPNsense console/policy steps. Generated daemon files receive real syntax/runtime checks on hosted Linux, not string-only tests.
3. Add immutable private kit writer in `scripts/portable_network_bundle.py`, guarded playbook in `playbooks/portable-dns.yml`, and stock RDC units under `portable/`. Tests: no overwrite/symlink adoption, corrupt manifest and plan/settings mismatch; playbook syntax and real disposable apply where practical.
4. Add bounded client diagnostics in `scripts/portable_network_probe.py`, using Python standard library DNS wire and SNTP with strict response matching, deadlines, no subprocess/shell or ambient DNS. Tests exercise response parsing and local fake socket servers, wrong answers, malformed packets, wrong NTP originate and unsynchronised time.
5. Integrate new preparation/check commands and wizard menu without requiring PVE credentials for local operations. Nonzero failures and unverified readiness fields are tested. Preserve legacy default CLI behavior.
6. Add disposable hosted network workflow exercising generated files in Linux namespaces, offline restarts and negative policy cases. Run local suite and full project checks; inspect hosted results; update docs and development version. Review diff against design and correct important findings before PR/merge under existing authorisation.

Review focus: clocks without trusted UTC; overlapping service DNS zones; same-bridge bypass; role/host mismatch; output-directory adoption and stale/tampered kits; unknown probes not interpreted as success. Real OPNsense installation acceptance remains separate.

## Progress

- Baseline: branch from merged PR19 at53da00a. Native worktree tool unavailable because task cwd is not a repository; isolated git fallback under ignored .work used.
- Design ruling: deliver roadmap stage3 first, following its explicit separation from stage4, because application access/backup contracts require their own implementation boundary.

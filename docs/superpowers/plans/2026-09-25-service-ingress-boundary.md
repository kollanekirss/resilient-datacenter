# Service ingress implementation

1. Add failing tests for strict normalized nftables structure, unexpected table contents and missing-rule refusal.
2. Implement the shared runtime guard and invoke it before proxy launch/attachment and during readiness; ensure packages and repeat-install behavior.
3. Add disposable LAN/overlay-interface packet probes, including spoofed source and service restart. Adapt upgrade fixture ingress to its declared synthetic overlay.
4. Run local checks and actual application, upgrade, regional and home-NAT checks for integrated source. Review inline, record bounded evidence and merge only passing changes. Preserve other firewall tables and the existing backup format.

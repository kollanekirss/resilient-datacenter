# Regional gateway implementation plan

Implement the approved regional journey without joining an ordinary client to two networks. All privileged acceptance runs use disposable GitHub-hosted Ubuntu; local work only prepares source/contracts and nonprivileged tests.

1. Define strict public institution identities, signed bilateral offers/acceptances and bounded agreement lifetimes. Test modified payloads, wrong peer keys, stale signatures, expiry, duplicate JSON keys and unsupported inputs. Private signing keys never belong in exports.
2. Add private guided key initialization, identity export, offer/acceptance preparation, independently verified peer fingerprint approval and inspect/revoke commands. Report approval separately from network admission. No exported document is executed.
3. Define the dedicated gateway and private-LAN service integration contracts. Keep one regional VPN identity per gateway and one internal identity per service VM. Reject subnet routing and conflicting deployments. Decide exact pinned application federation endpoints from upstream source and runtime evidence.
4. Render fixed ingress HTTPS and restricted forward-proxy rules. Add transactional scoped firewall rules, bounded peer expiry and startup/restore guards. Peer expiry/revocation must close existing access, not merely deny new TCP sessions. Validate real native configurations before activation.
5. Add application integration with stable domains, exact upstream TLS verification and restricted federation names/settings. Preserve independent internal users, accounts and service identity. Regional failure must leave internal service operations available.
6. Exercise two actual independent institutions and a regional network in disposable isolation: approved Matrix exchange, approved Nextcloud exchange, rejection of unrelated users/routes/destinations, revocation, disconnected regional transport and interrupted changes. No single-process mock is evidence of cross-network isolation.
7. Extend gateway backup/recovery without resurrecting revoked approvals. Update plain-language diagrams, installation paths, status and acceptance evidence. Keep physical site loss, home NAT, provider issuance and colleague usability explicitly pending until independently performed.

Implementation is incremental but the regional journey is not advertised as supported until its real transport/application tests pass.

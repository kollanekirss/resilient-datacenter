# Institutional crisis networks: delivery priorities

Updated 26 September 2026 from the user's explicit scope clarification. This
priority order supersedes the earlier recovery-first order and the ordering in
older component roadmaps. Recovery is useful later work, not the primary product.

## Required operating model

Each institution has two separate network roles:

1. **Institution user access:** its headquarters users and field operators reach
   its own services through a resilient institutional network. A national/regional
   loss of outside connectivity must not by itself stop access where domestic or
   local communication paths still exist. Headquarters LAN-only success is
   insufficient evidence for this requirement.
2. **Inter-institution service connectivity:** a separate network carries approved
   service-to-service exchange, such as police and rescue Matrix homeservers.
   Each node retains its own service data and operates independently when isolated.
   Partners communicate when a path exists; no automatic full-database replication
   or restoration is required for the first milestone. Shared application content
   can be held by participating services according to their federation semantics.

The current gateway implementation attaches each institution to a regional
service network; it does not federate Headscale controllers or join field users
to the partner network. These logical roles do not create physical connectivity
where every usable carrier/radio/cable path is absent.

The kit and users are prepared **before a crisis**: software, accounts, stable
service names and publicly trusted certificates. Staff must not need a private
CA installation, a certificate warning bypass, new public issuance or external
sign-in during the crisis. Public trust on the supported device fleet and
remaining certificate validity need actual acceptance, not test-CA evidence.

## Current evidence and next work

| Priority | Work | Current state | Acceptance still required |
|---|---|---|---|
| 1 | Resilient institutional access for headquarters and field users | Actual Headscale/Tailscale/DERP, multiple relays and user-to-service operations tested on disposable Ubuntu | National/regional external disconnection with domestic connectivity retained; fresh/restarted sessions, changed uplinks, domestic DNS/bootstrap, authority reachability, relay admission and expiry/revocation behaviour |
| 2 | Separate inter-institution service network | Independent internal/regional networks and actual approved Matrix/Nextcloud exchange tested; partner denial/revocation tested | Multiple physically independent institutions, partner partitions/reconnection, regional authority/gateway outage and portable-profile integration |
| 3 | Public certificate preparation and supported-device access | Supplied-certificate and managed issuance/renewal paths exist; lifecycle tests use a private fixture CA | Real public issuance before the exercise; supported devices accept chains without private trust installation; operation with external DNS/CA/identity dependencies unreachable |
| 4 | Prepared portable headquarters kit | Site planning, Proxmox API adapter/media guidance, local DNS/time/frontend and applications implemented in development | Actual Proxmox/OPNsense boot and enforcement; moving to another uplink while preserving service identity; field and partner access after movement |
| 5 | Institution-facing operator handover and physical pilot | Partial wizard and instructions exist | Ordinary operator follows prepared instructions; device enrollment in advance; wiring, power, independent carriers and actual field operations |
| Later | Data backup, restoration and empty-machine reconstruction | Draft PRs #24–#26 include encrypted material, readiness and a passing combined Linux recovery exercise | Deferred behind network continuity; actual OPNsense/Proxmox/physical recovery remains unproven |

Offline software preparation in draft PRs #22/#23 remains relevant to advance
preparation. Recovery-specific development is deferred, and its existing work is retained. Draft PRs #22–#26 remain unmerged at
this update. No institutional production deployment is claimed.

## Critical evidence limits

Multiple DERPs do not remove controller dependence. Existing evidence establishes
surviving-relay traffic and brief continuation of established sessions during a
controller outage. It does not establish unrestricted new sessions/admissions or
cold starts during a national isolation event. The current regional gateway is
also a single failure point. These are first-stage continuity gaps.

The recent [combined recovery rehearsal](combined-recovery.md) is supplementary
Linux recovery evidence; it is not field-access or regional-isolation acceptance.
Historical test records remain in [validation status](validation-status.md).
Do not use a test count or recovery time as a measure of completion of the two
required networks.

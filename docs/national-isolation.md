# Prepared institutional access during regional isolation

This exercise prioritizes the project's two networks: each institution's user
and field access, and separate approved service-to-service communication between
institutions. It extends the existing independent-network Matrix fixture. It
contains no backup restoration or machine replacement milestone.

## Disposable architecture

Two institutions each have an independent Headscale authority, a prepared field
client, a Matrix service and two dedicated production DERP processes. Two separate
gateway clients belong to a third, regional Headscale authority with its own two
relays. Only approved Matrix federation endpoints cross the gateways. Field users
do not join the regional network. A domestic Unbound resolver supplies authority,
relay and field-facing application names. Gateway federation mappings remain
explicit fixture hosts entries, matching the existing gateway test.

Every controller, relay, resolver and client has its own network namespace.
Authorities and application databases are separate processes/state directories.
This is logical isolation on one disposable Ubuntu runner, not independent power,
carriers, hardware or physical institutions. Artifacts are downloaded beforehand
by the separately connected CI orchestrator. All test certificates are generated
before the cut; no enrollment, issuance or trust installation is needed afterward.
The public-certificate requirement is unchanged: the fixture CA is test-only and
cannot establish acceptance on ordinary devices.

A live endpoint on the shared test underlay represents outside-region
infrastructure. It is reachable from every participant before the cut. The cut
allows only declared domestic control/relay/DNS endpoints and their replies on
the underlay; direct peer UDP is denied, so application traffic must traverse the
private relays. IPv6 underlay egress also falls through to denial. The outside
endpoint remains alive but becomes unreachable from every participant. There is
no general Internet/default route in these namespaces, before or after the cut.
This is a synthetic national boundary, not a real route to Estonia's Internet.

## Required checks

- Baseline field login, private chat write/read and two-way federated room exchange.
- Outside positive/negative controls across all participants; continued domestic
  access and approved federation after the cut.
- Stop/restart each prepared field daemon using its existing state, preserving
  its node key/address without enrollment; perform a fresh application login.
- Repeat after changing its underlay address. This simulates endpoint change,
  not actual cellular/Wi-Fi handover, carrier NAT or a new physical route.
- Identify and stop the active relay for each institutional field path. Require
  useful operations through the surviving relay with no direct path, retaining
  the existing application session rather than repeatedly logging in.
- Block the partner gateway path while both institutions continue private local
  operations, then reconnect and exchange new federated messages again. Queued
  cross-partition message backfill/conflict behaviour is not covered here.
- Stop one institutional authority. Observe established access and access after
  a field restart separately. Unavailability is reported rather than hidden;
  this does not turn a single-authority deployment into an HA design. The other
  institution must remain usable. Restart the same authority process/state and
  require useful field access and federation to return. No data restore occurs.
- Verify that outside connectivity remains blocked at the end and that regional
  gateways still reject user/admin endpoints.

## Evidence and remaining gates

Hosted result: **PASS**, implementation head `c133333`,
[run 36238695962](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36238695962),
26 September 2026. All required combined phases passed. All **932 local tests**
and playbook checks passed on GitHub for that implementation revision. Existing
regional-network, gateway and infrastructure checks also passed; unrelated longer
application regressions were still running when this evidence was recorded.

| Observed case | Result |
|---|---|
| Simulated outside-region cut across all participants | Outside canary blocked; domestic field login/chat and approved federation worked |
| Prepared field client restart in each institution | Same enrolled identity; fresh local login and message write/read worked |
| Simulated field address change in each institution | Fresh login and useful chat worked |
| Active relay loss, direct peer path blocked | Useful authenticated operations through the survivor; 8.91 seconds in each institution |
| Partner path blocked | Both institutions retained authenticated private chat |
| Partner path reconnected | New messages exchanged in both directions |
| North authority stopped, established field session | Authenticated chat write/read remained available in the short observation |
| North authority stopped, field daemon restarted | **Unavailable** in the bounded observation |
| North authority stopped, south institution | Authenticated private chat remained available |
| Same north authority restarted with its existing state | Fresh north login/chat and two-way federation returned |

The restarted-client observation made **80 attempts over 90.44 seconds** with
the field daemon confirmed alive. No attempt completed the authenticated user
operation until the authority was restarted. This is still a bounded observation,
not a measurement of an unlimited outage. Relay
timings include the successful user operations and are observations, not SLAs.
The controller-loss limitation is an open product gap. A passing lab run does not
mean the complete institutional resilience requirement is met.

The first run found a fixture firewall syntax error; native nftables check mode
now validates generated isolation rules before setup. The second run hit the
application's login rate limit from excessive repeated test logins. Existing
sessions are now retained for relay/partner outages; fresh login remains required
for baseline, outside cut, field restart, address change and authority return.
Production rate limits were not relaxed. Independent review verified the evidence
boundaries and the fixes. Local contract tests cover endpoint rejection,
identity-preserving restart arguments, authenticated observations and mandatory
phase completion. A documentation-only follow-up records these results.

Still required: real public certificate issuance and preparation, supported
phone/laptop trust checks without private CA installation, independent domestic
controller/bootstrap discovery and failover, enrollment/expiry/revocation during
partitions, DNS redundancy, mobile carrier handover, gateway redundancy, actual
Proxmox/OPNsense integration and physical relocation. A short successful session
cannot establish indefinite operation through certificate or node-key expiry.

The test result records observed controller-loss behaviour separately from the
required domestic-connectivity phases. Recovery time from earlier restoration
exercises is not used as evidence for this milestone.


## Next continuity milestone

Prioritize making the institutional authority reachable through a domestic
failure before expanding restoration work. Define and test continuity of the
same authority identity, stable DNS/TLS endpoint, node keys and policy during
loss of its active location. Keep relay admission checks enforced. A second
independent Headscale installation is not automatically a replacement authority.
The acceptance must repeat prepared-client restart and endpoint change while the
original authority is unavailable, including denial/revocation and expiry cases.
Domestic DNS redundancy and service-network gateway redundancy remain separate
gates. No implementation of controller failover is claimed here.

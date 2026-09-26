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
  useful application operations through the surviving relay with no direct path.
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

Hosted result: **pending**. Local contract tests verify underlay deny rules,
endpoint validation, identity-preserving restart arguments and honest evidence
requirements. Only a passing hosted run proves the combined runtime checks.

Still required: real public certificate issuance and preparation, supported
phone/laptop trust checks without private CA installation, independent domestic
controller/bootstrap discovery and failover, enrollment/expiry/revocation during
partitions, DNS redundancy, mobile carrier handover, gateway redundancy, actual
Proxmox/OPNsense integration and physical relocation. A short successful session
cannot establish indefinite operation through certificate or node-key expiry.

The test result records observed controller-loss behaviour separately from the
required domestic-connectivity phases. Recovery time from earlier restoration
exercises is not used as evidence for this milestone.

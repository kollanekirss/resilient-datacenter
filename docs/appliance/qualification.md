# V1 role qualification boundary

The approved [roles plan](../superpowers/plans/2026-10-11-appliance-v1-roles-release.md)
now has software implementations for private Linux guest administration,
owner-approved joining, separate hosting eligibility, persistent Headscale and
DERP setup, private role snapshots and conservative product-release checks.
It does not yet have accepted machine or public-network execution.

## Checks available without a test machine

```sh
.venv/bin/python scripts/check_local.py
.venv/bin/python scripts/ci_appliance_roles.py --suite all --format text
./rdc-appliance release-check
./rdc-appliance preview examples/appliance-site-roles.json
```

The ordinary checks make no target connections. Local tests cover actual TLS
handshakes with temporary certificates and actual OpenSSL signatures as well
as controlled command transcripts, identity persistence, secret handling,
timeout/replay refusal, firewall rendering and snapshot failures. They do not
establish that the Linux image boots, the daemon configuration works on the
pinned guests, or public packets cross OPNsense as intended.

The role acceptance script defaults to read-only inspection and returns exit
2 / **NOT RUN** when execution is absent or prerequisites are missing. Its
explicit execution path is restricted to a named disposable independent Linux
namespace. It can collect bounded HTTPS, peer/nonce, fresh test-client,
STUN and selected-relay measurements. Partial measurements are signed evidence
of those observations only. They cannot become a whole-case PASS when any
required assertion is missing.

## Work requiring the later machine and independent endpoint

1. Prepare the signed package closure and build the offline Linux role image;
   retain its actual hash, recipe and source receipt. Import into three new
   isolated Proxmox guests. Prove different first-boot identities and private
   guest-agent operation before connecting them.
2. Run the [base acceptance suite](lab.md), including the real USB/UEFI journey,
   port mapping, management recovery and OPNsense configuration migration.
3. Join the existing controller behind ordinary NAT, with no inbound mapping.
   Exercise positive HTTPS and a known live denied listener. Force the selected
   relay path, then repeat host/router/guest restarts and WAN loss/return without
   re-enrolling or changing the node identity.
4. Exercise Headscale on direct public addressing and separately on controlled
   upstream DNAT. Test DNS/TLS failures, fresh client enrollment, allow/deny
   policy, certificate replacement and authority continuity.
5. Obtain a real routed public allocation for DERP. Verify inbound and outbound
   source addresses, STUN and relayed application traffic. Exercise new
   unknown-client rejection and new-session rejection during a verifier outage.
   The latter two need the dedicated DERP wire-client/fault-channel adapter;
   they are explicit remaining automation work, not simulated passes.
6. Exercise both hosted roles on distinct endpoints, internal verifier routing,
   denial of relay access to management and unrelated infrastructure, consistent
   role exports and independent decryption with all restored identities inactive.
7. Have an unfamiliar operator follow the complete guide on physical two-port
   hardware. Record actual resource usage and update the provisional budgets.

## Release gate

`v1_release_allowed` requires every base case, including the physical operator
case, plus these eight role cases:

| Case | Required coverage |
|---|---|
| `join-nat` | Owner/controller identity, no inbound mapping, no subnet routing, authorized/denied traffic, independent management |
| `relay-path` | Direct path blocked, selected region actually used, relayed HTTPS, owned faults cleaned |
| `controller-hosting` | Both public profiles, fresh enrollment, policy, persistent authority, certificate replacement |
| `standalone-relay-hosting` | Routed public VM, no NAT, both source directions, STUN, selected relay, unknown/verifier-down admission |
| `both-hosting-roles` | Distinct endpoints, local verifier, management denial, independent eligibility |
| `role-identity-restart` | Host/router/guest restarts and WAN return with unchanged identities |
| `private-role-export` | Complete consistent state, restart after failure, encrypted readback, inactive recovered identities |
| `full-operator` | Physical USB-to-network journey, unfamiliar operator, export/repair and measured budgets |

The gate rejects missing, duplicate, failed, stale, synthetic or NOT RUN records,
changed evidence files, mismatched build/source/lock identities, missing resource
measurements and a non-independent probe. It checks recorded evidence integrity;
it does not authenticate arbitrary JSON submitted by a third party or publish a
release. A site that legitimately cannot host is a supported installation
outcome; qualifying the product still requires separately testing its supported
hosting profiles.

The single Proxmox host remains one failure domain. No automatic authority
failover, whole-site reconstruction, production deployment or public release has
been performed as part of this implementation.

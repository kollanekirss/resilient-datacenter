# Regional gateway lifecycle design

Status: implementation contract under the user's continuing product mandate; not a statement of completed acceptance.

The goal remains a maintainable dedicated regional gateway that institutions can recover without losing their ownership boundaries. This increment adds certificate replacement/renewal and encrypted recovery. It does not make a gateway redundant or eliminate the shared regional controller.

## Certificate identity and activation

Use one certificate naming every application domain in the gateway's pinned signed identity. Names cannot be added by a renewal profile. Preserve the existing trust validation: system CA chain, exact DNS SAN, matching private key and at least seven days of remaining validity. A publicly trusted certificate is the supported ordinary path; a private CA requires explicit trust configuration on both applications and gateways.

Reuse the certificate generation mechanism in `certificate_lifecycle.py` with a dedicated gateway role and `/etc/rdc-gateway/tls/active`. Envoy reads the generation through its existing read-only gateway mount. Both the regional listener and a TLS-only loopback check listener at 127.0.0.1:9443 read the same certificate configuration. The check listener denies all HTTP requests and has no upstream routes. It provides actual TLS fingerprint verification during a closed partner policy without weakening the firewall. Refuse an existing listener on that port during initial installation.

All certificate changes hold the gateway operation lock and, when configured, the backup operation lock first. A durable certificate-pending marker keeps the periodic guard and startup from opening partner traffic after interruption. Close the gateway before switching the generation. Restart the owned proxy and verify the served certificate for all pinned names; reopen only the unchanged current policy, with fresh clock, membership and expiry checks. On activation failure, restore the previous certificate and verify it; retain an actionable failure record. If recovery cannot be verified, retain the pending marker and closed transport. No certificate operation changes approvals or discards revocations.

Initial installation stages a validated generation before starting Envoy. Repeat installation checks the managed certificate ownership and current generation, rather than requiring the original input file to equal the most recently renewed certificate. Unowned legacy TLS files are never silently adopted. PR8's unreleased gateway format may be changed before its first published release; previously installed experimental revisions need an explicit upgrade path.

## Issuance and scheduling

Extend the fixed DNS-01 issuer contract to a gateway certificate request with the exact pinned service names. Use the existing restricted Cloudflare provider implementation and isolated Certbot configuration. Keep the provider token private to root and out of output. The fixed renewal runner must include and verify its complete dependency catalogue under isolated Python execution.

Gateway issuance may be prepared after network enrollment and signed identity import, before gateway application installation. Enabling automatic activation requires matching installed gateway identity. A timer renews and activates through the same locked transaction. Report current expiry, last renewal outcome and whether the actual served fingerprint was verified separately. A provider failure retains the working generation and does not imply renewal success. Tests substitute only the provider boundary; no live issuer claim without real credentials/domain validation.

## Recovery boundary

Add gateway as an explicit backup package on a dedicated locally enrolled peer. Include the owned network identity/state needed to rejoin, pinned public gateway identity, profile, current policy, monotonic revocation history, clock history, certificate generations, renewal ownership/configuration and required recovery secrets. Never include an institution's offline approval signing key, which does not belong on a gateway. Consistent capture uses the same backup-first lock order and existing encrypted Restic transport. Preserve runtime compatibility hashes.

Restoration uses the existing fenced/journaled recovery workflow, with old-primary fencing explicitly confirmed. Before any service starts, create a persistent gateway-recovery suspension marker. Restored policy state and revocations remain inspectable, but cannot open the network. A historical backup cannot prove that a later revocation did not occur: record a recovery-time approval floor and require newly issued bilateral approvals at or after that floor before recovery suspension can be cleared. Retain historical revocation IDs; do not reset the state generation to bypass them. A clock problem keeps the boundary closed.

A replacement normally retains its signed network/domain identity only when the old primary is fenced and that network identity is recoverable. A different gateway address or institution key requires a new signed identity and new agreements, not a silent edit to historical approvals. Independent backup access must not rely solely on the unavailable regional control plane; the supported recovery instructions must describe the reachable backup endpoint and separately held credentials.

## Acceptance

1. Local contract tests: both names, mismatched keys, expiry, unsafe generation paths, held operation locks, pending policy/recovery, same-generation verification, failed activation and failed rollback.
2. Disposable Ubuntu: real Envoy serves the new trusted certificate; injected activation failure retains and serves the old certificate; loopback TLS check has no application route and is unreachable from LAN/regional peers; approvals and revocations remain byte-for-byte unchanged.
3. Frozen renewal runner: actual isolated import closure, scheduled activation and provider-boundary failure, with no provider secret in logs.
4. Encrypted gateway capture and replacement restore: selected backup age reported, old primary fenced, stable identity retained, transport closed on startup, stale agreements rejected even if absent from the backed-up revocation list, fresh bilateral approvals explicitly applied, and subsequent approved application exchange restored.
5. Failed and interrupted operations remain resumable and closed. No missing marker/state may be interpreted as a new empty gateway.

The existing regional protocol acceptance must pass before enabling Nextcloud in the ordinary route catalogue. Gateway lifecycle acceptance is independent of real-world site/NAT/colleague exercises.

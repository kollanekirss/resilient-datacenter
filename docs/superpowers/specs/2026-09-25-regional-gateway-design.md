# Regional gateways and explicit partner approval — draft

Goal: two institutions retain independent internal Headscale networks while approved applications exchange traffic over a separate regional network. This is a product increment after verified standalone chat/file recovery.

## Deployment boundary

One dedicated Ubuntu gateway VM per institution, enrolled only in the regional network. Internal service VMs retain only their internal identities. An institution-owned private LAN connects these VMs. The gateway has no general IP forwarding and advertises no subnet routes. It exposes only approved HTTPS application routes on its regional overlay address. A common private LAN is a prerequisite for this first topology; an isolated connector for overlay-only services is a separate design, not an implicit second identity on the gateway.

Application HTTPS remains end-to-end verified on each connection: partner-to-gateway and gateway-to-local-service. Gateway certificates are institution-owned secrets, never region-wide credentials. The gateway uses exact upstream IP/port and TLS server name; no request can select an arbitrary upstream. A separate LAN listener on a service is restricted to its configured gateway source. Existing internal user HTTPS remains unchanged.

Outbound application requests use a LAN-only explicit forward proxy on the gateway. Its destination catalogue contains only approved partner domain/port pairs, with exact regional overlay addresses and no general Internet CONNECT. Application account permissions remain separate from gateway and Headscale permissions. Matrix additionally restricts federation server names. Initial file federation needs explicit incoming/outgoing enablement and a real share acceptance/revocation test; trusted-server discovery does not itself grant file access.

## Bilateral agreement

Each institution generates a local signing key and exports a public identity document. The document includes institution identifier, public-key fingerprint and declared application domains. Labels and signatures from an unknown key do not prove an institution's identity: administrators compare fingerprints through an independent channel.

An offer names both key fingerprints, exact application identities, network identities, requested scope, expiry and a unique identifier. The other party signs its acceptance of the exact offer hash. Activation requires both signatures and local approval of the peer fingerprint. Export/import files contain no private keys, enrollment tokens or user credentials. Reject oversized documents, duplicate JSON keys, unknown fields, altered offers, expired agreements and unsupported protocol versions.

Network admission remains a separate regional-administrator action. Generate a narrowly scoped, reviewable access request; do not claim traffic is available merely because an agreement exists. Configuration stages are proposed, locally approved, mutually approved, awaiting network access, verified and revoked/expired.

Revocation first removes local transport permission, then updates application policy and generates any regional policy withdrawal. Failure during later cleanup must leave access denied. Already delivered messages/files cannot be recalled. Expiry must fail closed without relying on a future human visit; clocks and status must be checked.

## Managed changes

Do not allow arbitrary proxy fragments or shell hooks. Use validated non-executable profiles and fixed renderers. Installation refuses unowned services, forwarding, conflicting listeners and unexpected systemd overrides. Updates stage configuration, run native validators, apply atomically, verify listener behavior, and retain a journal for interrupted operations. Partnership changes do not rotate service/account identities.

Backups include gateway identity/approval state and local proxy configuration; private keys remain institution-controlled. Recovery must check agreement expiry and current revocations rather than blindly resurrecting old access. Treat restored approval state as pending review before enabling partner ingress.

## Acceptance

1. Two actual Headscale authorities plus a third regional authority in disposable isolated Linux namespaces/VMs; each daemon belongs to exactly one authority.
2. Baseline internal chat/file operations survive a disconnected regional gateway.
3. Unknown peer, unsigned/modified acceptance, expired agreement and missing regional grant each deny access.
4. Approved Matrix servers exchange a real room event with account identity preserved; non-approved federation is rejected.
5. Approved Nextcloud users share, accept, read and revoke a file; unrelated local files remain inaccessible.
6. Attempts to reach local administration, databases, arbitrary LAN destinations, metadata addresses or arbitrary Internet CONNECT fail.
7. Revocation and interrupted activation leave the intended deny state; restore does not reactivate old partner approval without review.
8. Report actual test boundaries, including simulated WAN/NAT and independent administrator acceptance still required.

## Primary implementation references

- https://element-hq.github.io/synapse/latest/setup/forward_proxy.html
- https://element-hq.github.io/synapse/develop/usage/configuration/config_documentation.html
- https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- https://github.com/nextcloud/server/blob/v35.0.1/config/config.sample.php

This draft is not a shipped capability or a final implementation decision. Proxy compatibility, Nextcloud endpoint scope and certificate renewal on the gateway must be resolved with the pinned upstream versions before coding the transport.

## Initial agreement contract

Use Ed25519 keys and canonical UTF-8 JSON restricted to validated integers, printable ASCII strings, lists and objects; no nulls, booleans, floats, ambiguous duplicate keys or executable content. Sign a domain-separated envelope for each document type. Public identities bind an institution label, controller DNS name, gateway overlay IPv4, and distinct Matrix/file domains. Administrators must verify the complete SHA-256 public-key fingerprint independently before acceptance.

An agreement binds exactly two complete identity documents and a nonempty subset of `matrix` and `nextcloud`. It has an unpredictable identifier, UTC integer issue/expiry times and at most a 90-day lifetime. One active agreement per peer covers all approved services, so every transport rule for that peer shares one expiry. A signed acceptance binds the exact signed offer digest. No signature alone makes a document locally trusted. Inspection must distinguish cryptographic validity, local fingerprint approval, local revocation, expiry and unverified transport.

Kernel firewall peer entries should have bounded timeouts so expiry does not depend solely on a later timer invocation. Activation rechecks time and remaining lifetime; revocation updates the deny boundary before proxy/application cleanup. Retain a durable revocation record and refuse activation of the same agreement identifier afterward. Gateway restoration starts with partner transport closed pending local review of the latest approval state.


## Approval key placement

The institutional approval signing key belongs in a private administrator workspace and is encrypted as Ed25519 PKCS#8 with a passphrase. It is not installed on the gateway. Gateways receive public signed approvals plus explicitly reviewed local trust policy. Gateway TLS keys remain separate credentials. Workspace initialization resumes the same key; public exports never contain private material. Initial approval commands deliberately report transport as unverified until the deployment increment is implemented.

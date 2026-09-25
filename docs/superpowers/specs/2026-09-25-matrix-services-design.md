# Matrix/Element services increment

Active implementation design under the approved full product scope. This document describes intended behavior, not delivered support. Matrix/Element precedes Nextcloud, and each package must pass actual login, data and recovery checks before its advertised journey is marked supported.

## Installation boundary

Use a dedicated Ubuntu 24.04 amd64 service node already enrolled with the existing local installer. Keep its networking ownership marker intact. Store a separate service-package ownership marker under `/etc/rdc-services`. Do not adopt existing Matrix, database, reverse-proxy or container deployments. Require independent administration access, enough disk and memory, a synchronized clock and exact expected node/controller identity.

Use digest-pinned upstream container images with Ubuntu's maintained Podman runtime, fixed systemd units and host networking. Application/database listeners bind only to loopback; the HTTPS proxy binds only to the verified overlay address. No automatic public port publishing, subnet routing or Docker firewall changes. Refuse occupied reserved ports and names. Container unit ordering starts the database before Synapse and stops ingress/Synapse before the database. Separate persistent bind directories allow consistent, stopped-service backups. No container engine API socket is exposed to applications.

Initial upstream candidates, verified from their official release records on 2026-09-25: Synapse 1.161.0 and Element Web 1.12.29. Resolve and review immutable linux/amd64 image digests before implementation. Use a separately pinned supported PostgreSQL image, UTF-8 with C locale as required by Synapse. Preserve upstream license notices and source links. Do not use floating `latest` tags at installation time.

## Identity, certificates and accounts

The wizard asks for the institution/node, Matrix hostname and a separate Element hostname. Matrix's `server_name` equals its stable service hostname and is immutable after initialization. Explain the resulting `@user:matrix.hostname` identity before installation. Element uses a separate origin and points only to the selected homeserver. Hosted integrations and telemetry are disabled by default. Calls/TURN, bridges, SSO and regional federation are separate capabilities, not implied by text chat.

TLS must remain browser-trusted on home nodes without public management SSH. Implement supplied PEM material plus a guided DNS-01 certificate mode, initially using an explicitly selected provider contract. Never infer credentials or write them into profiles. The DNS provider's required permissions and independent renewal dependency must be explained. Public HTTP-01 is not a substitute when service names resolve only to overlay addresses. Certificate names, trust, keys and expiry are checked; no browser/TLS bypass is an acceptance method. Local DNS resilience still requires a separately implemented resolver/configuration path.

Disable open registration and guest access. Initial account creation runs locally as the administrator using hidden password input and Synapse's supported shared-secret registration API on loopback. Secrets never appear in process arguments, logs, public examples or support reports. Proxy routes exclude Synapse administration APIs. Network membership does not grant an application account or room access. Initial federation is denied until the separate partner approval workflow configures it.

## Data and recovery

The service catalogue contains configuration, database, media, signing keys and other server-held secrets, plus the local network identity needed to preserve the service endpoint. Client-side Matrix encryption recovery keys remain the user's responsibility; explain independent storage and test recovery of encrypted history before claiming it. A server backup cannot reconstruct a user's lost decryption secret.

Add an explicit service scope to backup ownership and snapshots. Installing services on a node with an existing network-only backup must not silently claim that its applications are protected. A reviewed `include services` transition preserves existing repository credentials and history, changes the captured resource catalogue, filters status to service-scoped snapshots and updates the protected scheduled runtime. Serialize that transition with running backups/recovery; do not kill a paused-service snapshot. Old network-only snapshots remain identifiable and must not be promoted as complete service recovery.

Reuse the guarded transaction concepts: full snapshot ID, exact component/image identity, immutable application identity, independently fenced old primary, ingress isolation, consistent candidate data, retained previous data, failure rollback before commit and no rollback after possible client writes. Retain the replacement's current TLS/account material while recovering application database credentials and signing identity together. Preserve pinned container UID/GID mappings for persistent volumes. Unknown schema or image transitions block promotion.

## Acceptance before release

- On disposable Ubuntu, install the actual pinned images and generated configuration, create two application users, log in, create a room and send/read a message. Demonstrate unauthorized access denial. Serve the actual Element build and test its browser login path with a trusted test certificate.
- Take an encrypted offsite-protocol snapshot containing actual database/media/signing state. Change data, recover the selected snapshot under isolation and verify the pre-backup accounts/messages/media and stable server identity. Record elapsed recovery and snapshot age without promising universal timings.
- Exercise restart, rejected ownership/configuration changes, incorrect credentials, certificate replacement and interrupted recovery. Test an actual encrypted conversation and recovery-key flow separately from unencrypted API message checks.
- Demonstrate that a network-only snapshot and stale scheduled runtime never produce a service-protected status. Exercise the explicit backup-scope migration and scheduler afterward.
- Home NAT, real DNS/provider issuance, physical site separation, disconnected institutional use and colleague usability remain external acceptance until run. Do not claim all three product journeys merely because a container starts.

Primary references: [Synapse installation](https://element-hq.github.io/synapse/latest/setup/installation.html), [pinned Synapse image instructions](https://github.com/element-hq/synapse/blob/v1.161.0/docker/README.md), [Element installation](https://github.com/element-hq/element-web/blob/v1.12.29/docs/install.md), [Synapse release](https://github.com/element-hq/synapse/releases/tag/v1.161.0), [Element release](https://github.com/element-hq/element-web/releases/tag/v1.12.29).

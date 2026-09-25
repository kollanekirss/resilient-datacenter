# Matrix services implementation sequence

Execute inline under the approved product scope; no subagents. The design is `../specs/2026-09-25-matrix-services-design.md`. Supplied certificates establish the first tested package slice; guided DNS-01 remains required before advertising automatic certificate operation for home nodes.

1. Strict non-executable service profile and separate immutable application ownership bound to the local network identity. Pin exact upstream linux/amd64 image manifests and configuration digests.
2. Render fixed Synapse/PostgreSQL/Element/proxy configuration. Separate browser origins, closed registration/federation, loopback-only backends, overlay-only HTTPS, no administration proxy routes and private generated secrets.
3. Build root-managed container launch/readiness/stop helpers and constrained systemd units. Verify image identities and container ownership; refuse adoption or replacement of unknown deployments. Perform all privileged tests only in disposable Ubuntu CI.
4. Local preflight/apply/status and guided account setup. Enforce actual enrollment, DNS, trust, ports, disk/memory and independent administration prerequisites. Preserve identities on repeat/resume; do not recreate databases or signing keys.
5. Actual package acceptance: trusted HTTPS, application account login, room/message/media operation, unauthorized access denial and Element browser path. Keep encryption-specific acceptance separate until demonstrated.
6. Add explicit service backup scope and exact-image restore catalogue. Preserve credentials/history during the reviewed network-only → service-scope transition. Replace the protected scheduled runtime only through that explicit transition, serialized with backup/recovery. Exercise encrypted application backup/restore with actual data.
7. Managed service certificates, package health/overdue reporting, beginner instructions, troubleshooting and release evidence. Test supported lifecycle transitions before allowing them; unknown transitions remain blocked.
8. After this package is implemented and verified, continue Nextcloud, regional gateway/bilateral approval, resilient DNS and remaining full-product acceptance. Do not stop at these foundations or mark the whole goal achieved.

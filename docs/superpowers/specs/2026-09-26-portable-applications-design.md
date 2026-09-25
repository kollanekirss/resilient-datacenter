# Portable local applications

Status: design for roadmap stage 4; no deployment acceptance claimed.

## Intended outcome

A prepared institution can cold-start its local chat and files service without
WAN, Headscale, DERP, public DNS or external login. Proxmox hosts separate edge,
DNS/time, NGINX, chat, files and partner VMs. This iteration concerns NGINX and
application access. Relocation, independent controller recovery and a complete
empty-host offline rebuild retain their separate roadmap gates.

## Selected approach

Extend the current pinned application modules with an explicit portable LAN
identity. Keep the existing enrolled overlay identity and its defaults intact.
Do not create dummy Tailscale ownership or bypass its checks. Do not fork a
second application installer: that would duplicate certificate, backup and
upgrade logic and make crisis recovery ambiguous.

NGINX terminates client HTTPS on the frontend VM and uses verified HTTPS to the
existing per-application Caddy listeners. This adds a second proxy hop but keeps
application runtime and certificate operations consistent across profiles.
Caddy is an internal TLS adapter, not a second public frontend. PostgreSQL,
Synapse HTTP, Element assets and Nextcloud Apache remain loopback listeners.

## Access contract

The portable identity binds institution, node, site-plan fingerprint, module,
backend address and frontend address. A profile must explicitly select this
identity. Derive addresses from the validated site plan. Only RFC1918 IPv4 is
supported in this first portable profile. Ordinary overlay profiles must never
accept LAN addresses by accident. A changed address or site fingerprint is a
migration, not an idempotent retry.

NGINX uses literal backend addresses and the permanent service hostname for TLS
SNI and verification. Trust anchors and prepared certificates are local files.
Certificates must cover the planned offline duration plus margin. No automatic
external issuance is needed at boot. Unknown hostnames and mismatched SNI/Host
are rejected. Frontend-to-backend certificate verification must not be disabled.

NGINX replaces forwarding headers using the actual client connection. Each
backend trusts only the declared frontend address, and its local adapter passes
sanitized client information to the loopback application. Source firewall rules
restrict backend HTTPS to NGINX; database and application HTTP ports are never
opened. Test both cross-zone and same-bridge bypass attempts.

## Installation and ownership

Preparation produces inspectable inputs from the site plan; application secrets
and TLS private keys remain private server-side material. The installer checks
Ubuntu 24.04 amd64, local assigned IP, available ports and owned paths before
mutation. It refuses existing unrelated applications, firewall ownership drift
and unreviewed service overrides. Installation is resumable for the exact same
identity. Local service units have no tailscaled dependency in portable mode.

NGINX runs as a separate managed unit with a fixed configuration and narrowly
scoped firewall. Installation cannot replace an existing NGINX configuration or
flush unrelated firewall rules. Proxmox bridge and OPNsense changes remain
explicit console operations. Supply the additional frontend-to-backend rules in
the generated guide.

## Recovery and upgrades

Application snapshots include the access identity and exact rendered
configuration. Validation, restore isolation, certificate replacement and
controlled upgrades understand the selected access mode. Portable recovery
isolates LAN application ingress while validating restored data. It must not
wait for a Tailscale connection. Reject a snapshot or upgrade whose access
identity differs; do not silently migrate it. Preserve local accounts, Matrix
signing keys, Nextcloud identity and database credentials.

NGINX configuration is reproducible from the saved site plan. Keep private TLS
material and local trust anchors in an independent encrypted recovery store.
Do not describe regeneration of NGINX configuration as tested full-host recovery.
Regional federation remains disabled unless separately reviewed for this profile.
No common writable database or automatic writable clone is introduced.

## Acceptance

1. Existing overlay tests remain green.
2. Unit tests reject mixed profiles, malformed identities, changed ownership,
   unsafe addresses, spoofed headers and altered recovery scope.
3. Disposable Ubuntu runs actual NGINX and pinned applications on separate
   isolated network endpoints with no WAN or overlay. Local clients log in,
   exchange a Matrix message, and upload/download a file, then repeat after a
   cold restart.
4. Unknown host, mismatched SNI/Host, untrusted backend certificate, expired
   frontend certificate and direct backend access fail safely.
5. Snapshot validation and upgrade tests exercise portable access as well as
   existing overlay access. Report any unperformed restore explicitly.
6. No vendor server software executes on the preparation Mac. Live Proxmox,
   OPNsense, physical relocation, power runtime and operator acceptance require
   separate evidence and cannot be inferred from hosted Linux tests.

## Primary references

- https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- https://element-hq.github.io/synapse/latest/reverse_proxy.html
- https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/reverse_proxy_configuration.html

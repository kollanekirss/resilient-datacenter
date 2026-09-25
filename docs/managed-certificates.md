# Managed controller and relay certificates

Choose **managed-acme** in the setup wizard only for fresh, dedicated Ubuntu 24.04 amd64 controller/relay hosts. Existing supplied-certificate installations continue to use schema 2. The managed mode uses schema 3 and cannot silently take over an existing installation or Certbot account.

Before choosing it:

1. Point each public DNS name directly at its own server's public IPv4 address. This initial mode requires no AAAA record, DNS proxy or load balancer for that name.
2. Allow inbound TCP 80 for HTTP-01 validation, TCP 443 for the service, and relay UDP 3478 as described in the networking guide. Port 80 must be free on the host. Keep it available for future renewals; the challenge listener runs only when needed.
3. Provide an account email and review the current [Let's Encrypt subscriber agreement](https://letsencrypt.org/repository/). The wizard requires you to type `accept`. Saving configuration authorizes the eventual certificate request when you explicitly apply it; setup itself makes no request.
4. Supply a verified or locally built relay artifact and finish the existing infrastructure review/apply flow.

Managed private keys and the ACME account stay on each server. The operator computer does not receive them. Account registration contacts Let's Encrypt; public certificates expose their DNS names in certificate-transparency logs. This mode requires external DNS, Internet connectivity and a certificate authority. It does not make certificate issuance autonomous during an Internet outage.

## What deployment does

Preflight verifies the strict configuration, ownership, supported platform, direct DNS resolution and free local port 80. It cannot prove Internet-wide inbound reachability. Certbot's actual challenge is the issuance check. A failure stops deployment without substituting an untrusted certificate.

Certbot is installed from Ubuntu's package repository. The deployment obtains one certificate named `rdc-managed` per host, using standalone HTTP-01 and the production Let's Encrypt directory. No issuer URL or shell hook can be supplied in the configuration. The existing generic Certbot timer is disabled only on these fresh, dedicated hosts, and replaced by the project's timer after successful service verification.

The activation helper validates the chain against the host trust store, hostname, key match and remaining validity. It stages protected certificate files, switches the service directory atomically, and checks the certificate actually served over trusted TLS on local port 443. During renewal it restarts the service; this can briefly interrupt controller availability or relay connections. It is not seamless failover. If activation fails, it restores the previous directory and checks recovery. A recovery failure is reported as a failure, never success.

The twice-daily timer includes a randomized delay. It attempts activation even when Certbot says renewal was unnecessary, so an already-issued certificate whose previous activation failed can be retried. It retains the active and preceding certificate generation after a successful replacement. Back up ACME account state separately when implementing disaster recovery; this milestone is not a backup system.

## Status and troubleshooting

On the managed server:

```sh
sudo /usr/local/sbin/rdc-certificate status
sudo systemctl status rdc-certificate-renew.timer
sudo journalctl -u rdc-certificate-renew.service
```

Status reports the last action, current certificate expiry, a warning within 14 days of expiry, and whether the running service presents the expected trusted certificate. Exit zero requires a recorded active state, a verified running certificate and more than 14 days remaining. It reads state and probes TLS; it does not renew, restart or change files.

To explicitly retry renewal and activation after correcting DNS/firewall/issuer issues:

```sh
sudo systemctl start rdc-certificate-renew.service
```

Read logs locally before sharing them; Certbot may include identifying domains and account information. Never copy private keys into a support request. If rollback could not be verified, use independent SSH or provider-console access to inspect the service. Do not delete network identities or certificate state as a troubleshooting shortcut.

Disposable Ubuntu CI tests the actual pinned controller and relay services with a temporary trusted test CA: initial TLS, replacement and a deliberately failed restart followed by verified rollback. This does not test public Let's Encrypt issuance, external DNS/firewalls, renewal after months of operation, NAT traversal or a regional outage. Those acceptance checks remain required before production use.

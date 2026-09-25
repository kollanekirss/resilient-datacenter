# Managed infrastructure certificate lifecycle

Add opt-in infrastructure schema 3 with `tls_mode: managed-acme`, `acme_email` and explicit `acme_terms_accepted: true`. The operator must review Let's Encrypt terms and accept them during setup. Existing schema 2 keeps operator-supplied certificates, with no migration or silent switch. Managed mode is for fresh Ubuntu 24.04 amd64 controller/relay hosts, one public name per host.

Use Ubuntu's Certbot package and standalone HTTP-01 on public TCP 80; actual DNS A/AAAA and inbound reachability remain prerequisites. Keep controller/relay HTTPS on 443. Private keys and ACME account state stay on their target. No DNS API credentials, configurable shell hooks, issuer override, self-signed fallback or trust bypass are accepted in public configuration.

A fixed target-side activation helper validates the certificate hostname, validity, key match and chain. It stages a private certificate generation, atomically switches the service certificate directory, restarts the owned service, and verifies the served certificate fingerprint using a trusted TLS connection. On failure, restore the previous generation and attempt to restart it, recording whether recovery succeeded. Initial activation stages the first valid certificate before service creation; deployment verifies the service after starting it. Existing managed state is checked before renewal or reapply.

A dedicated systemd timer runs renewal and retries activation of already-issued certificates if a previous deploy hook failed. Report both issuance/renewal and activation state. Keep the prior generation for rollback; retention must be bounded without deleting the active or previous version. Status exposes timestamps and expiry, never keys. Installer must guard existing Certbot/state directories and reserve port 80.

Implementation: strict contract and ownership tests; atomic activation failure tests; Certbot role and timer; fresh-host preflight and service templates; wizard and read-only certificate status; syntax/regression checks plus disposable Ubuntu lifecycle acceptance where possible. Public issuance and cross-site resilience remain unverified without actual DNS/hosts. Routine design gates are delegated by the user's instruction to proceed through the goal spec.

References: https://certbot.eff.org/docs/using.html and https://letsencrypt.org/docs/challenge-types/ .

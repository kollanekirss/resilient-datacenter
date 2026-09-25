# Private-service certificate issuer

Implement under the approved full-product mandate, without another design approval gate. Keep the issuer separate from application identity: institutions may use an existing PKI, and replacing the certificate supplier must not rename Matrix users or change the backup database identity.

The first automated provider is explicitly selected Cloudflare DNS-01 with Let's Encrypt production ACME. It can issue browser-trusted certificates for overlay-only services without opening a public HTTP listener. The user must control the public DNS zone and explicitly accept the issuer terms. A restricted API token is entered privately on the managed Ubuntu node and never appears in a profile, process argument, report or public log.

Create a strict non-executable certificate profile bound to the existing local node and the two service names. Use a private dedicated Certbot configuration, work and log directory under `/etc/rdc-service-acme`; do not adopt or alter other Certbot installations. Export verified regular root-owned certificate/key files under its `issued` directory, which the ordinary service profile references. Thus `tls_mode: supplied` continues to describe the application's file-input interface; the separately owned issuer status states whether renewal is automated.

Offer prepare, issue, enable-renewal and status operations. Initial issue does not pretend applications are installed. Enabling renewal requires an installed application with exactly matching names and a successfully verified certificate. The timer executes only a frozen root-managed runtime. Renewal validates both names, chain trust, validity and key matching, switches TLS generations, restarts the owned proxy and checks the live certificates. Failed activation retains/reinstates previous material; an issuer outage does not replace a working certificate. Status reports expiration and issuance/activation separately.

Serialize issuance/activation with application installation, backups and restore. A pending restore blocks activation. The scheduled job never reads executable code from a user's checkout. Refuse unknown administration files, unit overrides and runtime changes. No automatic adoption, shell hooks, arbitrary ACME endpoints or provider plugin selection.

Private provider credentials and the issuer account are independent recovery requirements in this increment. Application backup continues to preserve the replacement's current TLS. Explain that users need independently saved DNS-provider access to bootstrap fresh certificates after total site loss. Do not claim the application snapshot alone recovers a lost provider account.

CI validates commands and secret handling, exercises the installed timer against a controlled issuer boundary, and tests activation/rollback using actual service HTTPS and trusted disposable certificates. Real public DNS/provider issuance requires a user-controlled domain and account, which have not been supplied; keep that acceptance explicitly unrun.

References: [Certbot Cloudflare plugin](https://certbot-dns-cloudflare.readthedocs.io/en/stable/) and [Certbot renewal guide](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

# Matrix and Element: experimental package

This package is being developed on the Matrix services branch. It is not yet a supported institutional release. See the [product acceptance requirements](superpowers/specs/2026-09-25-resilient-services-product-design.md). The released networking archive does not contain this package.

Matrix is the chat server; Element is its browser interface. Each person needs both access to your private network and a separate chat account. Installing a second server does not replicate the first one's accounts or messages automatically.

## Before installation

Use a dedicated Ubuntu 24.04 **amd64** machine with systemd, approximately 4 GiB RAM and at least 12 GiB free disk for the initial package. Allow additional space for messages, uploaded files, local backup staging and retained recovery data. Do not install into an existing container or application deployment. This path is suitable for a full virtual machine; nested containers are not the tested baseline.

1. Complete local-node installation and enrollment. Confirm `sudo ./rdc node status YOUR-NODE-PROFILE` succeeds.
2. Choose a permanent Matrix hostname, for example `matrix.example.org`, and a separate Element hostname such as `chat.example.org`. User identities become `@name:matrix.example.org`. Changing that name later is a migration, not a configuration edit.
3. Arrange for both names to resolve to this node's private overlay IPv4 from the server and user devices. The current checker requires exactly that IPv4 and no IPv6 answer. Private DNS distribution and resilient local resolvers remain separate product work.
4. Obtain a browser-trusted certificate containing both names, using your existing certificate process or the optional DNS issuer below. Place its certificate chain and private key in separate root-owned files on the service node. The key must be readable only by root. Public HTTP validation cannot reach a private overlay-only listener.
5. Keep a console or other independent administration path available. Do not depend entirely on the service being repaired for recovery access.
6. If this node already has scheduled networking backups, disable the schedule before installing applications. After installation, explicitly extend backup scope, take a new snapshot, and re-enable the schedule.

The installer uses pinned upstream container image digests. It installs Ubuntu's Podman and selects runc. It does not publish container ports or replace the host firewall. PostgreSQL, Synapse and Element's static web server listen on loopback; the HTTPS proxy listens only on the overlay address. Open registration, guest accounts and external federation start disabled. Calls, TURN, bridges and SSO are not included in this package.

## Install on the service node

If your public DNS zone is hosted on Cloudflare, the optional issuer can prepare certificates before application installation:

```text
./rdc services issuer setup --output-file inventories/lab/certificates.json
sudo ./rdc services issuer issue inventories/lab/certificates.json
```

The request wizard asks for the node, both names, account email and explicit acceptance of Let's Encrypt's terms. Issue asks privately for a restricted Cloudflare API token. Give it DNS editing permission only for the relevant zones. The token stays in a root-only file on this node; it does not belong in GitHub or the non-secret request profile. Independently save emergency provider access.

Successful issuance exports these two file paths for the ordinary application wizard:

```text
/etc/rdc-service-acme/issued/tls.crt
/etc/rdc-service-acme/issued/tls.key
```

The application's `tls_mode: supplied` describes that file interface. The separate issuer owns issuance and renewal, so replacing a certificate provider does not rename application accounts. The issuer uses a dedicated Certbot directory and refuses to adopt another installation. Public DNS/provider issuance has not been exercised with a real account; this remains an experimental path requiring operator acceptance.

From the reviewed project checkout with its documented Python environment prepared:

```text
./rdc services setup --output-file inventories/lab/matrix.yml
sudo ./rdc services check inventories/lab/matrix.yml
sudo ./rdc services apply inventories/lab/matrix.yml
sudo ./rdc services status
```

If you used the optional issuer, enable its protected renewal timer after the application is working:

```text
sudo ./rdc services issuer enable
sudo ./rdc services issuer status
```

Renewal checks twice daily with a randomized delay. A failed provider request retains the active certificate and reports failure; expiration still eventually interrupts access. The application backup preserves replacement certificates rather than recovering the provider account. A replacement therefore needs valid supplied certificates or independently held DNS-provider access.

The setup questions create a private configuration file. They do not install anything. The check verifies the actual enrolled node, DNS, certificates and available resources. Apply shows the target node and requires its exact confirmation phrase. Run the same profile again to resume an interrupted installation. Existing passwords, database contents and signing keys are retained; changed identities or configuration are blocked for review.

Create the first administrator locally:

```text
sudo ./rdc services account --admin
```

Create ordinary users with `sudo ./rdc services account`. Passwords are entered through a hidden prompt. Do not put passwords in command arguments or public issue reports. The shared registration secret and administration API stay local to the server.

Before signing in, have the controller administrator use the [guided access workflow](operations.md#approve-a-device-to-service-connection) to allow each intended user node to reach the service node on `https` (TCP 443). Apply that reviewed inventory. Enrollment alone grants no application connectivity. Both service names must resolve to the service node on the user device as well as on the server.

On an enrolled and approved user device, open the Element HTTPS address and sign in. Confirm that two users can exchange a message in an invited private room. Save each user's Element recovery key independently when enabling encrypted-history recovery. Server backups do not reconstruct a lost client recovery secret.

## Replace a supplied certificate

Obtain a new trusted certificate covering both service names and a matching private key. Keep the input files root-owned and the key readable only by root, then run:

```text
sudo ./rdc services certificate --certificate /root/new-chain.crt --private-key /root/new-private.key
```

Both names, trust, validity and key matching are checked before activation. The proxy restarts and both live HTTPS endpoints must serve the selected certificate. A failed activation attempts to restore and verify the previous certificate. Replacing a certificate does not change Matrix accounts or application data. This operation does not arrange automatic issuance or renewal.

## Add chat to encrypted backups

First configure and initialize the remote encrypted repository using [the backup guide](backups.md). Keep the repository password and emergency storage access somewhere independent of the service node.

```text
sudo ./rdc backup include-services
sudo ./rdc backup run
sudo ./rdc backup status
sudo ./rdc backup schedule enable --frequency daily
```

The scope transition retains repository credentials and older snapshots. It includes the network identity, application configuration, database, media, signing key and server-held secrets in future snapshots. If a schedule already exists, it also installs the reviewed application-aware backup runtime. A failed transition can be resumed from the same source revision. A previous frozen runtime is retained for administration review.

Networking-only snapshots are not listed as application recovery points. Status distinguishes a snapshot's existence and age from a tested restore. Snapshots briefly pause chat while obtaining a consistent database/files copy, then restart it before encrypted upload. The storage machine should be in another failure domain. This package does not make the storage repository immutable and does not delete snapshots automatically.

## Recover a selected snapshot

Follow the fenced recovery procedure in [the backup guide](backups.md). Install the same reviewed networking and application versions on the replacement, retain the same node and Matrix identities, supply valid replacement certificates, and import independently saved backup credentials. Extend backup scope to Matrix before staging its snapshot.

Review the full snapshot ID and its age. Independently shut down or isolate the old writer before confirming replacement; an unreachable server might still be running. The restore keeps the replacement's current TLS and endpoint configuration and restores application credentials together with their database. It verifies exact component identities and service readiness before releasing its temporary isolation.

Afterward, sign in, read a known older message and download a known file. Test encrypted history separately with the user's saved recovery key. Changes newer than the selected snapshot are not recovered. Record the actual recovery time and data-loss interval from your exercise.

If recovery is interrupted, use `sudo ./rdc backup restore-recover`. Startup guards prevent an unfinished transaction from automatically serving mixed data after reboot. Do not manually delete those guards or the pending transaction marker.

## Implementation evidence and remaining work

Disposable Ubuntu testing has demonstrated actual pinned PostgreSQL/Synapse/Element/proxy startup, trusted HTTPS, two account logins, room access denial and invited message access, media upload/download, and blocked external administration/federation routes. The successful startup run is [36131039798](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36131039798).

The complete [Matrix recovery and browser run 36132446410](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36132446410) passed. Actual scheduled SFTP snapshots preserved credentials and excluded network-only history from application status; recovery retained account sessions, messages, media and signing identity and removed a later message. It also verified certificate replacement and rollback, actual browser login and sending, and encrypted-history recovery in a fresh browser with an independently held recovery key.

That single-host disposable fixture uses a synthetic networking daemon and does not demonstrate home NAT or physical separation. Real DNS/provider issuance, controlled application upgrades, regional federation and colleague usability remain outstanding. The optional issuer's frozen timer has a CI fixture with a simulated external issuer boundary; its acceptance is still pending. That fixture cannot prove public ACME issuance. Do not use these results as a claim that the complete product is ready.

The explicit runc selection follows observed AppArmor failures with Ubuntu's crun combination. CI checks enforced container confinement; it does not disable AppArmor. Related upstream context: [container-libs issue 805](https://github.com/podman-container-tools/container-libs/issues/805).

# Nextcloud file service (development preview)

This package is under active development. Actual application, browser, encrypted backup, fenced recovery and TLS lifecycle checks have passed on disposable Ubuntu runners. See [the validation record](validation-status.md) for exact evidence and remaining boundaries. Do not treat a published draft branch as a supported institutional deployment. The old 0.2.0-alpha.1 download does not contain this package.

## Prepare a file-service node

Use a dedicated Ubuntu 24.04 amd64 VM with systemd, approximately 4 GiB RAM, at least 12 GiB free for the initial package, and additional room for your files and recovery copies. It can share physical hardware with other VMs; that creates a shared hardware and power dependency. For offsite protection, place the backup destination in another failure domain.

Follow the [local-node setup](guided-setup.md) and complete enrollment first. Run installation commands on that Ubuntu VM, from the reviewed project checkout and its documented Python environment. A Mac can prepare profiles but cannot host this package through the installer.

Choose a permanent DNS name such as `files.example.org`. Configure it to resolve to the enrolled node's private overlay IPv4, including on user devices. Provide a trusted certificate and private key for that name as root-owned local files; the private key must be readable only by root. The profile accepts supplied certificate files. The optional isolated DNS issuer below can provide and renew them; actual public-provider issuance still requires operator acceptance.

## Optional automatic certificates

For a Cloudflare-hosted DNS zone, prepare the isolated DNS-01 issuer on the file node before application installation:

```sh
./rdc files issuer setup --output-file inventories/lab/files-certificates.json
sudo ./rdc files issuer issue inventories/lab/files-certificates.json
```

The wizard requests the permanent domain, node identity, account email and explicit agreement to the certificate issuer's terms. Issue asks privately for a restricted DNS token. Restrict it to the relevant zone and retain emergency provider access independently. No public inbound HTTP listener is required for this mode.

Use `/etc/rdc-service-acme/issued/tls.crt` and `/etc/rdc-service-acme/issued/tls.key` as the file paths in the application wizard. After the application is working, enable renewal:

```sh
sudo ./rdc files issuer enable
sudo ./rdc files issuer status
```

The frozen timer checks twice daily. A failed issuer request keeps the current certificate; expiration remains a dependency to monitor. Provider credentials are outside the application backup, so a replacement needs valid certificates or your independently retained provider access. The CI issuer boundary is simulated and does not prove public certificate issuance.

## Install and create accounts

```sh
./rdc files setup --output-file inventories/lab/files.json
sudo ./rdc files check inventories/lab/files.json
sudo ./rdc files apply inventories/lab/files.json
sudo ./rdc files status
```

Setup writes a private profile and changes no servers. Check verifies the intended machine, enrollment, domain, certificate, available capacity and conflicting resources. Apply shows the node and asks for its exact installation phrase. The initial administrator password is entered privately and does not belong in the profile or GitHub.

The package installs pinned Nextcloud, PostgreSQL, a private HTTPS proxy and background jobs. Its application code and steady configuration are read-only. The database and uploaded files remain writable. It refuses to adopt existing unowned applications. Run the same profile to resume; a different hostname, package version or network identity requires a reviewed migration.

For an ordinary account:

```sh
sudo ./rdc files account
```

Have the network administrator approve each intended device's `https` access to the file-service node through [the guided access workflow](operations.md#approve-a-device-to-service-connection). Network membership and file permissions are separate. Sign in at the configured HTTPS address, upload a small test file, and confirm another user cannot read it until explicitly shared. Test removal of that share too.

External federation starts disabled. Public sharing links and downloading extra apps through the app store are disabled in the fixed package. This initial package does not include office-document editing, video calls, external storage, SSO or arbitrary third-party apps. Local accounts and explicitly shared files establish the first supported behavior.

## Protect and recover files

Prepare independent encrypted SFTP storage and save recovery credentials using [the backup guide](backups.md). Then explicitly include this node's file application:

```sh
sudo ./rdc backup include-services
sudo ./rdc backup run
sudo ./rdc backup status
sudo ./rdc backup schedule enable --frequency daily
```

The application scope includes the network identity, database, instance secrets, fixed configuration and uploaded data. Existing network-only snapshots do not protect files. Application code is recreated from the exact pinned image on a replacement. Custom code and themes outside the fixed package are unsupported.

Backup briefly pauses application writers and background scheduling to capture consistent data, restarts service, then uploads encrypted content. This is active service plus recoverable backup; it does not create a second writable copy or provide zero downtime. The backup target is not immutable, and this workflow does not enable host disk encryption or end-to-end file encryption.

For recovery, install the same reviewed versions on an isolated replacement with the same permanent service identity and valid current TLS. Import the independently retained storage credentials, extend backup scope to Nextcloud, and follow the staged/fenced procedure in [the backup guide](backups.md). Independently fence the previous writer before promotion. The replacement keeps its current endpoint and certificate settings.

The staged restore refreshes Nextcloud's client recovery fingerprint while retaining instance identity and secrets. Sync clients may present conflicts or recover newer local files; review those explicitly. This follows the purpose described in [Nextcloud's recovery documentation](https://docs.nextcloud.com/server/stable/admin_manual/maintenance/restore.html#synchronising-with-clients-after-data-recovery). Verify login, a known file's exact contents, another user's permissions and any important shares after recovery. Record the snapshot age and actual recovery duration.

## Replace the HTTPS certificate

```sh
sudo ./rdc files certificate --certificate /root/new-chain.crt --private-key /root/new-key.pem
```

The replacement is checked for trust, name and validity. Activation verifies the live fingerprint and attempts verified rollback on failure. Certificate replacement does not change the permanent Nextcloud identity. For supplied certificates, arrange renewal yourself; the optional issuer provides the separate automated path.

## Evidence

Consult the current [Nextcloud draft pull request](https://github.com/kollanekirss/resilient-datacenter/pull/7) and its disposable Ubuntu checks. Current acceptance is still in progress. Synthetic network addresses, a local test CA and same-runner SFTP cannot establish home NAT, public provider issuance, physical offsite protection or beginner usability.

## Implementation references

Nextcloud 35 includes federation components that cannot be uninstalled. The package disables external sharing through the effective application settings and verifies their values; it does not claim those required components are absent. Public links use `core/shareapi_allow_links`, the setting checked by the [upstream share manager](https://github.com/nextcloud/server/blob/v35.0.1/lib/private/Share20/Manager.php). The [federated share provider](https://github.com/nextcloud/server/blob/v35.0.1/apps/federatedfilesharing/lib/FederatedShareProvider.php) defines the incoming/outgoing sharing controls.

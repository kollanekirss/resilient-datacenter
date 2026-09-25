# Nextcloud package design

Status: implementation next; no support claim yet. This implements the file-service portion of the approved product goal. Routine design choices are delegated by the user's instruction to continue through the whole specification.

## Deployment and identity

Use a dedicated enrolled Ubuntu 24.04 amd64 service VM for the first Nextcloud package. An institution can run the chat VM and file VM on its existing virtualization platform. This keeps their databases, backup ownership and maintenance boundaries separate without purchasing a separate physical server for each application. The guided instructions must show both as parts of the institutional package, and must disclose a shared physical host's failure domain.

Keep the existing local enrollment and explicit HTTPS access workflow. A Nextcloud domain remains stable during recovery. The package uses fixed upstream images, PostgreSQL, a local cache/locking service if required by the selected configuration, background jobs and a private HTTPS proxy. Backends listen only on loopback; the proxy binds only the enrolled overlay address. Local accounts precede optional SSO. Federation starts closed until the regional boundary has a separate tested implementation.

Nextcloud and Matrix have distinct application ownership types. Networking ownership remains unchanged. Prefer small shared primitives for filesystem ownership, image verification, process control and TLS activation, while preserving package-specific configuration and readiness checks. Do not teach the Matrix account or recovery code to accept arbitrary package commands.

## Installation and credentials

Validate the domain, actual node identity, resource availability and a trusted certificate before installation. Pin a concrete upstream image manifest and configuration digest; no floating tag is executed. Hidden prompts collect the initial administrator password. No administrator or database secrets belong in command arguments, generated public examples, support reports or journals. Installation is closed to users until initial database setup and restrictive application configuration finish.

A repeat operation resumes the exact installation and preserves database state and Nextcloud's instance identity. Refuse unknown existing containers, conflicting listeners, altered ownership and unsupported image/schema transitions. Existing third-party Nextcloud installations need a separately reviewed migration path.

## Backups and recovery

Explicitly extend the node's encrypted backup scope to its Nextcloud ownership. The consistent snapshot includes its database, application configuration, instance secrets, uploaded files and supported application state. Pause web access and background writers before capture, restart locally before upload, and retain independent repository credentials. A cache is not the authoritative copy of file data.

Validate exact package versions and the expected resource catalogue before staging. Restore under the existing fenced transaction and startup guards. Retain the replacement's current network endpoint and valid TLS, preserve the stable file-service domain, and repair file ownership without following links. Run Nextcloud's documented post-restore cache/client recovery procedure where required. Never treat an application code downgrade as a safe database rollback.

## Required evidence

All privileged tests run on disposable GitHub-hosted Ubuntu. Exercise actual browser login, file upload/download, a second account denied access to the first account's file, explicitly approved sharing and revocation, actual background-job execution, encrypted SFTP backup, a selected snapshot restore and subsequent byte-for-byte file recovery. Verify instance identity and account continuity and show that changes after the snapshot do not reappear. Test repeated installation, blocked unsupported upgrades and certificate lifecycle. Keep simulated DNS/VPN boundaries explicit.

The package is incomplete until these tests pass. Physical offsite recovery, home NAT, provider issuance and colleague usability remain separate acceptance requirements.

## Certificate issuer reuse

Extend the existing isolated DNS-01 issuer with a distinct `nextcloud-certificates` request containing one file-service hostname. Retain the existing Matrix request unchanged. Both use the same fixed Cloudflare/ACME boundary on their separate dedicated nodes; credentials remain outside application backups. Select the application runtime and TLS directory from the validated request kind, never from arbitrary paths or commands in a profile. Reuse the protected timer and actual live-certificate verification, and extend the disposable issuer test to the file service. A simulated provider failure must leave the active HTTPS certificate usable. Actual public issuance still requires operator provider acceptance.

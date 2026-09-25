# What to prepare before installation

The installer asks for configuration; it cannot create the infrastructure you do not yet have. Start with disposable data. Record who owns each role and who can recover it when your usual chat or password service is unavailable.

## Machines

Use fresh Ubuntu 24.04 amd64 with systemd and root/sudo access. A full VM is the conservative baseline. ARM boards, macOS servers, Windows servers and nested application containers are unsupported deployment targets. A Mac can prepare the plan and manage remote infrastructure.

| Role | Initial planning allowance | Access and placement |
|---|---|---|
| Headscale controller | 2 vCPU, 2 GiB RAM, 20 GiB disk | Public IPv4/DNS/HTTPS; independent SSH or console; offsite for home use |
| DERP relay | 2 vCPU, 2 GiB RAM, 20 GiB disk | Separate machine, public IPv4/DNS, TCP 443 and UDP 3478; bandwidth matters |
| Each chat or file VM | 2 vCPU, 4 GiB RAM, at least 12 GiB free before user data | Local administration and outbound enrollment; one package per VM |
| Each backup target | Size for all retained snapshots and growth | Separate location; dedicated enrolled target per writer |
| Replacement capacity | At least the original service capacity | Independent console and enough free space for download, candidate and retained original data |
| Regional gateway | Dedicated Ubuntu VM; size for traffic and logs | One regional membership, private LAN to service VMs, independent administration |

These are small-pilot planning allowances, not tested production capacity promises. The preflight makes its own minimum checks. Measure CPU, memory, disk and relay bandwidth using your actual workload. Upgrade and restore staging may require multiple copies of application data; a nearly full disk is unsuitable. No automatic backup retention/pruning is enabled.

Separate VMs on one physical host share its power, disk, networking and failure risk. Different VPS labels or providers do not prove separate sites or upstream cables. Verify the physical dependencies and available emergency access.

## Names and certificates

Prepare real controller and relay DNS names resolving to their public IPv4 addresses. Choose permanent Matrix, Element and Nextcloud names. Application names must resolve to their enrolled overlay IPv4 on both service machines and approved user devices. The application checker currently expects that IPv4 and no IPv6 answer.

This project retains the client's existing DNS configuration. It does not install Unbound, configure your router or automatically distribute private DNS. Use your institution's resolver or a carefully maintained small-pilot hosts configuration; test name resolution from each participating device. Keep bootstrap DNS independent of the private network it helps start.

Provide trusted certificate chains and their root-private keys, or use the explicit supported DNS-provider issuer and complete real-provider acceptance. A private CA also requires trust installation on every relevant client through your own device administration. Do not bypass certificate validation. Provider account access and fresh certificate issuance must remain available during recovery.

## Accounts and secrets

Prepare administrator-approved network enrollment and the minimum HTTPS/backup grants. Each person also needs an application account and room/file permission. The current local installer manages Ubuntu nodes; other user devices need a compatible upstream Tailscale client and independently administered Headscale enrollment. General desktop/mobile installation and fleet management are outside this package.

Keep these privately outside the primary site: repository password, writer SSH private key or emergency storage access, storage host-key verification, intended controller identity, stable service domains, reviewed source version, needed certificates/provider access, and the recovery runbook. Matrix users should separately preserve their encryption recovery key; a server backup alone cannot decrypt their encrypted history.

Regional partners additionally need independently verified organisation signing identities, bilateral application approvals and the documented private LAN connection. A familiar institution label is not identity verification.

## Before using real data

Complete [the site acceptance worksheet](site-acceptance.md). Have a second person follow the released instructions without help from the author, including a recovery exercise. Agree on tolerated backup age, maintenance windows, operating responsibility and what to do when status needs attention. CI cannot make those decisions for your institution.

## Managed client diagnostics

Project-managed Ubuntu clients explicitly disable upstream diagnostic uploads with the supported `TS_NO_LOGS_NO_SUPPORT` setting. Local service logs remain available. This applies after installing or reapplying this reviewed node profile; merely downloading a release does not change an existing daemon. Reapplying may restart its networking service, so retain independent administration access. Separately installed desktop/mobile clients need their own privacy configuration. The opt-out limits upstream support based on those diagnostics; see [Tailscale’s logging documentation](https://tailscale.com/docs/features/logging). This is not a claim of zero external traffic: DNS, time, package/image downloads and configured certificate providers remain dependencies.

# Personal installation and fresh-machine recovery evidence

The personal journey runs networking locally on each Ubuntu service machine using outbound enrollment. No public inbound management SSH is required at home. The operator still needs local or independent console access, stable names/certificates, an offsite network authority and separately recoverable credentials.

The disposable home-NAT workflow uses pinned Ubuntu 24.04 cloud images as actual fresh VMs. QEMU user-mode NAT exposes no application ports. Its only forwarding is a loopback-only SSH connection on the disposable host, serving as an independent local console. It installs the real client, runs actual application preflight/installation and uses a separate real enrolled client for HTTPS operations. It authorizes a restricted encrypted SFTP backup writer and stores recovery credentials outside the source VM.

The exercise independently stops the original VM and confirms its process has exited. A new disk and new temporary client identity are created, then the original identity is recovered from encrypted storage before installing and restoring the application. Both network and stable application identities must match, and real saved user data must be readable afterward. The API exercise is automated; it is not an unfamiliar human following the wizard.

## Results

At `596e4aa`, the Matrix job in [run 36165726657](https://github.com/kollanekirss/resilient-datacenter/actions/runs/36165726657) passed this complete path. The selected snapshot was 13.13 seconds old when the original VM was fenced. Recovery and the final user operation took 149.58 seconds, including replacement guest setup from the already downloaded base image. This does not include buying/provisioning a physical machine, downloading the base image or obtaining new public certificates. The Nextcloud job in the same run also passed: its snapshot was 10.22 seconds old at fencing and recovery took 237.15 seconds with the same measurement boundary. Neither time is a guarantee for another site or workload.

This test found two integration defects that prepared-host fixtures had missed: backup executable verification used a different daemon path from the actual installer, and restoration checked enrollment before the restarted client finished loading its identity. The catalogue now matches the installed daemon, and recovery waits under isolation for strict identity readiness. A wrong or permanently unverified identity still fails.

## Boundaries

All VMs, namespaces and controller/backup fixtures share one disposable physical runner. The controller's embedded relay is a fixture; this does not establish a supported combined controller/relay installation. Separate production relays and controller recovery are tested by the infrastructure workflow. Physical home routers, separate power/upstream paths, provider firewalls, public DNS/issuance and unfamiliar-colleague usability remain external exercises.

Matrix's fresh-guest proof uses authenticated API data. Browser login and user-held-key recovery of encrypted chat history are independently tested by the Matrix application workflow. There is no claim that server backups alone decrypt encrypted messages, that a backup destination is immutable, or that an unreachable primary is safely fenced.

Use [the product guide](product-start.md), [backup bootstrap and restore instructions](backups.md#a-fresh-application-or-gateway-replacement) for your own deployment.

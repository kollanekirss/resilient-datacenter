# Personal installation behind NAT and fresh-VM recovery acceptance

This milestone closes the integrated personal journey acceptance gap. It uses two separately created Ubuntu 24.04 amd64 guest disks, with only one active application instance at a time, on a disposable GitHub-hosted Ubuntu runner. No virtualization or downloaded server software runs on the developer computer.

## Test topology and trust

Use QEMU's user-mode NAT, which blocks incoming connections by default. A loopback-only SSH forwarding port is an automated local-console substitute, with an individually pinned guest host key; it is not public management access. No public forwarding for SSH or application ports is added. Actual application use and backups traverse enrolled Tailscale clients. The offsite fixture runs an actual Headscale authority/DERP and an enrolled backup/user node. It is a software simulation on shared physical hardware, not proof of independent sites.

The guest baseline is the official dated Ubuntu image, pinned to Canonical's published SHA256 before use: https://cloud-images.ubuntu.com/noble/20260911/noble-server-cloudimg-amd64.img, SHA256 612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354. See https://cloud-images.ubuntu.com/noble/20260911/SHA256SUMS. Require KVM on the disposable runner and fail clearly if unavailable. Each guest has a fresh writable disk over the verified read-only image, 4 GiB RAM and adequate expandable disk. Only one guest runs at a time.

Cloud-init supplies test CA trust and private administrative access. The exact checked-out repository archive is copied into the guest. Install through the existing local-node engine without replacing its checks. One-use administrator-approved enrollment keys are delivered through private files and removed after use. Private fixture credentials and keys are never artifacts or command-line arguments.

## Sequence

1. Install the local client on the first fresh guest through its own local installation path; verify exact controller, tag and node identity. Reapply the same manifest and verify identity preservation.
2. Install the selected current Matrix or Nextcloud package with supplied test TLS. Create an account and perform an authenticated message/file operation from an enrolled offsite client.
3. Configure a restricted encrypted backup destination reachable through the actual overlay; authorize the writer, include full application scope and take a consistent snapshot. Retain password/SSH recovery material in a private independent fixture vault outside the guest.
4. Prove the selected snapshot contains the expected user data, record its age, and explicitly stop the original VM. The process must be confirmed exited before its identity can be restored elsewhere.
5. Boot a second guest with a distinct fresh disk. Locally install the exact network components. Import independent backup access, download the full snapshot, derive/review/promote its network identity under the existing guarded bootstrap workflow. Never copy live guest state or disks to the replacement.
6. Install the original package identity with TLS on the recovered overlay address. Include full application backup scope; stage and promote the selected full application snapshot. Verify original node key/address, stable application identity, login and actual data from the offsite client. Record measured elapsed recovery and selected snapshot age without an SLA claim.

Matrix and Nextcloud use separate workflow cases. Element browser encryption recovery remains covered by the dedicated application acceptance; this fixture does not pretend a server backup alone restores a user's encryption secrets.

## Boundaries and execution

Physical routers, power, public DNS/certificate providers and a colleague following only released instructions remain external acceptance. This is an integrated software path, not a guarantee of every NAT implementation or continuous service. User authorization is continuous through the goal; execute inline, with author review and no subagents. Keep failures visible and fix underlying implementation problems instead of bypassing checks in the fixture.

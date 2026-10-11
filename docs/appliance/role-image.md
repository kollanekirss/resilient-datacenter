# Linux network-role image

The shared image contains the private guest helper, QEMU guest agent, cloud-init, and pinned Tailscale, Headscale and DERP binaries. Each role receives its own copied disk and one static network interface. The reusable image contains no site configuration, login credentials, controller identity, enrollment key or TLS private key.

**Current evidence:** the official Tailscale 1.104.1 and Headscale 0.29.4 Linux artifacts were downloaded and hashed. DERP 1.104.1 was cross-compiled successfully on the Mac using Go 1.27.1, targeting Linux amd64 with CGO disabled. No Linux binary was executed. The signed package preparation and offline image assembly commands below are implemented and tested with controlled command fixtures; they have not run on a Linux builder. Guest startup, packet behavior and physical testing remain NOT RUN.

## Reviewed binary inputs

The [role input lock](../../appliance/releases/role-image.inputs.json) holds exact extracted binary sizes and hashes, source commit, Go module/toolchain checksums, target and linker flags. The [main release lock](../../appliance/releases/v1.lock.json) holds the official archive and Headscale checksum documents. No derived image hash is invented.

| Input | Source | Verification performed |
| --- | --- | --- |
| Tailscale / tailscaled 1.104.1 | [Official static archive](https://pkgs.tailscale.com/stable/tailscale_1.104.1_amd64.tgz), [artifact checksum](https://pkgs.tailscale.com/stable/tailscale_1.104.1_amd64.tgz.sha256) | Complete 41,130,123-byte archive and both extracted ELF files hashed. |
| Headscale 0.29.4 | [Official Linux executable](https://github.com/juanfont/headscale/releases/download/v0.29.4/headscale_0.29.4_linux_amd64), [checksums](https://github.com/juanfont/headscale/releases/download/v0.29.4/checksums.txt) | Complete 52,457,634-byte executable hashed. |
| derper 1.104.1 | [Tailscale source commit](https://github.com/tailscale/tailscale/tree/9a522a9786c97eb7910c01ccb7bd66557b04c910), `tailscale.com/cmd/derper@v1.104.1` | Cross-build produced 25,810,277 bytes, SHA256 `5187d3a7f0110f2e38e28824a8e618045765058da28b9a20ad0e5e5278e54bf0`. Build embeds exact 1.104.1 version stamps and the source commit. Runtime untested. |

The compiler was the Go module toolchain `go1.27.1` for Darwin amd64. Both module and toolchain downloads were checked by Go's checksum mechanism; their sums are recorded in the input lock. `-trimpath`, `-buildvcs=false` and a cleared build ID remove local build paths and checkout state. A different build host must reproduce the locked Linux executable hash; a mismatch stops preparation.

## Prepare and build later

Use an isolated Ubuntu Linux build machine with the Ubuntu archive keyring, APT, `dpkg-deb`, Go, `qemu-img`, `virt-customize` and `virt-cat`. The image builder needs the verified Ubuntu base image already obtained by the base installer workflow. Run from this repository. Keep the working directory private:

```sh
mkdir -p .work/role-inputs
chmod 700 .work/role-inputs
python3 -m appliance.guest.image prepare-binaries --inputs .work/role-inputs
python3 -m appliance.guest.image prepare \
  --base-manifest .work/role-inputs/base.manifest \
  --inputs .work/role-inputs \
  --output .work/role-inputs/recipe.json
python3 -m appliance.guest.image build \
  --recipe .work/role-inputs/recipe.json \
  --base /path/to/verified/ubuntu-24.04-server-cloudimg-amd64.img \
  --inputs .work/role-inputs \
  --output .work/role-inputs/role-image.qcow2
```

`prepare-binaries` rechecks existing inputs, obtains missing vendor artifacts and cross-builds DERP if necessary. Archive extraction accepts only the two regular files at their expected paths; archive links cannot escape the input directory. No downloaded Linux executable runs on the build host.

`prepare` verifies the [official base package manifest](https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.manifest), pinned to SHA256 `cfe3667617da8f136b7a1673e197d46dbb99cdc248a73f4457ad0ffcfc9796eb`. It creates a separate APT root and package-status file, resolves the required packages against the [Ubuntu snapshot service](https://snapshot.ubuntu.com/) at `20260926T000000Z`, and downloads authenticated package archives. It never installs or upgrades the build host. Historic snapshot metadata expiry is disabled deliberately; signature checking remains enabled through the installed Ubuntu archive keyring. The resulting private recipe records every added archive, exact versions, the complete expected installed package manifest, and authenticated index digests.

`build` refuses unresolved packages. It verifies every input, copies the base image, disables guest networking during customization, installs only the staged package archives, and compares the complete resulting package inventory against the recipe. It clears machine identity, SSH keys, cloud-init seed and all role state. It masks SSH and package-update services, disables all role daemons, and installs the fixed private administration helper. The emitted `.qcow2.json` receipt binds the output bytes to the recipe, runtime source files and service units. Its qualification stays `not-run`.

The initial checked-in template deliberately has an empty package closure. Use the preparation command to resolve it; do not fill it with guessed versions or mark an image qualified manually.

## Import and administer

Use the [role commands](roles.md) to provision the image, supplying its private `--image-receipt` when the receipt is not named `role-image.qcow2.json` in the input directory. This locally built artifact has a distinct receipt path; it does not pretend to be an official vendor download.

Provisioning verifies that the receipt matches current appliance source and the reviewed binary pins, then verifies the image bytes. It refuses a foreign VM ID, changed disk/image, backing image, extra interface or pending operation. Import leaves the guest stopped and disconnected. The seed uses Netplan [ignore-carrier](https://netplan.readthedocs.io/en/1.0/netplan-yaml/#properties-for-all-device-types) with the networkd renderer so the static address and route can be inspected while the virtual cable is still disconnected. First startup binds the immutable role and plan, generates a distinct machine identity, recovers interrupted snapshots and checks image identity, network address/MAC/default route, disabled forwarding/IPv6 and masked SSH before the host permits attachment. A changed plan or authority requires deliberate reconciliation; existing identity is never silently replaced.

Guest administration uses the documented [Proxmox guest execution interface](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc): stdin is limited to 512 KiB, the command path is fixed, and execution is polled by PID. Enrollment credentials and TLS keys never enter command arguments or the config drive. The guest only accepts fixed role actions. Both host and guest save private operation intent before mutation; transport failure leaves an unknown result to inspect rather than repeating enrollment. Fresh observations include both machine identity and the guest kernel boot ID. Only snapshot readback can return private bytes, and those bytes are not retained in status journals.

Before release, run two guest instances to prove distinct identities, actual guest-agent I/O, no SSH/default cloud credentials, one allowed interface, reboot recovery, enrollment response-loss recovery and the role acceptance suites. Cross-compilation and fixture tests do not satisfy these gates.

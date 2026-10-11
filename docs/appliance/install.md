# USB installer and two-port base: development candidate

This implements the USB builder and local host/router control paths. **No image has been boot-qualified and no physical installation has been tested.** Use a disposable x86-64 machine for the first execution. This is not a production release or the complete V1 with optional overlay roles.

## Prepare the image

A Linux build computer needs Python 3.11+, `xorriso`, `squashfs-tools` and `initramfs-tools-core`. It does not need to be the target machine or have KVM merely to assemble the ISO. UEFI boot and Secure Boot disabled are the initial target profile. The adapter pins the exact Proxmox source and refuses an unexpected image layout; updating a release number alone is insufficient.

From the repository:

```sh
mkdir -p .work
./rdc-appliance release-check
./rdc-appliance bundle prepare --cache .cache/appliance-media --output .work/appliance-inputs
./rdc-appliance iso build --bundle .work/appliance-inputs --output .work/appliance-dev.iso --qualification-build
```

`--qualification-build` permits provisional resource allocations for development. It does not waive source, media, disk or network checks. The builder publishes the ISO plus its `.iso.json` receipt, with an image digest and qualification marked `not-run`. It never writes a USB device. Allow at least 12 GiB free during assembly, in addition to the input bundle and cache. The final receipt reports actual ISO size; choose a USB larger than that size rather than assuming a fixed image capacity.

Write the resulting ISO with an image-writing tool, selecting the thumb drive by its observed model and capacity. That action erases the selected USB. Compare the downloaded/built image digest with the receipt and use the tool's write-verification function. Do not use the offline input directory itself as an image.

## Boot and select the machine

Label the two physical cables **Management** and **Internet**. Extra physical NICs remain down. Management connects directly to the administrator's computer; the Internet port connects to the upstream network. V1 supports Ethernet DHCP or explicit static IPv4; staff LAN, wireless, PPPoE and IPv6 are outside this profile.

The custom boot menu has console/serial choices leading to **Install / Repair / Exit**. There is no automatic reinstall timeout. The live entry takes over before upstream network startup and disables IPv6 at the kernel boundary. Actual absence of DHCP/IPv6 traffic remains a required later packet-capture test.

Use an existing site JSON or the local disk/NIC/network wizard. Check permanent MAC addresses, physical cable identity, disk serial/WWN, capacity and existing storage. Before erasure the installer requires the current plan identity and typed target identity, and recollects the machine state. It refuses ambiguous storage, its own boot media, unsafe shared storage and non-target `pve` storage. Cancel if the displayed target is not the intended disposable disk.

Enter a unique local root password. No site password or enrolled identity belongs in the reusable ISO. The pinned official installer performs disk installation; the appliance stages verified code and the router/probe media onto internal storage before announcing completion. A failed or interrupted handoff stops for inspection, never retries erasure automatically.

## First installed boot and local management

Remove the USB after successful staging. Configure the administrator's computer with the plan's `management.admin_ip` and subnet mask; a gateway is unnecessary for direct host access. Open `https://<management.host_ip>:8006` or SSH directly to the numeric address. Check the host certificate/key from its physical console before trusting it. DNS, the router VM and Internet access are not prerequisites for this connection.

The first-boot service verifies staged bytes, restores any pending management transaction, resolves NICs by permanent identity and applies the early management policy. A failure prevents ordinary networking and management services from starting; use the physical console to inspect it. The authenticated console on tty2 is available for local login. Run:

```sh
rdc-appliance menu
rdc-appliance diagnose
rdc-appliance network apply
```

`network apply` prints a transaction ID and private challenge. Within 120 seconds, open a **new SSH login over the management port** and run:

```sh
rdc-appliance network confirm <transaction-id>
```

Enter the challenge at its prompt. Confirmation checks the actual login session, local address, source subnet, current boot and live policy. An expired, old or non-management session cannot approve the change. The independent timer restores known-good management if confirmation does not arrive; reboot also restores an unconfirmed transaction. See [host network details](host-network.md).

## Install and configure OPNsense

```sh
rdc-appliance router install
```

This allocates only the planned owned VM, attaches the locally staged ISO and starts with **every virtual NIC disconnected**. Use the Proxmox VM console to complete the OPNsense installer onto its virtual disk. Shut the guest down after installation, then:

```sh
rdc-appliance router disk-boot
```

This detaches the DVD and limits boot to the owned disk. A running VM alone does not establish an installed or correctly configured router. Complete the private bootstrap files, restricted management channel and console checklist in [router console setup](router-console.md). In particular, disable DHCP/RA on both physical segments before connecting management.

After completing that checklist:

```sh
rdc-appliance router enable-management
rdc-appliance router verify
rdc-appliance router enable-wan
rdc-appliance router policy transit
```

Management activation requires explicit console attestation bound to the current VM boot. WAN activation recollects the router through its pinned SSH channel and requires bootstrap policy with guest forwarding blocked. Transit additionally checks acquired upstream ranges and the local firewall guard before connecting internal zones. Missing, changed or overlapping upstream evidence keeps forwarding blocked. Guest and wire tests are still needed to prove actual behavior.

## Prepare a neutral test guest

The [probe guide](probe.md) prepares a unique private seed and imports the pinned Ubuntu test image already staged on the host. Start the probe disconnected, inspect its console, and attach only its workload interface after the router's fresh transit checks pass. No role enrollment or Internet download is part of this preparation. The [disposable lab guide](lab.md) covers later boot/cancel observations; complete routing acceptance remains a separate exercise.

## Interrupted work and recovery

`status`, `diagnose` and `resume` are inspections; they do not repeat installation or allocate another disk. After a lost VM command response, use `router reconcile`: it compares the actual owned VM with the saved intended result and clears the pending operation only on an exact match. A mismatch remains blocked for inspection. `router reconcile-policy` and `router reconcile-link <zone>` separately acknowledge only already completed policy/link outcomes after fresh inspection; they never replay the mutation.

See [configuration export and repair](repair.md). Optional Headscale, DERP and connector provisioning remains the separate roles milestone. Do not describe this development base as a complete V1 or high-availability system.

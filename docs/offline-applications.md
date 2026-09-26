# Install prepared portable applications without downloads

This increment supports an explicit offline installation mode for portable
Matrix/Element and Nextcloud guests. It does not package all software or rebuild
an empty datacenter. Prepare Ubuntu and the reviewed dependencies while connected,
then check each guest before taking the kit away.

On the intended Ubuntu 24.04 amd64 guest, use the same reviewed source revision
and private site plan as the rest of the portable kit:

```sh
sudo ./rdc portable applications-check /private/site.json --role chat --json
sudo ./rdc portable applications-check /private/site.json --role files --json
```

Run only the command for that guest. This check is read-only: it examines the
platform, required executable paths and actual root-managed Podman image
identities. It never installs, pulls images, resolves service DNS, starts services
or elevates itself. Managed application commands explicitly force local Podman
execution, even if its configuration otherwise selects a remote server. Use sudo deliberately to inspect the image store used by the
installer. A Mac reports blocked and does not execute server binaries.

`application-software-prepared` means only that these prerequisites passed.
Certificate validity, local DNS/time, account access, end-user operations and
recovery still require their own checks. Missing dependencies or unreadable,
malformed or mismatched image metadata produce a blocked result and nonzero exit.
Prepare the exact images in the project's current `service_images.json` or
`nextcloud_images.json` catalogues, not arbitrary newer tags.

Then use the existing guarded installer with an explicit offline requirement:

```sh
sudo ./rdc portable applications-apply /private/site.json --role chat --offline
sudo ./rdc portable applications-apply /private/site.json --role files --offline
```

The offline prerequisite gate runs before a new portable identity is written or
the initial Nextcloud password is requested. The underlying installers repeat the
gate and refuse package acquisition or registry pulls. Missing software is an
actionable failure, never an excuse to use WAN. Existing TLS, platform, ownership,
local address, ingress and application checks still apply. Local DNS and service
connections remain necessary; `--offline` means no software download, not no
network traffic at all. It is accepted only for `applications-apply`.

Follow [portable local applications](portable-local-applications.md) for the
separate DNS/time and NGINX preparation, certificates, account creation, encrypted
backup and fenced restoration. Their software must also be prepared in advance.

## Evidence and boundaries

The disposable portable application workflow now prepares pinned images online,
blocks external egress, and invokes the production installer in offline mode for
each package. It subsequently exercises the existing local access and
WAN-blocked restart/native snapshot restoration checks. Consult the exact branch
run for results; changing the fixture alone is not passing acceptance.

This checks installation onto a prepared Ubuntu guest with cached software.
It does **not** establish acquisition of a complete offline package/image bundle,
an empty-disk whole-site rebuild, public certificate issuance, physical
Proxmox/OPNsense deployment, client CA provisioning, power-loss endurance or
relocation. Those remain required for the self-contained crisis-kit objective.

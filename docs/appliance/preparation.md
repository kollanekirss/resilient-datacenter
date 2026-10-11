# Appliance development commands

The appliance now includes a USB image builder, guarded live installer, installed-host networking/rollback, owned router VM operations and private configuration export/repair. **Boot, guest networking and physical acceptance remain NOT RUN.** The code is a development candidate, not a production release.

Start with the [installation guide](install.md), [router console setup](router-console.md), [host network controls](host-network.md) and [repair guide](repair.md). The [implementation evidence](implementation-progress.md) distinguishes local checks from remaining runtime qualification.

Preparation commands are separate from the older `rdc` service toolkit and use Python 3.11+. They do not change the preparation computer's network or open an installation target:

```sh
./rdc-appliance status
./rdc-appliance inspect
./rdc-appliance release-check
./rdc-appliance preview examples/appliance-site.json
./rdc-appliance attachment examples/appliance-site.json
```

Replace illustrative disk, NIC and address values with observations from the actual machine. `preview` checks consistency, not physical cable placement or permission to erase. `inspect` reports build-computer prerequisites. The live USB collects its own fresh storage/NIC observations; an input JSON file is not an installation capability.

```sh
./rdc-appliance media prepare opnsense-dvd --cache .cache/appliance-media
./rdc-appliance media prepare restic --cache .cache/appliance-media
mkdir -p .work
./rdc-appliance bundle prepare --cache .cache/appliance-media --output .work/appliance-inputs
./rdc-appliance bundle verify --output .work/appliance-inputs
```

The bundle is an offline input directory, **not a bootable image**. It contains pinned Proxmox, OPNsense, probe and Restic inputs. Downloads and decompression are bounded; cached content is reverified. Existing unrelated/incomplete outputs are refused. The single permitted vendor redirect is Restic's official GitHub release path to GitHub's release-assets host. See [release inputs](release-inputs.md).

On Linux with the documented build tools:

```sh
./rdc-appliance iso build --bundle .work/appliance-inputs --output .work/appliance-dev.iso --qualification-build
```

The builder checks exact upstream source/layout and reads back mapped image content. Unknown inputs or missing tools fail explicitly. The development-build flag allows provisional budgets, not weaker destructive or network checks. Image assembly does not qualify its boot behavior. The live console performs per-install confirmation; no `--force` bypass exists.

To inspect host configuration offline, create a ports JSON mapping the observed names, for example `{"management":"enp1s0","wan":"enp2s0"}`, then:

```sh
./rdc-appliance network render examples/appliance-site.json --ports ports.json --output .work/host-preview
```

This writes a new directory of proposed files without applying them. Installed mutations require Linux, root and the staged appliance identity. `status`, `diagnose`, `resume` and archive inspection never silently retry an uncertain operation. The menu is usable without Internet access; the installed local console requires login.

Use `--json` before the subcommand for structured output. A zero exit confirms only the named operation. `configured`, `assembled` and content-integrity `verified` are deliberately distinct from hardware or packet acceptance. The ordinary CI workflow runs software checks only; `scripts/ci_appliance_base.py` defaults to read-only checks and offers an explicit disposable boot/cancel observation; see [lab setup](lab.md). It cannot certify an unexecuted scenario or complete suite.

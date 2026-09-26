# Separate connectivity installer

Start the new connectivity workflow from this development checkout:

```sh
./rdc connectivity install --output-dir /absolute/private/path/my-connectivity
```

**Implemented now: scope explanation, topology planning, private save/resume and stage reporting. No server is contacted, installed or changed by this increment.** Do not use the word `install` in the command as evidence that the deployment adapters already exist. The opening screen states this limitation before asking for input.

Prepare the normal repository Python environment first, as described in the README. Planning works on a preparation computer; it does not run Linux installation commands there. This command does not ask for credentials or download artifacts.

## Opening screen

The installer identifies its purpose, included networking roles, prerequisites and current capabilities. It explains that services are installed separately. Choose `start`, `resume` or `exit`. There is no automatic application installer at the end.

The target networking roles are OPNsense for institutional field access, local DNS/time, institutional Headscale/DERP, and a separate partner gateway with its own regional Headscale/DERP connection. Applications and backups are outside this workflow. Static WireGuard is future work and cannot be selected as a working transport.

## Planning questions

Name the institution and site, Proxmox HTTPS endpoint, node/storage, four distinct bridge names and a reserved RFC1918 IPv4 /16. Bridge names and the subnet are planning intent; this increment does not discover the host, allocate subnets inside that block, detect overlap with live networks or create bridges. Existing management access must be preserved during the later provisioning work.

For each network's coordinator and relay choose:

- `local`: plan to create the role on the local Proxmox host.
- `external`: plan to deploy the role on another independently administered server.
- `existing`: plan to connect to a service already operated elsewhere.

Supply a credential-free HTTPS URL and declare whether the role is domestic or foreign. This first profile assumes the local site is domestic. These declarations do not prove routing or physical independence. Each role requires a distinct DNS hostname; shared endpoint profiles are not implemented. A public IP/port exposure plan and its validation are still required before deployment.

Proxmox URLs accept ports 443 or 8006; coordination/relay URLs use 443. Publicly trusted certificates must be prepared before use. This increment does not verify certificate trust, ownership or validity, enroll clients, or inspect remote endpoints.

The current planner selects one coordinator and one relay per network. It explicitly reports the resulting continuity limitations. Multiple relays, controller continuity and an alternative transport require subsequent implementation and acceptance. A foreign selected dependency prevents claiming domestic-isolation readiness from this plan.

## Save, correct and resume

During questions:

- `:back` revisits the previous question and clears later answers for consistent review.
- `:save` saves the current answers, including an unfinished draft.
- `:cancel` or end of input stops without replacing saved answers.

After the complete preview, type `SAVE` to save or anything else to exit unchanged. The directory is private (0700), and `connectivity.json` is private (0600). Keep the directory outside Git. No application state, tokens, passwords or private keys belong in this record. Unknown fields or unsupported completion claims are refused.

Resume explicitly:

```sh
./rdc connectivity install --resume /absolute/private/path/my-connectivity/connectivity.json
```

Choose `resume` at the opening screen. You can also give the original `--output-dir` and choose `resume`. The installer displays the saved stage report before revisiting answers, with saved values as defaults. It refuses unrelated workspace files, insecure records and stale concurrent saves. Old `site.json` and `journey.json` records are not silently converted or overwritten.

## Stage report

The report lists six stages: host planning/inspection, local edge/bootstrap, coordination/relays, field access, partner connectivity, and continuity exercises. Only the planning component exists in this new workflow. Host inspection has not run; all deployment stages show `unsupported`.

The final checkpoint explicitly shows:

- Built/configured: none; only local planning state was saved.
- Verified: input structure, not host or network health.
- Not yet available: deployment adapters and live acceptance.
- Next step: finish the draft, or implement the host inspection/edge provisioning adapter.

`prepared` means all planning answers were supplied; it does not mean installation finished. Exit code 0 means a plan or draft was saved, 4 means the user stopped, and 3 means a recognized planning/state prerequisite blocked the operation. File-system failures may return the existing CLI failure code 1.

The existing deployment commands remain available separately for their previously documented scope. They are not invoked by this workflow, and they cannot be assumed to consume the new record.

## Next implementation

Follow the [connectivity design](superpowers/specs/2026-09-27-connectivity-foundation-design.md). The next adapter must inspect the actual Proxmox host and create/configure the selected connectivity VMs without inheriting the old fixed application layout. Then integrate coordination/relays, OPNsense field enrollment, the separate partner gateway and live outage verification. The services installer is a separate future entry point, not a stage here.

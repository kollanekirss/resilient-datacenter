# Start with your intended use

This development checkout has a guided route for personal use, institutional chat/files, and a regional partner gateway. It is experimental. The published 0.2.0-alpha.1 download predates this interface and the application packages. Use the source preparation instructions in the README.

## 1. Make a plan on your own computer

Run `./rdc start`. Choose personal, institution or regional, the chat/file services you need, an institution identifier, a responsible operator, primary and recovery location labels, and a new or existing network. Institution defaults to both chat and files. Type `:back` to correct an answer, `:save` to save an unfinished draft, or `:cancel` to stop.

The wizard writes private `journey.json` and `START-HERE.md` files under `inventories/lab/journey` by default. Read the checklist before deploying. Different location labels are a planning aid; check that electricity, upstream connectivity and emergency access are actually independent. A replacement VM is recovery capacity, not a second writable copy of a database.

To resume an unfinished draft, run `./rdc start --resume /absolute/path/draft.yml --output-dir /absolute/path/journey-folder`. Keep this directory private and out of Git. It contains intended infrastructure details, not installation credentials. Existing output bundles require explicit replacement.

## 2. Prepare the machines and access

You still need machines or VMs, domain names you control, and local administration or independent provider-console access. Local node/application installation supports Ubuntu 24.04 amd64 with systemd. Each chat/file package uses its own VM. The controller and relay use the existing remote infrastructure deployment workflow. See the generated machine cards for which network each machine joins.

Personal use can place services at home while the controller and relay are offsite. A second location holds encrypted backups and replacement capacity. Home-router and provider differences still require a real deployment exercise; a simulated test cannot prove your physical connectivity.

Regional use keeps internal services on their institution's own network. A separate gateway joins the regional network and reaches service VMs through the reviewed private LAN connection. Give that gateway a backup target reachable from its regional network. Do not join one ordinary client to two controllers. Partner approval is bilateral and application-specific; joining a network does not itself authorize federation.

## 3. Work through the guide on the appropriate machine

Run `./rdc guide /absolute/path/journey.json`. Select a part, then a task. Each task says which machine it affects. The guide routes to the existing checked operations; it does not install everything merely because a plan was saved. Role wizards collect actual addresses, domains, certificate paths and backup inputs when needed. Domain ownership, DNS and infrastructure procurement remain your responsibility.

Use this order:

1. Prepare or obtain access to the intended network; check and deploy a new controller/relay if needed.
2. Install and enroll each local node, then verify its identity and intended controller.
3. Obtain trusted certificates, install the selected chat/file packages, and create local application accounts. Network approval and application accounts are separate.
4. Test a real login and message or file operation.
5. Prepare independent backup storage; authorize the writer, configure encrypted backups, include the application scope, and take a snapshot. Store recovery credentials privately somewhere accessible during a site outage.
6. Schedule backups, then perform a fenced restore exercise. Explicitly stop the previous instance before recovering its identity elsewhere.
7. For regional use, complete the separate partner approval and gateway/connector steps, then test a real partner exchange.

Copy only the public or private input files needed for each machine, through a trusted administrative channel. Do not copy a live node's identity to a second running node. Follow [chat](matrix-services.md), [files](nextcloud-services.md), [backup/recovery](backups.md) and [regional gateway](regional-gateway.md) guidance for the detailed operations.

## 4. Read current evidence

Run `./rdc status` on each managed server, using your existing local administration permissions if needed. `./rdc status --json` gives machine-readable output. The command never elevates itself, enrolls a client, starts services or repairs configuration. Permission failures, deadlines and incomplete ownership remain unknown. Unsupported preparation computers also show unknown rather than server health.

Six dimensions remain separate: network, applications, certificates, backup, recovery and partners. Exit code 3 means at least one dimension needs attention; exit code 0 only means the displayed checks did not require attention. Neither is a resilience certificate. Service listeners do not prove a user can recover their messages or files, and a running gateway does not prove a partner exchange.

Backup age comes from the consistent snapshot's capture time, not its upload completion. The saved hourly/daily schedule determines overdue status, with a 30-minute grace period; without one, status uses a daily threshold. A failed scheduled attempt stays visible alongside the previous success. If storage cannot be reached, that old success is historical evidence only.

Successful completed restores record capture/completion times and the component versions that were verified. Pending recovery takes precedence over older results. Earlier restores performed before this feature do not gain invented proof. Changed component versions are marked as prior-component evidence. User-operation proof is always separate: finish the exercise with a real login and message/file test, recording the result in your institution's recovery log.

## Still required before a supported deployment

The reviewed upgrade paths and infrastructure outage tests are described in their guides. Both services have [fresh-machine recovery evidence](home-nat-recovery.md) behind simulated NAT; the unfamiliar-colleague exercise remains external. Public DNS/provider issuance, real independent sites and your institution's operational acceptance need real infrastructure and people. The software cannot promise uninterrupted relocation during a network partition or data recovery newer than the last successful snapshot.

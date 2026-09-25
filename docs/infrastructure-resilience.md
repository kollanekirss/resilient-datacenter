# More than one relay location

A relay provides a path when two enrolled devices cannot connect directly. It does not store your messages or files, and adding a relay does not create a second Headscale controller or a second application database.

## Prepare the locations

1. Choose one offsite controller and between one and four dedicated relay machines. Use different power and connectivity providers where practical. Several VMs in the same building do not establish site resilience.
2. Give every relay its own public IPv4 address and DNS name. Each needs TCP 443 and UDP 3478; the managed certificate option also needs public TCP 80 and direct DNS to that machine. Keep the controller address separate.
3. Run `./rdc setup` and select an independent network. The wizard asks for the primary relay, certificate mode and relay count, followed by the additional addresses and names. Supplied certificates require separate matching certificate/key paths. Managed certificates are issued separately on each host after explicit agreement to the issuer's terms.
4. Review and deploy the prepared infrastructure using the [setup guide](guided-setup.md). The controller receives the full relay map. The additional relay machines use their own validated certificate names. Existing one-relay inventories remain compatible.
5. Enroll clients and test a real application operation. During a planned exercise, stop one relay and repeat the operation. Record which relay was used, the interruption and recovery. A direct connection that never used the stopped relay is not evidence of relay failover.

Advanced inventories may add `additional_relays` under `all.vars`, with one to three entries containing `host`, `hostname` and `region_id` (902–999). Each entry must identify a host in the `relay` group; exactly one other host is the primary, which retains region 901. Never reuse a region ID or DNS name for a different active location.

## Protect the controller separately

The controller retains network identities, enrollment and policy. It needs its own consistent encrypted backup, independent recovery credentials and a fenced recovery exercise. Service backups alone do not protect this information.

Controller and relay machines are not automatically enrolled clients. An overlay-only storage endpoint therefore does **not** automatically give them a backup route. Configure a separately reachable, restricted SFTP destination using the [backup guide](backups.md), with a pinned SSH host key and independent encryption credentials. The packaged overlay storage helper serves enrolled nodes; public or privately routed SFTP provisioning remains an administrator prerequisite. Do not expose an unrestricted SSH account or assume that testing storage from a user laptop proves controller reachability.

During controller loss, already established client paths may continue while their cached identities and policies remain usable. New enrollment, policy changes and new relay admissions depend on restored control. Relays deliberately reject admission when controller verification is unavailable. Do not describe this as multiple independent Headscale authorities.

Before restoring the controller, explicitly fence its previous instance. Restore the selected exact-version backup on the prepared owned server and verify its authority identity, existing client access and a fresh enrollment. The disposable acceptance loses and restores controller state while retaining its OS/TLS baseline; a fresh-machine infrastructure rebuild remains a separate operator exercise.

## Evidence and limits

See [validation status](validation-status.md) for source-specific acceptance. The test uses actual pinned Headscale/Tailscale/DERP, private test certificates and Linux namespaces. It blocks direct UDP between two clients, removes the relay carrying traffic, checks HTTPS through the survivor, then restores enrolled controller state from encrypted routed SFTP storage. It also verifies existing client keys/addresses and fresh enrollment after recovery.

A successful simulated-site test does not prove independent electricity, sea cables, physical locations, public issuance or uninterrupted service. Each institution still needs to rehearse its own failure scenarios.

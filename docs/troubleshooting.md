# Troubleshooting without weakening the controls

Start with `./rdc version` and `sudo ./rdc status` on the affected managed server. For networking, run `sudo ./rdc node status /absolute/path/node.yml` and the read-only doctor command documented in [operations](operations.md). Keep independent console access available.

| What you see | What to check next |
|---|---|
| Unsupported platform | Confirm Ubuntu 24.04 amd64 with systemd. Use this computer only for preparation if it is a Mac or another unsupported host. |
| Awaiting enrollment | Verify the intended controller through a trusted channel; have its administrator approve this specific node and tag. Saving a profile does not admit a node. |
| Controller TLS/DNS failure | Check the name resolves to the correct address, system clock, certificate hostname/chain and outbound HTTPS. Do not disable verification. |
| Installed but cannot open chat/files | Confirm enrollment and explicit device-to-service HTTPS grant, resolve the service name to its overlay IPv4, then inspect service/certificate status. Network access and an application account are both required. |
| Works locally but not over the private network | Confirm the real client interface and intended grants. Direct LAN access to an overlay-bound application is deliberately denied; use the approved private-network path. |
| Foreign ownership or changed runtime | Stop. Check whether this is the wrong machine, a different profile or a manually modified installation. Do not delete ownership markers or replace images to bypass the check. |
| Snapshot exists but application is unprotected | Include the selected application in backup scope, take a new full snapshot and verify it. An earlier network-only snapshot cannot recover files or chat. |
| Backup overdue or unreachable | Check destination power/network, approved TCP 2222 path, pinned SSH host key, writer authorization, free space and the last scheduled attempt. A prior success remains historical while storage is unreachable. |
| Restore or upgrade pending | Use independent administration and the matching `backup restore-recover` or `upgrade recover` operation from the same reviewed source. Keep the previous primary fenced. Never delete the pending marker. |
| Restore refused due to components | Obtain the exact reviewed source/binaries corresponding to the selected snapshot. Arbitrary old/new database or helper combinations are not supported migrations. |
| Partner exchange unavailable | Check both approvals, their expiry/revocation, the regional membership, each gateway, trusted TLS and the exact connector. Internal use can remain available while sharing is down. |
| Partner remains closed after restore | This is expected. Review revocation history and obtain fresh bilateral approval; restored historical consent does not automatically reopen exchange. |
| Certificate renewal failed | Check provider access, DNS and time. The previous certificate remains active only until expiry; resolve the failure before that time. |
| Disk fills over time | Inspect snapshot and application growth. Automatic pruning is absent. Arrange reviewed retention with independently retained recovery copies; never delete the only verified copy to make space. |

The status command reports separate evidence. A listener check does not prove user login, and a snapshot does not prove restoration. After repair, repeat the user operation that failed and record its result.

For a public issue, include the commit/version, supported OS, command category, sanitized error and whether this is disposable data. Do not upload inventories, support bundles or logs without inspecting them for secrets and personal data. Suspected security vulnerabilities belong in [private reporting](../SECURITY.md).

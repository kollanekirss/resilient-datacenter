# Guided setup and local installation: live acceptance

All live cases are **NOT RUN**. Local unit tests and mocked subprocess tests are not evidence of a working Ubuntu deployment or NAT traversal.

Use disposable Ubuntu 24.04 amd64 VMs or machines at two private-network locations, plus the offsite controller and relay. Retain console access. Never run a destructive failure experiment on institutional data or the developer workstation.

| Case | Procedure | Required evidence |
|---|---|---|
| Beginner preparation | A colleague unfamiliar with the code follows guided-setup.md, prepares independent output, saves/resumes a draft and transfers manifests | No YAML edits or undocumented assistance; record confusing prompts and missing prerequisites |
| Offsite infrastructure | Apply infrastructure-only configuration with no public service-node addresses | Only controller/relay receive SSH connections; target Headscale configtest and HTTPS checks pass |
| Private-node check/apply | Run local check/apply on both supported Ubuntu nodes through their local consoles | Correct machine/controller summary, trusted TLS, client starts; no public SSH rule or router forwarding needed |
| Admission pending | Start registration before administrator approval | Status remains awaiting enrollment, with no application-health or resilience claim |
| Approval | Authorize tag and register each independently verified pending node | Status becomes enrolled with distinct stable node identities and overlay addresses |
| Wrong controller or tag | Present a conflicting manifest to an already managed node | Installation/enrollment blocked before reset or preference replacement |
| Cancellation/resume | Cancel a pending foreground registration, then approve and resume | Daemon/state retained, existing identity reused, pending information absent from saved reports |
| Rerun/reboot | Record node IDs, rerun matching apply and enroll, reboot each node | IDs retained, existing enrolled nodes skip registration; normal service recovery measured |
| Direct/relay transport | Inspect path diagnostics between authorized lab nodes under normal and constrained NAT conditions | Observed path recorded; relay uses intended infrastructure. Do not treat transport diagnostics as application-policy proof |
| Application restriction | Attempt an explicitly temporary authorized endpoint experiment under a separately reviewed narrow grant | Default deny remains effective for unrelated traffic; do not mistake ping for application authorization |
| Controller/relay loss | Follow the existing outage guide using disposable nodes | Record cached direct connectivity separately from fresh enrollment/relay admission; disclose single points of failure |
| Secret handling | Check retained files/logs after normal and cancelled runs | No private key contents, sudo passwords, registration URLs/IDs or reusable enrollment keys in generated reports |

The infrastructure-only workflow intentionally has no general application grants or automated cross-site endpoint test. A later service-package milestone must define the appropriate application policy and real operation tests. Existing profile test-pair machinery is not an automatic migration path for these newly owned machines.

Keep an acceptance record with UTC timestamps, software versions, topology, selected paths, node identifiers, failures and corrective actions. Redact temporary registration material. A successful installation on one VM does not prove compatibility with both private networks or recovery of future applications.

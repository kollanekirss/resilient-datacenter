# Portable crisis kit: delivery pipeline

Updated 26 September 2026. The objective is an institution-owned kit that keeps
local crisis tools usable at temporary headquarters without external sign-in,
package servers, public DNS or a working regional controller. Federation resumes
only where an approved communication path is available.

| Order | Work | Current state | Acceptance still required |
|---|---|---|---|
| Foundation | Headscale/private relays, restricted regional gateways, Matrix/Element, Nextcloud, consistent encrypted backups | Existing Ubuntu implementation with disposable acceptance; regional application federation already tested | Institution deployment and operational ownership |
| Portable platform | Site planning, guarded Proxmox API adapter, media wizard, edge instructions, local DNS/time, NGINX and local application access | Implemented development components with separate evidence boundaries | Real combined Proxmox/OPNsense deployment, boot and network enforcement |
| 1 | Explicit offline application installation and public role-software bundle | Draft PRs #22/#23; fresh disconnected chat/files bootstrap and native restoration passed | Integration review; OS/hypervisor media remain separate |
| 2 | Encrypted private recovery package | Draft PR #24: local encryption and verified staging; offline synthetic round trip and independent review passed | Integration review and real private-material usability |
| 3 | Recovery readiness report | Draft PR #25: read-only assessment; 38 tests passed with networking disabled | Missing material, actual backup age, certificate coverage for the planned offline period, usable recovery credentials and last successful exercise |
| 4 | Complete disconnected site reconstruction | Draft PR #26: [combined Linux rehearsal](combined-recovery.md) passed (440.34-second synthetic recovery); actual OPNsense/Proxmox still unproven | Recover edge, addressing, DNS, time, frontend and application state together from independently held material; fence original identities; measure recovery time/data loss |
| 5 | Relocation and controlled reconnection | Planned | Keep the internal LAN stable while changing uplink; local use first; portable-profile partner integration, revocation/expiry and partitions; no simultaneous writable clones |
| 6 | Guided operator release | Partial wizard exists; full handover planned | Clear wiring guide, printable offline runbook, client trust/device preparation and an unfamiliar colleague completing the exercise |
| 7 | Physical pilot | Waiting for a suitable disposable hardware environment | Cold boot, abrupt power loss, UPS runtime, capacity, actual relocation and restoration measurements |

The ordering expresses dependencies, not completion dates. Development can continue
with disposable Linux testing before physical hardware exists. Component success
must never be presented as a completed institutional deployment.

## Subsequent or separate work

- Optional SSO/local identity integration, preserving a tested local emergency
  login route. External SSO must not become the sole crisis access method.
- Authenticated domestic controller/bootstrap-address recovery; more DERP relays
  alone do not solve controller availability, and Headscale controllers do not
  federate.
- Additional institution-approved federated services after their access, backup,
  restore and partition behaviour are defined. SharePoint is not currently deployed
  by this kit.
- Application-specific conflict and partition handling. No automatic promise of
  uninterrupted service while moving a powered-off kit, synchronous multi-site
  writes or lossless merging of independently writable replicas.
- Production hardening and external security review before institutional adoption.

The older September 24 connectivity pilot plan is historical context, not the
current completion record. Use [validation status](validation-status.md), the
[portable roadmap](architecture/portable-proxmox-roadmap.md) and individual PR/test
records to distinguish implementation, acceptance and remaining work.

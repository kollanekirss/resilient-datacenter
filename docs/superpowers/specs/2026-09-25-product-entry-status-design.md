# Guided product entry and separate operational evidence

Date: 2026-09-25. Scope: product-completion items 7 and 8. The user has authorized continuing implementation through the product goal without milestone approval pauses. This design refines that existing scope; it does not add a web service, deployment authority or a new network architecture.

## Approach

Extend the existing command interface with a purpose-first `rdc start` journey wizard and `rdc status` summary. Retain the validated deployment, enrollment, service, gateway and backup commands as the execution engine. A separate web installer would add authentication, persistent privileged execution and another recovery dependency; replacing every existing wizard would duplicate validated contracts. A thin guided layer gives novices a coherent sequence while preserving those boundaries.

Preparation and execution remain visibly distinct. A saved journey describes intended machines and next actions; it is never evidence that they were provisioned, enrolled, protected or tested. The existing interactive menu remains backward compatible and adds the new entry/status choices.

## Journey record

A private versioned JSON record contains purpose (personal, institution or regional), institution identifier, selected services, administrator contact label, primary and recovery location labels, network choice (new or existing), and a fixed generated machine-role plan. No passwords, enrollment tokens, signing keys or DNS provider tokens belong in this record. Purpose determines defaults: institution selects chat and files; personal selects chat, files or both; regional requires an existing internal network and a dedicated regional gateway.

Use strict field and enum validation and the existing private bundle writer. Support saving an incomplete draft and resuming it without recreating network or application identity. Prepared outputs include a plain-language checklist with each machine role, the network it joins, prerequisites and exact existing commands. A per-machine guided action menu delegates directly to the existing command dispatcher; it never executes text from saved records or a shell command assembled from user input. Every server-changing operation retains its existing preview, platform checks and explicit operator action.

The role plan uses separate controller and relay hosts, separate chat and file VMs, and an independently placed backup target. Recovery capacity is shown separately from a running replica. Regional gateways join only the regional network and use the reviewed private LAN connection to internal service VMs. The wizard explains that a local application account is separate from network enrollment and that offsite storage needs independent emergency access.

Ask for service domains and certificate/account inputs only in the existing role-specific wizards, where they are validated and applied. Show the order: network preparation and approval; local enrollment; certificate/service setup; local accounts and a real user operation; backup target and access; encrypted snapshot; fenced restore exercise; optional partner approval and exchange. Discover OS/architecture and existing owned role on the local machine for display, but never infer a deployment location or independent failure domain from an IP address.

## Read-only status

Collect bounded local evidence without requesting sudo or changing files/services. Display separate dimensions for network, applications, certificates, backups, recovery and partners. With insufficient permissions, unsupported OS, missing configuration, unavailable commands or a failed probe, report unknown/unavailable and a concrete next action. Do not collapse them into a green resilient badge.

Read only owned, regular, bounded administration records. Reuse existing role-specific checks where they are read-only, with finite subprocess/network timeouts. Sanitize output to fixed summary fields: no secrets, raw exception text, raw VPN JSON, signed agreements or account contents. A malformed or mixed installation is blocked rather than guessed. Lack of a configured application on a network-only node is 'not configured', not a failing application. A configured but stopped application is an attention item.

Network evidence distinguishes enrollment/controller identity from controller availability. Certificate evidence distinguishes configured material, current validity, actual serving verification and automatic-renewal outcome. Backup evidence distinguishes configured destination, last successful attempt, age and present reachability; an old success survives a later failed attempt. Recovery evidence distinguishes completed service verification from a real user-operation exercise, which remains untested until independently recorded. Partner evidence distinguishes signed approvals and running transport from actual federation verification, which is never inferred from a listener.

Add a private local restore-result record after a fully finished successful restore transaction. It includes owned scope, snapshot capture time, completion time and component identity. If the process dies before writing it, status remains unknown. It is not a user-operation certificate or a guarantee that the backup destination still exists. Pending global restore, gateway recovery review, connector suspension and pending certificate/policy operations take precedence over historical success.

## Acceptance

File-only unit tests exercise all three purpose plans, input rejection, private persistence/resume, cancellation, no hidden deployment, and dispatch to the same existing commands. Status tests use bounded probe adapters to verify missing permission, partial failures, stale backup, pending restoration and absent user-operation proof without running daemons on the developer machine. The actual Ubuntu acceptance jobs additionally inspect status before and after their installed service, backup and recovery exercises. A colleague usability exercise still requires a real colleague and cannot be claimed from automated tests.

## Author review

The guided layer owns intent and navigation, not installation completion. The status layer owns evidence presentation, not automatic repair. Existing privilege, identity, secret and independent-fencing boundaries remain in their deployment modules. Location labels are operator declarations and do not establish physical independence. All execution dispatch uses an allowlisted argument structure; saved text is never executable. This is an inline author review, not independent review.

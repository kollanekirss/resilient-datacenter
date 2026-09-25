# Additional relay locations and controller recovery

The product scope requires useful enrolled-client traffic after one relay is lost and after a fenced controller is restored. This milestone extends the existing infrastructure installer, rather than introducing multiple writable Headscale controllers. Physical site diversity, public issuance and provider independence remain external acceptance.

## Design

Keep the existing primary relay and schema 2/3 inventories compatible. Add an optional `additional_relays` list, with one to three entries containing exactly an inventory host name, a distinct DNS hostname and a stable region ID in 902–999. The primary retains region 901. Every additional relay must have a dedicated managed host, unique public IPv4, separate supplied certificate/key or its own managed certificate. Names and region IDs must be unique and match the relay group exactly. Do not allow arbitrary host variables or executable input.

Normalize every infrastructure profile to a complete relay catalogue. Controller DERP maps list each location as a distinct region. Derive each relay's actual hostname from validated data before certificate preflight and deployment. Preserve the existing server ownership schema: managed TLS binds its hostname; supplied TLS retains the existing ownership contract and exact configuration checks. The guided setup asks for the relay count and additional location details, retaining save/back/resume behavior. A label is not evidence of site independence.

Use the existing supported controller and relay binaries. Relay admission remains controller-verified and fail-closed. Do not promise new relay sessions or enrollment while the controller is unavailable. Distinguish already established direct traffic from control-plane operations.

## Acceptance

A disposable Ubuntu test creates an actual controller, two production relay processes and actual enrolled Tailscale clients in isolated Linux network namespaces. Explicit network rules prevent direct UDP connectivity, so successful HTTPS traffic must traverse a relay. Record relay selection, stop the selected relay, and require useful traffic through the surviving region within a bounded test timeout. Temporary interruption is allowed and measured; there is no zero-disruption claim.

For controller recovery, capture a consistent encrypted offsite snapshot with clients enrolled. Fence the original controller process, restore its stable database/noise identity using the owned recovery workflow, verify existing-client traffic and controller identity, and enroll an additional client after recovery. Restoration must not create a new authority or require existing users to re-enroll. An unreachable controller alone is not authority to promote a second writable copy.

The fixture's private CA and simulated sites prove bounded software behavior only. Record current-source results and unsupported cases in validation-status.md. Do not advertise regional resilience from a generated map alone.

## Execution rulings

The user explicitly authorized continuous implementation through the goal. Design and implementation decisions are recorded here without additional approval pauses. Work occurs in an isolated checkout; no downloaded server/client code runs on the developer Mac. Reviews are author reviews because this side conversation prohibits subagents.

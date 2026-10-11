# Joining and optional network hosting

V1 keeps two physical cables: **management** and **Internet**. The connector and
Headscale each use their own Linux VM on the internal infrastructure network.
DERP uses a third VM on a separate, publicly routed virtual network. Proxmox and
OPNsense do not join the overlay. Staff LAN and application deployment remain
outside this version.

The software is a development candidate. Guest image assembly, actual role
execution, public routing and physical testing have not run. Follow the
[qualification record](qualification.md) before treating an installation as
accepted. The [role image guide](role-image.md) describes its pinned inputs and
Linux build boundary.

## Choose each role independently

| Role | What must be available | What does not qualify |
|---|---|---|
| Join an existing network | Approved controller URL, trusted TLS identity, owner approval and a single-use enrollment credential; outbound connectivity | A failed join never authorizes creating a replacement controller |
| Host Headscale | Named authority, public DNS and valid operator-supplied TLS; stable public TCP 443, directly or through explicitly owned upstream forwarding | A private static WAN address alone; declarations without an independent registration and allow/deny test |
| Host standalone DERP | Public IPv4 on the relay VM itself, upstream routed allocation through OPNsense, preserved source addresses, TLS, STUN and a reachable Headscale verifier | Ordinary inbound/outbound NAT, CGNAT, a public address only on the router, unknown-client admission or fail-open verifier behavior |

Two DNS names cannot share the same external IPv4/TCP 443 endpoint in this V1
profile. Use distinct endpoints when hosting both services. The relay verifier
uses Headscale's certificate-matching infrastructure address when co-located;
it does not depend on NAT reflection. A relay never gains general management or
infrastructure access.

Use `roles eligibility` for separate planned prerequisites and `roles inspect`
for actual guest observations and any current, independently signed evidence.
`configured` means local setup exists; it does not mean public reachability was
proved. `unknown` means required evidence is absent or stale. An eligibility
failure retains the existing identity and data.

## Prepare the site before installation

Start with [the base plan](../../examples/appliance-site.json) or the
[three-role example](../../examples/appliance-site-roles.json). Replace every
example disk, NIC, address, endpoint and probe-key identity. Documentation-range
public addresses intentionally fail hosting eligibility. Select only needed
roles; each selected role needs its own VM, unique MAC and static address.

The plan is bound into the router channel, VM ownership and guest seed. Configure
the intended roles before building the site installer. There is no automatic
identity migration to an edited plan. Changing a controller or copying enrolled
state into another live guest is deliberately refused.

Complete the [USB/router path](install.md), then apply the authenticated router
`transit` policy. The two hosting roles' fixed publications and the relay's
no-NAT policy are part of that reviewed plan. Do not replace router XML manually
and assume that the running firewall changed.

## Provision and start a role

After the Linux builder has produced a pinned private image and receipt, run on
the installed appliance:

```sh
rdc-appliance roles provision connector --inputs /root/role-inputs \
  --image-receipt /root/role-inputs/role-image.qcow2.json
rdc-appliance roles start connector
```

Repeat with `headscale` and/or `derp` if selected. Import creates a stopped,
disconnected VM. Start verifies the router's active policy, the owned guest,
the unique guest identity, its image, interface and local restrictions before
connecting its sole interface. Cold starts reconnect existing role state;
they never submit another enrollment credential or create another authority.

An interrupted operation must be inspected with `roles query-operation ROLE ID`
or `roles reconcile-vm ROLE`. Repeating a timed-out mutation is not recovery.
Local management remains usable when any role is unavailable.

## Join an existing network

Place the network owner's authorization in a root-owned directory with mode
0700, in a file with mode 0600. It contains these fields:

```json
{
  "controller": "https://control.example.org",
  "tls_sha256": "REPLACE_WITH_OWNER_VERIFIED_LEAF_CERTIFICATE_SHA256",
  "approved": true,
  "owner_reference": "network-team/approval-123",
  "node_name": "school-connector",
  "expires_at": 0,
  "one_use": true,
  "credential": "REPLACE_WITH_SINGLE_USE_CREDENTIAL"
}
```

Set `expires_at` to a Unix timestamp within the next hour. Compare the controller
certificate identity through an independently trusted owner channel. The guest
checks the certificate's trust chain, hostname and approved fingerprint before
using the credential.

```sh
rdc-appliance roles join --authorization /root/private/network-approval.json
```

The credential travels only through private stdin and is removed from the
guest after use. Protect/delete the operator's source file separately. Public
status and operation journals do not include it. Joining disables advertised
and accepted subnet routes, exit-node use, Tailscale SSH, overlay DNS changes and
IP forwarding. It does not connect staff devices or publish applications.

## Create Headscale or configure DERP

Private credentials contain `certificate_pem`, `private_key_pem` and `trust_pem`.
Headscale additionally requires `authority` matching the deliberately chosen
name in the plan. These files have the same private permissions as enrollment
authorization. The guest checks the real certificate, key, chain, name and
validity before use; a PEM-shaped string is insufficient.

```sh
rdc-appliance roles create-controller --credentials /root/private/controller.json
rdc-appliance roles configure-relay --credentials /root/private/relay.json
```

Headscale starts with a persistent key/database, embedded DERP disabled and an
empty allow policy. Creating it never enrolls the connector automatically.
For disposable verification clients, `roles approve-client --request-file FILE`
accepts `owner_approval`, `registration_id` and `user`. The fixed
`roles set-verification-policy --request-file FILE` accepts `owner_approval`,
`source_ipv4`, `allowed_peer_ipv4` and `denied_peer_ipv4`; it permits only the
declared source to the allowed peer on HTTPS. It does not grant general access.

DERP uses native TLS and explicitly sets verifier fail-open to false. The guest
records a persistent relay identity and refuses NAT-based hosting. Configuring
it does not advertise it to ordinary clients. Full admission and public-path
qualification is still required before publication by the network owner.

Certificate status includes expiry and a 30-day renewal warning. To replace a
certificate deliberately, supply the new private credential file with
`replace_certificate: true` through the same configuration command. The
authority/relay identity is preserved; old external evidence becomes stale.
No automatic ACME or renewal service is assumed.

## Independently verify the result

Register a separately administered probe endpoint in `probe_endpoint` in the
site plan. Its public-key SHA256 and endpoint/host/owner identities must be
obtained independently; a VM on this Proxmox host is not an external endpoint.

```sh
rdc-appliance roles register-probe --public-key /root/probe-public.pem
rdc-appliance roles probe-request enrollment --targets /root/private/targets.json \
  --output /root/private/challenge.json
```

The targets document contains a `targets` array. Each entry has `id`, HTTPS
`url`, `expect` (`allowed`, `denied`, `denied-control` or `public-tls`),
`peer_identity` and `tls_sha256`. Public hosting targets also specify
`expected_ipv4`. Allowed/control listeners must echo the nonce and authenticated
peer identity. The denied peer's independent control must confirm the exact
listener is up; a dead service is not an isolation result.

For an enrollment challenge, every `allowed` target must name the actual
connector node identity collected locally by the appliance. The disposable lab
must provide a controlled HTTPS probe listener on that connector; an unrelated
reachable peer cannot verify it. This external-to-connector measurement proves
that inbound test path only. It does not establish the connector's outbound
allow/deny policy or complete network acceptance, which remain separate tests.

On the registered endpoint, run `python3 -m appliance.probe_agent --request
challenge.json --private-key probe-private.pem` and return its signed JSON to
`roles verify-probe --receipt FILE`. Challenges expire after 15 minutes and bind
the plan, build, targets, guest identities, policy, certificate and runtime.
Unknown keys, altered targets, stale challenges or restarts invalidate evidence.

Use the [qualification procedure](qualification.md) for the dedicated
controller/relay collectors. The generic HTTPS collector cannot prove fresh
registration, forced relay use or admission during verifier failure. Missing
measurements remain unknown; neither matching configuration nor a signature on
an incomplete test qualifies hosting.

## Export and recovery

`export create` captures each selected role in turn during a bounded maintenance
pause, copies its complete declared state (including SQLite sidecars), and
attempts to restart the original even on capture failure. Private chunks travel
over the guest agent. The resulting package is encrypted using the existing
Restic path, then read back and verified before publication. Aggregate export
size is currently bounded at 8 MiB; larger state fails explicitly.

An inspected export validates component hashes without starting restored
identities. V1's automatic recovery claim remains the isolated router copy.
Full controller reconstruction, automatic failover and moving an active
authority to another box are outside this release. Keep the export password
separate from the appliance and the encrypted copy.

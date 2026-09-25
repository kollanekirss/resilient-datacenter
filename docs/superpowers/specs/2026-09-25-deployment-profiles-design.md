# Independent and join deployment profiles

Status: approved by the user and implemented locally, 2026-09-25. Live deployment is unverified; see [validation status](../../validation-status.md).

## Purpose

Enable another institution to use the public deployment toolkit in either of two ways:

1. Create and administer its own private network and service nodes.
2. Deploy its own service nodes into a network administered by another institution.

An independently operated installation must remain independent when it later adds approved service federation. Federation does not merge controllers, transfer administrative ownership, replicate all data, or promise uninterrupted service.

This milestone establishes deployment profiles and a shared configuration contract. An interactive wizard, real applications, partner federation and production high availability follow in separate milestones.

## Existing implementation

The current kit assumes exactly one controller named control-01, one relay named relay-01 and peers named server-a and server-b. Its policy grants only reciprocal TCP 8443 between two fixed tags. Test endpoints require certificates and a fixed peer pairing.

The new implementation will separate basic node deployment from this optional two-node connectivity experiment. Existing identities and running deployments must not be silently rewritten.

## Profile behavior

| Capability | independent | join |
|---|---|---|
| Create local controller | Required: exactly one in this milestone | Prohibited |
| Create local relay | Required: exactly one in this milestone | Prohibited |
| Install service-node clients | One or more nodes | One or more nodes |
| Manage controller policy | Locally owned new controller only | Never |
| Approve enrollment | Local controller administrator | Existing network administrator |
| Reset or move enrolled nodes | Never during routine deployment | Never during routine deployment |
| Deploy test HTTPS endpoints | Optional separate stage | Optional, with remote access approval |
| Cross-institution federation | Future optional capability | Future optional capability |

Join mode must not require a controller management IP, controller SSH credentials, relay build artifact, or controller/relay private keys. The external controller URL is a connection destination, never an Ansible target.

Both modes initially support fresh Ubuntu 24.04 amd64 targets and public IPv4 management addresses. Arbitrary virtualization platforms and operating systems remain outside this milestone. One controller and one relay are an explicitly limited topology, not HA.

## Configuration contract

Keep one static YAML inventory per environment, compatible with the existing Ansible workflow. Introduce these common variables:

- `schema_version`: integer 1 for the new profile format.
- `deployment_mode`: exactly `independent` or `join`.
- `institution_id`: stable lowercase identifier used for local deployment ownership; it does not grant network authority.
- `headscale_hostname`: DNS hostname, without scheme/path; deployment derives the HTTPS URL.

Common node fields:

- Stable inventory name, distinct across all groups.
- `ansible_host`, `ansible_user`, optional `ansible_port`.
- `node_tag`: explicitly assigned machine tag. In join mode the receiving administrator must authorize this exact tag before enrollment.

Independent-only variables retain `derp_hostname`, `enrollment_admin`, `derper_artifact` and `derper_sha256`. Controller/relay hosts require certificate and key source paths. Independent mode requires groups `controller`, `relay` and `peers`; the controller and relay each contain one host, while peers contains one or more.

Join mode contains only the `peers` group. Reject controller/relay groups and independent-only variables instead of silently ignoring them. Peers do not need application certificates merely to install the network client.

Deployment secrets remain outside the inventory: use the SSH agent/configuration, protected certificate files and explicit enrollment approval. Do not accept reusable enrollment tokens in this format. Real inventories remain excluded from Git.

### Independent example: conceptual inputs

```yaml
all:
  vars:
    schema_version: 1
    deployment_mode: independent
    institution_id: institution-a
    headscale_hostname: control.example.com
    derp_hostname: relay.example.com
    enrollment_admin: lab-admin
    derper_artifact: /absolute/path/to/derper-linux-amd64
    derper_sha256: REPLACE_WITH_VERIFIED_SHA256
  children:
    controller:
      hosts:
        a-control:
          ansible_host: 192.0.2.10
          ansible_user: ubuntu
          tls_certificate: /absolute/path/to/control.crt
          tls_private_key: /absolute/path/to/control.key
    relay:
      hosts:
        a-relay:
          ansible_host: 192.0.2.20
          ansible_user: ubuntu
          tls_certificate: /absolute/path/to/relay.crt
          tls_private_key: /absolute/path/to/relay.key
    peers:
      hosts:
        a-services:
          ansible_host: 192.0.2.30
          ansible_user: ubuntu
          node_tag: tag:institution-a-services
```

### Join example: conceptual inputs

```yaml
all:
  vars:
    schema_version: 1
    deployment_mode: join
    institution_id: institution-b
    headscale_hostname: existing-network.example.com
  children:
    peers:
      hosts:
        b-services:
          ansible_host: 192.0.2.40
          ansible_user: ubuntu
          node_tag: tag:institution-b-services
```

These examples intentionally use invalid deployment placeholders. They illustrate the implemented format; replace placeholders before deployment validation.

## Access policy and enrollment

For a new independent installation, generate explicit tag ownership and an empty grant list. Default inter-node application access is denied until the administrator adds an explicit permitted connection. Do not grant full mesh access merely because nodes share an institution identifier.

For the optional pilot endpoint, accept an explicit test pair of distinct managed peer names and generate only the two TCP 8443 grants required by that pair. Other nodes gain no application access. General application policies are a later milestone.

Join mode never modifies the remote controller policy. Produce a nonsecret enrollment summary containing the institution identifier, requested host names and tags, and any requested pilot access. The remote administrator checks the request independently, authorizes tags, and approves each pending node registration. Installation success does not imply admission or application access.

The joining institution can revoke local participation by a deliberate operator action. The controller administrator can revoke network admission. Neither action can retract data already shared through an application.

## Optional two-node test profile

Move endpoint certificates, the test CA and peer pairing out of mandatory base deployment inputs. A top-level variable `connectivity_test` is absent by default; when enabled it names exactly two managed peer inventory names through `nodes`, and supplies `ca_certificate`. Only those two peer records then require `test_dns_name`, `tls_certificate` and `tls_private_key`.

Derive reciprocal pairing from the selected two-node list. Do not require every service node to have a partner. The existing HTTPS identity and denied-port tests continue to operate on that pair, using discovered overlay addresses.

In independent mode the local controller grants the two test connections. In join mode the administrator receives the requested grant description; deployment does not apply it remotely. Verification must fail honestly if authorization has not been granted.

The endpoint's accepted identity values must change from the fixed server-a/server-b names to validated inventory node identifiers. Overlay-only binding and TLS verification remain mandatory.

Cross-inventory testing against a partner's private servers is not included in this milestone.

## Deployment sequence

1. Select a profile and prepare the matching example inventory.
2. Validate schema, required/forbidden fields, unique hosts, addresses and paths locally.
3. Run read-only preflight on locally managed targets only.
4. Independent: install controller, relay and clients. Join: install clients only.
5. Display profile-specific enrollment instructions and the requested node tags.
6. Administrator approves enrollment through the selected controller.
7. Read back node identity, controller URL and accepted tag; reject mismatches.
8. Optionally install the test endpoints and run the explicit pair's acceptance checks.
9. Save reports that distinguish installed, awaiting approval, enrolled, tested and not-run results.

No cloud resource purchases, DNS creation, automatic certificate issuance or remote publication are part of these commands.

## Identity, reruns and compatibility

Store a nonsecret ownership record on each managed host containing the schema version, institution identifier, role and intended controller hostname. Validate it before mutation. A profile change or controller mismatch is a migration request and must fail with a clear explanation, including when an enrolled daemon is stopped.

Never delete or recreate persistent client/controller state as part of profile deployment. Enrollment remains explicit and separate. A failed initial installation must be recoverable by rerunning the same profile without acquiring authority over unrelated pre-existing software.

Preserve the current unversioned four-host pilot as a documented legacy format in its existing validation/deployment path. Add profile-specific entry points rather than silently interpreting the old inventory as a new default-deny deployment. Existing deployments continue to receive their original policy until an operator deliberately migrates them. Automatic migration is outside this milestone.

Keep the shared controller/client/relay roles reusable, but ensure legacy callers preserve their original defaults while new callers provide derived controller and relay inventory names. The new path must contain no hardcoded control-01, relay-01, server-a or server-b assumptions.

## Future wizard and federation interfaces

The future wizard generates this same validated configuration; it must not become a second deployment engine. It can ask for profile, institution identifier, host details, controller hostname and profile-specific TLS/artifact inputs, then show a reviewable summary.

Connecting independent institutions later adds separately approved application endpoints. It does not switch an institution's nodes to another controller. Gateway transport, partner identity verification, allowed services, revocation and optional data replication need their own design and acceptance tests. Do not accept a federation configuration section until that capability is implemented; unsupported settings must fail rather than imply success.

## Implementation acceptance criteria

- Legacy tests and syntax checks remain passing.
- Valid independent and join inputs pass local schema checks; placeholders fail deployment checks.
- Independent mode handles arbitrary valid inventory names and one, two and several peers.
- Join inputs require no relay executable or controller/relay certificate files.
- Join inventory rejects controller/relay targets and remote-management credentials.
- Join deployment has no tasks capable of changing the external controller, relay or policy.
- New independent policies deny inter-node application traffic by default; only an explicitly enabled test pair gains TCP 8443 access.
- Invalid/duplicate tags, duplicate host identities and conflicting configuration fail before mutation.
- Reruns preserve persistent state and reject an unintended controller/profile change.
- Optional test configuration rejects unknown, identical or more than two peer names.
- Ansible syntax and task selection are tested for both profiles; template tests are not reported as live deployment success.
- Documentation provides independent, join and legacy workflows, with limitations and explicit approval responsibilities.

Live installation, enrollment, policy enforcement and outage/recovery results remain NOT RUN until real servers are available.

## Next step after review

The implementation plan is complete and local checks pass. Proceed to live validation when servers, DNS, certificates and management access are available. The wizard and service federation remain subsequent milestones. No Git repository or remote publication has been created.

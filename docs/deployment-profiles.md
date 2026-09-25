# Independent and join deployment profiles

Status: implemented and locally checked; real deployment and recovery remain NOT RUN. These are advanced operator workflows for Ubuntu 24.04 amd64 machines with reachable public IPv4 management addresses. A separate guided wizard and local-node installation path now exist; see guided-setup.md. This SSH-managed path retains its original limits. Real home-NAT deployment, Matrix/Element, Nextcloud, backups and regional gateways remain unverified or unimplemented as documented.

## Choose the correct ownership model

| Profile | Locally managed machines | External administrator needed? |
|---|---|---|
| Independent | One controller, one relay, one or more service-node clients | No external network administrator; you operate your controller |
| Join | One or more service-node clients | Yes: the existing network operator authorizes tags, enrollment and permitted connections |

Join mode does not install, SSH into or change the existing controller/relay. You supply its DNS hostname only. It is not a gateway between two networks: each installed client joins one network. The future regional gateway will expose selected services while preserving institutional network boundaries.

Independent mode starts with **no permitted inter-node application connections**. An optional explicit test pair adds only TCP 8443 in both directions. No general subnet routing or exit-node access is enabled. One controller/relay is not high availability.

## Prepare local tools

Run all commands from the project directory after following the README's Python environment setup. Local tooling uses Python 3.11 or newer. Keep strict SSH host-key verification and confirm your target's host key independently. An SSH agent/configuration supplies credentials; do not put passwords or private keys in inventory YAML.

Choose fresh machines. Existing unowned installations, including legacy pilot installations, are rejected. Migration is a separate operation, never an automatic response to a failed check.

### Independent environment

```sh
mkdir -p inventories/lab
cp inventories/examples/independent/hosts.yml inventories/lab/independent.yml
.venv/bin/python scripts/build_derper.py
```

Edit the copied file: set your institution identifier, arbitrary stable lowercase host names, public management IPs, SSH users, distinct controller/relay DNS names, certificate/key paths, relay executable path/checksum and service-node tag(s). The controller and relay need publicly trusted certificates and working DNS. The base service nodes need no application certificates.

Keep `schema_version: 1` and `deployment_mode: independent`. The controller and relay groups each have one machine; peers may contain one or more. All managed IPs, node names and peer tags must be distinct. A tag is a requested authorization label, not proof of institutional identity.

```sh
.venv/bin/python scripts/validate_profile.py inventories/lab/independent.yml --mode independent
.venv/bin/ansible-playbook -i inventories/lab/independent.yml playbooks/profile-preflight.yml
.venv/bin/ansible-playbook -i inventories/lab/independent.yml playbooks/profile-independent.yml
```

### Join an existing environment

```sh
mkdir -p inventories/lab
cp inventories/examples/join/hosts.yml inventories/lab/join.yml
```

Edit your institution identifier, the existing controller's hostname and each local node's management IP, SSH user and requested tag. Confirm the intended controller with its operator through a trusted channel. Do not obtain controller SSH credentials, controller/relay private keys or a DERP artifact: join mode does not require them and rejects controller/relay configuration.

```sh
.venv/bin/python scripts/validate_profile.py inventories/lab/join.yml --mode join
.venv/bin/ansible-playbook -i inventories/lab/join.yml playbooks/profile-preflight.yml
.venv/bin/ansible-playbook -i inventories/lab/join.yml playbooks/profile-join.yml
```

A wrong-profile entry point fails before remote access. Preflight reads local inputs and target facts/ownership; it does not install services. The deployment claims only the validated local machines, then installs the client without registering or resetting it.

## Explicit enrollment

Substitute your actual private inventory path in the following commands:

```sh
.venv/bin/ansible-playbook -i inventories/lab/join.yml playbooks/profile-enrollment.yml
```

The read-only enrollment playbook shows each node's current state and a node-specific `tailscale up` command. It also displays a nonsecret administrator request listing node names, requested tags and any requested test grants. It sends no request and approves nothing.

1. For an independent network, create the configured enrollment administrator once on the controller (for example `sudo headscale users create lab-admin` after checking `sudo headscale users list`). The controller policy assigns the configured tags to this administrator.
2. For join mode, give the displayed request to the existing administrator. They must authorize those tags and any required application connections under their own policy. The join installer cannot do this.
3. On each node needing enrollment, run its displayed command. The request keeps DNS/route acceptance and Tailscale SSH disabled.
4. Verify the printed pending authentication ID and machine identity independently. The controller administrator registers it using the pinned Headscale workflow: `sudo headscale auth register --user ADMIN-NAME --auth-id=PENDING-ID`.
5. Rerun profile-enrollment.yml. Require `enrolled`, the intended controller, exactly the requested tag and one valid overlay IPv4 address. A running daemon alone does not establish these facts.

Do not rerun enrollment commands on already enrolled nodes as a repair procedure. Do not use logout, reset or forced reauthentication during routine deployment. Treat pending registration links/IDs as sensitive and temporary; keep them out of Git.

Enrollment reports are saved as `artifacts/enrollment-NODE.json`, with UTC generation time and application/restore results explicitly not-run. Normal deployment reports client installation separately; it does not claim enrollment or application health.

## Optional two-node connectivity experiment

This remains a test endpoint, not Matrix or Nextcloud. You need two peers in the same managed inventory. Add this under `all.vars`:

```yaml
connectivity_test:
  nodes: [south-services, second-peer]
  ca_certificate: /absolute/path/to/test-ca.crt
```

Ensure both names exist under `peers.hosts`. Add these fields to each selected peer, using distinct valid service names and matching certificate material:

```yaml
test_dns_name: service-a.your-actual-domain.ee
tls_certificate: /absolute/path/to/service-a-fullchain.crt
tls_private_key: /absolute/path/to/service-a.key
```

Every peer also keeps its management IP, SSH user and unique node_tag. Peer certificates are checked against the supplied CA. Unselected peers must not carry test certificate settings; their role remains client installation only.

For an independent environment, rerun its deployment after enabling/changing the pair so its policy has the two corresponding TCP 8443 grants. For join mode, request these grants from the existing network administrator. Local deployment never modifies that remote policy.

```sh
.venv/bin/ansible-playbook -i inventories/lab/independent.yml playbooks/profile-test-services.yml
.venv/bin/ansible-playbook -i inventories/lab/independent.yml playbooks/profile-verify.yml
```

Use join.yml instead when testing the join profile. Test stages reject an absent pair, unknown nodes, duplicate nodes and unapproved identities. Only the selected two nodes receive the test endpoint; an unrelated third peer receives no test grant or endpoint installation.

Verification checks real HTTPS with CA and hostname validation, then runs the explicit known-listener denial experiment on ports 22 and 8444. The temporary 8444 service expires after 120 seconds and has failure cleanup. If SSH is not listening on overlay TCP 22, the denial experiment is inconclusive/failing, not a policy pass. See acceptance.md for firewall attribution and outage procedures.

Positive and negative reports are separate, timestamped files under artifacts/. Inspect the current run's exit status; an old successful report does not establish a later run passed. Neither the endpoint nor its tests imply replicated application data or automatic failover.

## Reruns and ownership

New deployments store `/etc/server-connectivity-profile.json` on each managed machine. It records the institution, mode, role and controller hostname. Routine reruns require exact equality and preserve existing state. Changing controller, mode, institution identifier or role requires a reviewed migration.

If a peer has persistent identity state but its daemon is stopped, the deployment stops rather than guessing its controller. Inspect the machine through independent management access, start the existing daemon when appropriate, then rerun. This is a conservative deployment safeguard, not automatic recovery orchestration.

The new profiles refuse legacy/unowned installations. The legacy deployment now also refuses hosts carrying a versioned profile marker, so it cannot accidentally replace the new deny-by-default policy. Do not delete markers to bypass these checks.

The profile preflight expects a complete run: do not use `--limit`, `--tags`, `--skip-tags`, or check mode. It rejects these partial modes; skipped local validation also blocks the remote guard. Use `--syntax-check` for offline parsing and profile-preflight.yml for read-only checks. `--list-hosts`/`--list-tasks` do not contact targets, but the optional pair is created dynamically and is only visible during execution.

Follow-up enrollment and test commands currently require the same local deployment files for full preflight validation. Keep private inventory and supplied certificate/artifact files available to the operator.

## What follows this milestone

The separate guided wizard and local-node installer are locally implemented; live Linux/NAT acceptance is pending. Matrix/Element, Nextcloud, encrypted backup/restore and regional gateways each need their own implementation and live acceptance. See the expanded product specification for the complete personal/institutional/regional goal.

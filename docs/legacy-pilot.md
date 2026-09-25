# Legacy four-VPS connectivity pilot

This is the original network-only operator workflow. For the current guided product, start at [the README](../README.md). Commands run from the repository root. Relative documentation links below refer to repository files.

## Legacy four-VPS workflow

1. Read [network prerequisites](networking.md).
2. Prepare your local tools and build the relay artifact below.
3. Obtain the four VPSs, two public DNS names and appropriate TLS certificates.
4. Fill and validate your private inventory.
5. Run read-only preflight, then deploy.
6. [Enroll the two servers](enrollment.md) through administrator approval.
7. Deploy test endpoints and run connectivity and isolation tests.
8. Work through [outage and recovery acceptance](acceptance.md) before adding real institutional services.

The [detailed colleague plan](colleague-project-plan.md) explains the wider project. The commands below describe the implemented kit and take precedence over illustrative paths or names in earlier planning documents.

## Local preparation — no VPS required

Use Python 3.11 or newer, OpenSSL and Go 1.21 or newer. Run these commands from this project directory. They create project-local dependencies and caches. Dependency downloads require internet access.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/check_local.py
.venv/bin/python scripts/build_derper.py
```

The relay helper selects **Go 1.26.6** and **tailscale.com v1.102.4**, cross-builds for Linux/amd64, and records the SHA256 in `artifacts/derper-build.json`. Module downloads use Go's checksum database; the resolved module checksums are retained in `artifacts/derper-go.sum`. It does not install Go or binaries globally. Keep the build metadata alongside an archived deployment release. Rebuilds after a toolchain or source change are a new release to test, not an automatic upgrade.

Build artifacts are ignored by Git. A fresh clone must build the relay or obtain a verified release artifact.

## Prepare deployment inputs

Suggested small lab starting point: 2 vCPU, 2 GB RAM and 20 GB disk per VPS, spread across at least two providers/locations. These are sizing assumptions for a connectivity pilot, not a production capacity recommendation.

```sh
mkdir -p inventories/lab
cp inventories/example/hosts.yml inventories/lab/hosts.yml
```

Edit only the private copy. Supply four distinct public IPv4 management addresses, SSH usernames, actual controller/relay DNS names, absolute local certificate/key paths, and the relay artifact path/checksum. Keep host names, group names, tags and peer pairings as supplied. Custom inventory plugins, arbitrary Ansible overrides and embedded credentials are intentionally outside this first version.

Certificates:

- Controller and relay: public-CA certificates with matching DNS SANs and full intermediate chains. Their names must resolve before deployment.
- Test endpoints: SANs matching `test_dns_name`; an institutional test CA is acceptable. Supply its PEM trust bundle as `test_ca_certificate`. Public DNS records for these endpoint names are unnecessary for the tests, which explicitly resolve them to discovered overlay addresses.
- Keys: unencrypted PEM, stored outside source control. The validator checks certificate dates, SANs and key matching; it also checks test endpoint chains against the supplied trust bundle. Public trust and reachability for controller/relay must be verified live.
- Renewal: your institution must issue/renew these certificates. Update the local files and redeploy the affected stage before expiry. This kit does not automate issuance or renewal.

Use an SSH agent or your SSH configuration for management keys; retain host-key verification. Confirm host keys through provider console or another trusted channel before Ansible. Sudo access is required; add `--ask-become-pass` if your institution requires an interactive sudo password.

```sh
.venv/bin/python scripts/validate_inventory.py inventories/lab/hosts.yml
.venv/bin/ansible-playbook -i inventories/lab/hosts.yml playbooks/preflight.yml
```

Preflight validates local inputs and reads target state without installing services. It rejects unsupported operating systems, unowned existing installations and a running managed client using another controller. Use fresh VPSs; this is not a migration tool. Ordinary check mode cannot simulate a fresh installation end to end because target binaries do not yet exist. `--syntax-check` is an offline syntax check only.

## Deploy and enroll

```sh
.venv/bin/ansible-playbook -i inventories/lab/hosts.yml playbooks/deploy.yml
```

Deployment preserves `/var/lib/headscale`, `/var/lib/sc-derp` and `/var/lib/tailscale`. It does not register or reset nodes. Review [enrollment](enrollment.md), register each node, then run:

```sh
.venv/bin/ansible-playbook -i inventories/lab/hosts.yml playbooks/test-services.yml
.venv/bin/ansible-playbook -i inventories/lab/hosts.yml playbooks/verify.yml
.venv/bin/ansible-playbook -i inventories/lab/hosts.yml playbooks/verify-deny.yml
```

Run the full inventory without `--limit` or `--tags`; this small pilot expects all four hosts and both peers. Positive verification checks real HTTPS responses, certificate trust, hostname and server identity in both directions. Diagnostic `tailscale ping` output is separate: it does not prove application-policy access. Denial verification temporarily starts port 8444, confirms its local HTTPS response, confirms local SSH on port 22, then tests both remote ports. A refused connection is inconclusive and fails the check. Cleanup runs after failures; the temporary service also expires after 120 seconds.

Successful live checks write separate per-server JSON reports under `artifacts/`. A failed run does not constitute acceptance; use command exit status and fresh report timestamps, not an old file. Denied-port results must be checked against host/provider firewall rules before attributing the result specifically to Headscale policy.


# Live acceptance: record evidence, not assumptions

All scenarios below currently have status **NOT RUN**. Use disposable lab servers, test data and independent SSH/provider console access. Record UTC start/end times, versions, node IDs, overlay IPs, relevant firewall rules, command exit status, service logs and actual user-visible outage duration. Keep evidence private. Do not infer an outage pass from a successful local template test.

## 1. Baseline and direct path

Run deploy, enroll, test-services and verify in README order. Confirm A→B and B→A HTTPS return the expected identities with trusted certificates. Inspect `tailscale ping` diagnostics and `tailscale status` during traffic. Record whether a direct endpoint or `DERP(pilot)` was used; a relay-only baseline is not a direct-path pass. Check that test listeners bind only the discovered overlay addresses with `sudo ss -lntp`. Confirm public-interface TCP 8443 is unavailable separately.

Run `verify-deny.yml`. It first repeats the positive tests, starts a temporary HTTPS listener on 8444 on both servers, confirms local HTTPS identity, checks local SSH on overlay TCP 22, and attempts the remote ports. Only timeouts count as blocked. If SSH binds only a different address/port, that test is inconclusive: document the institutional SSH binding instead of opening public access. A closed/refused port never proves the policy worked. Inspect overlay host firewall rules so another firewall is not silently providing the result attributed to Headscale.

## 2. Private relay fallback

Save the existing provider firewall configuration. At the provider layer, temporarily block only **peer-to-peer UDP** in both directions, leaving administration, controller/relay HTTPS, relay UDP 3478, DNS and time traffic available. Do not blanket-block all UDP or flush a host firewall. Confirm both peers receive the private DERP map with only region 901. Inspect `tailscale netcheck`, repeated path diagnostics, status and relay logs. Repeat actual HTTPS tests and require observed use of the selected private relay. Record interruption and time to reconnect; retries may be needed and seamless failover is not promised. Restore the saved rules and confirm direct connectivity returns. If the provider cannot express this narrowly, design a provider-specific experiment before proceeding.

This approximates a lost direct path, not a complete regional isolation event. A severed sea cable only affects this design when it removes the relevant routes; placement labels alone do not prove path diversity.

## 3. Controller outage

With baseline working, record existing connections and stop Headscale on the controller using `sudo systemctl stop headscale`. Test separately: an existing direct session, new HTTPS sessions over the existing peer map, policy propagation, attempted new enrollment, and a fresh DERP connection. Avoid conflating an already admitted relay connection with new admission. DERP verification is fail-closed, so fresh admission may fail without the controller. Restore with `sudo systemctl start headscale`, confirm service health, then rerun positive tests. Record this limitation even if some direct traffic survived.

## 4. Relay outage

With direct paths available, stop `sc-derp` on relay-01 and verify real direct application traffic. Then combine the unavailable relay with a narrowly blocked direct path in a separate controlled test: failure is expected with this single-relay topology. Start the relay and restore saved rules; confirm recovery. Never describe this four-server arrangement as relay high availability.

## 5. Peer reboot and deployment rerun

Save node IDs and overlay addresses. Reboot one peer through its management channel, measure detection and service recovery, then repeat for the other. Repeat deploy and test-services without reenrollment. Node IDs and overlay addresses must remain unchanged. Distinguish expected certificate/config service restarts from unintended identity replacement. Inspect the second Ansible recap for unexpected changes; true idempotence is a live check, not guaranteed by syntax validation.

## 6. Location change and full loss

For an address change, use a controlled provider operation while preserving the peer's local identity. Update management inventory/firewall rules, verify management access, and measure overlay reconnection and HTTPS recovery. A server that is powered off cannot serve its local application; overlay identity continuity does not replicate storage or make requests interruption-free.

For complete server loss, use the recovery guide. Do not boot two clones of the same node identity. Record recovery time and any unrecoverable state. Regional power loss and complete internet isolation require independent power/connectivity plus application replicas outside the affected region; this pilot does not supply those features.

## 7. Backup restore

Use the consistent offline controller backup in recovery.md. Restore into an isolated network, with the original controller fenced off before activating its identity. Verify node lists and policy, then test connectivity against the intended DNS endpoint. Record actual recovery time and backup age. A backup existing on disk is not a successful restore test.

## Acceptance decision

Require both positive directions, both denied ports in both directions with known listeners, observed private-relay fallback, recovery after restored direct rules, stable identities after rerun/reboot, and a demonstrated controller restore. Document controller/relay single points of failure and measured disruption. Any unperformed or inconclusive check remains NOT RUN/INCONCLUSIVE, never PASS. Application federation, institutional SSO, multi-region replication and production availability commitments are later milestones.

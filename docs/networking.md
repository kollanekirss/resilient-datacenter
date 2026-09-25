# Network, TLS and administration prerequisites

The kit does not change provider firewalls, replace a host firewall or modify the operator's computer networking. An institutional operator must review existing controls before installation. Keep provider console access and source-limited management SSH available independently of Headscale.

| Destination | Inbound traffic | Purpose / source scope |
|---|---|---|
| All VPSs | Management SSH, normally TCP 22 | Administrator's fixed source addresses only |
| control-01 | TCP 443 | Headscale HTTPS from peers, relay and authorized future clients |
| relay-01 | TCP 443 | DERP HTTPS from peers and authorized future clients |
| relay-01 | UDP 3478 | STUN from peers |
| server-a, server-b | UDP 41641 | Direct overlay transport, initially other peer's public IP |
| Peers on tailscale0 | TCP 8443 | Test application, additionally restricted by Headscale grants |
| Peers on public interfaces | No TCP 8443/8444 allowance | Test service must never bind the public address |

Permit return traffic and required outbound DNS, HTTPS, NTP and direct UDP. The relay needs outbound HTTPS to the controller's `/verify` endpoint. Peers need controller/relay HTTPS, relay STUN and each other's direct UDP. Package installation also needs Ubuntu repositories and the upstream artifact hosts. NAT/provider filtering can prevent direct paths even when these rules appear correct.

Publish controller/relay A records to the corresponding public addresses. Avoid an HTTPS CDN/proxy for this initial pilot. Do not publish AAAA records unless IPv6 service/listener/firewall support has been deliberately configured and tested. This kit's management and DERP map profile use IPv4. Overlay IPv6 addresses can exist but application tests use IPv4.

Controller metrics and management gRPC bind loopback. No public metrics endpoint or API key is required for this workflow. DERP's auxiliary HTTP listener is disabled, so the supplied-certificate workflow does not need public TCP 80.

Use CA-trusted certificates and correct clocks. From the relay and peers, verify the controller hostname with a normal TLS-verifying HTTPS client before enrollment. Do the same for the relay from each peer; an HTTP error for an unrecognized path may be legitimate, but certificate/hostname/connection failures are not. Check service logs for details. Never add insecure certificate bypass flags to make acceptance pass.

The node clients retain their existing resolver settings: this version does not enable MagicDNS or override local DNS. Public DNS and management access are bootstrap dependencies and remain necessary during outages. Future local DNS must not depend exclusively on a network that itself requires that DNS to start.

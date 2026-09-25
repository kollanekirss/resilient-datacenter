# Explicit administrator-approved enrollment

Deploy infrastructure first and confirm controller/relay HTTPS trust. Commands below use illustrative domains: replace them with inventory values. The `lab-admin` name must match `enrollment_admin`. Run controller commands with sudo on **control-01**, client commands on the named peer. Do not run client commands on the operator's laptop.

1. On the controller, inspect the running version and service, and create the enrollment user once:

```sh
sudo headscale version
sudo systemctl status headscale --no-pager
sudo headscale users list
sudo headscale users create lab-admin
```

If that exact user already exists, do not recreate it. This user owns both permitted machine tags for the pilot. Production institutions need an explicit enrollment/approval governance design; do not assume this single administrator model provides institutional independence.

2. On **server-a**:

```sh
sudo /usr/local/bin/tailscale up --login-server=https://CONTROL-DNS-NAME --hostname=server-a --advertise-tags=tag:institution-a-server --accept-dns=false --accept-routes=false --ssh=false
```

3. Follow the printed registration URL. Extract the pending authentication ID and verify the requesting machine with your independent management session. On **control-01**, approve only that pending request:

```sh
sudo headscale auth register --user lab-admin --auth-id=AUTH-ID-FROM-REGISTRATION
```

Treat registration links/IDs as sensitive, temporary material. Do not commit them or share them in public tickets. Do not grant reusable preauthorization keys for this first pilot.

4. Repeat on **server-b**, changing hostname and tag:

```sh
sudo /usr/local/bin/tailscale up --login-server=https://CONTROL-DNS-NAME --hostname=server-b --advertise-tags=tag:institution-b-server --accept-dns=false --accept-routes=false --ssh=false
```

Approve B's own authentication ID on the controller. Do not reuse A's ID.

5. Inspect both registered nodes:

```sh
sudo headscale nodes list
```

On each peer:

```sh
sudo /usr/local/bin/tailscale status --json
sudo /usr/local/bin/tailscale debug prefs
sudo /usr/local/bin/tailscale ip -4
```

Require `BackendState: Running`, the correct tag, distinct persistent overlay IPv4 addresses, and the intended `ControlURL`. Diagnose rejected tags or unexpected identities before deploying test services. Do not use `--reset`, logout or delete state to “repair” a routine rerun. A controller change is a separate migration.

6. From the operator workstation run `playbooks/test-services.yml`, then `playbooks/verify.yml` as shown in the README.

The authentication command syntax was checked against Headscale v0.29.4 source. Its execution and interoperability with the selected clients remain live acceptance requirements. Consult the installed binary's `--help` if a future upgrade changes the CLI; update and retest the release together.

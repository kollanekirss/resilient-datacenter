# Version provenance

Checked against upstream release/source endpoints on 2026-09-24. Versions are pinned for this pilot, not a claim that future releases should be installed without testing.

| Component | Selected version / provenance |
|---|---|
| Headscale | v0.29.4, official Linux amd64 DEB |
| Tailscale clients | 1.102.4, official static Linux amd64 archive |
| DERP | `tailscale.com/cmd/derper` from module v1.102.4 |
| DERP compiler | Go 1.26.6, selected through Go toolchain download |
| Local validation | ansible-core 2.19.5, pytest 8.4.2, PyYAML 6.0.3, cryptography 46.0.3 |

Headscale DEB SHA256:
`1f65364716ae1fcc3845b1a65a47583469022e9c6f194dfdfeb25403f89f0841`

Tailscale archive SHA256:
`50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9`

Locally built Linux amd64 DERP SHA256:
`1ae593bc6e4d31c774538982cd6400f6503e053d6a15f9373f98aa5e141f85e5`

The local build's metadata and module checksums are in `artifacts/derper-build.json` and `artifacts/derper-go.sum`. A checksum verifies that deployment uses the reviewed artifact; it does not substitute for source trust or a production supply-chain review. The Python lock snapshot in `requirements-lock.txt` captures this local environment; `requirements.txt` declares the direct development dependencies.

Official references:

- [Headscale release v0.29.4](https://github.com/juanfont/headscale/releases/tag/v0.29.4)
- [Headscale release checksums](https://github.com/juanfont/headscale/releases/download/v0.29.4/checksums.txt)
- [Exact-release configuration example](https://github.com/juanfont/headscale/blob/v0.29.4/config-example.yaml)
- [Exact-release registration CLI](https://github.com/juanfont/headscale/blob/v0.29.4/cmd/headscale/cli/auth.go)
- [Exact-release configtest implementation](https://github.com/juanfont/headscale/blob/v0.29.4/cmd/headscale/cli/configtest.go)
- [Headscale policy documentation](https://headscale.net/stable/ref/policy/)
- [Headscale DERP documentation](https://headscale.net/stable/ref/derp/)
- [Tailscale static archive checksum](https://pkgs.tailscale.com/stable/tailscale_1.102.4_amd64.tgz.sha256)
- [DERP source at v1.102.4](https://github.com/tailscale/tailscale/tree/v1.102.4/cmd/derper)
- [Selected module's Go requirement](https://github.com/tailscale/tailscale/blob/v1.102.4/go.mod)

Source checks confirmed manual certificate filenames `<hostname>.crt` and `<hostname>.key`, verification callback flags, the explicit fail-open override, and `headscale auth register --user --auth-id`. The staged Headscale configuration is checked by the actual target binary before activation during deployment. That runtime check has **not** run on a VPS yet. The local structural policy tests are weaker than runtime policy validation and live packet-level enforcement tests.

# Verified experimental releases

Releases package the networking foundation. They do not yet include Matrix/Element, Nextcloud, automatic recovery or verified production resilience. The downloaded relay targets **Linux amd64**; configuration and verification may run on macOS. There is no ARM binary and no automatic installation or upgrade.

## Download

Start from a reviewed checkout of this repository and prepare its Python environment as described in the main README. Install the official [GitHub CLI](https://cli.github.com/) with support for `gh attestation verify` and the source/signer policy flags below. Authenticate it to GitHub if required. The project does not install GitHub CLI or request a token inside its wizard.

Find a specific experimental release and its full source commit on the repository's Releases page. Check the tagged source and workflow; never take an expected commit from an untrusted mirror.

```sh
./rdc release fetch 0.2.0-alpha.1 --commit FULL_40_CHARACTER_COMMIT --output-dir "$PWD/artifacts/verified-alpha1"
```

The version is an example; use a published version. The output's parent directory must already exist, belong to you, and not allow other users to write. The destination must not exist. No symlink parents are accepted. A release fetch requires network access to GitHub and its attestation trust services; offline verification is not yet provided.

The command downloads into a private staging directory. It verifies each artifact using the fixed project repository, `.github/workflows/release.yml`, exact tag and source/signer commit, and refuses attestations from self-hosted runners. It then checks the strict manifest and SHA-256 hashes. Verification errors never fall back to checksum-only trust. GitHub CLI must itself be trusted; this is not a way to authenticate a malicious initial checkout or compromised maintainer.

On success the output contains:

- `derper-linux-amd64`: relay executable bytes, intentionally without execute permission locally.
- `source.tar.gz`: tracked source at the exact tagged commit, with a single project prefix.
- `derper-build.json`: source, module, toolchain and checksum information.
- `notices.tar.gz`: dependency licenses, copyright notices, scanner report and warnings, Go notices, and dependency locks.
- `release-manifest.json`: exact release identity, target and SHA-256 hashes.

Keep the notices with any redistributed relay. Fetch does not extract archives, launch a downloaded program, replace your checkout, or change servers. For deployment, supply the verified relay path and its manifest checksum to the existing setup flow. Its configuration and ownership checks still apply. Verification is evidence of origin and integrity, not proof that the software is secure or production-ready.

## Maintainer publication

1. Review and merge changes, pass CI, and set `project-version.json` to a specific `alpha.N`, `beta.N` or `rc.N` version with channel `prerelease`.
2. Review the pinned Go/Tailscale inputs in `build/derper/`, `scripts/build_derper.py` and the dependency license report. The build blocks new/unclassified license families instead of silently omitting them. The initial approved families are MIT, BSD-2-Clause, BSD-3-Clause, ISC and Apache-2.0; all license and notice files must remain in the distribution. Assembly scanner warnings are retained for review; CGO is disabled.
3. Create and push the corresponding `vVERSION` tag at the reviewed commit. Do not retarget a published tag.
4. Manually run **Experimental release** using that tag. Ordinary pushes/PRs cannot publish. The workflow must exist on the default branch for dispatch to be available.
5. The workflow runs the local suite, builds the pinned relay, gathers notices, archives exact source, signs all assets using GitHub attestations and creates a prerelease. Existing releases are not overwritten. A failed run does not establish a published release; inspect the run and resolve the problem before retrying.
6. Download the published release through `rdc release fetch` with its exact source commit. Record this real verification separately from unit tests. Promotion to a supported release additionally requires the live acceptance exercises in the product specification.

Release-job permissions are limited to repository content publication, OIDC signing and attestations. The ordinary CI job remains read-only. The build uses a GitHub-hosted Ubuntu runner and pinned action commits. This is provenance, not a claim of SLSA certification or independently reproducible builds.

References: [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations), [verification policy flags](https://cli.github.com/manual/gh_attestation_verify), [dependency notice tool](https://github.com/google/go-licenses).

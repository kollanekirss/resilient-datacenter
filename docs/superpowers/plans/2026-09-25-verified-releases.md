# Verified experimental releases

The approved distribution increment adds an explicitly requested tagged prerelease, never a release on ordinary push or PR. A maintainer runs the workflow on a prerelease tag; its commit, ref, repository and workflow are required during verification. The release is experimental and does not imply runtime acceptance.

Deliver one bundle containing the relay, source archive, dependency license material, build metadata and a strict manifest. The checksum list and each asset are attested. The downloader requires an explicit version and expected commit, uses the fixed project repository/workflow, rejects self-hosted signing, and checks both signed provenance and manifest hashes. Downloads stay in a private staging directory until every check passes. It never extracts archives, installs executables or overwrites an existing output directory. Preparation on macOS is allowed; the bundled executable remains Linux amd64 only.

Build with pinned Tailscale and Go versions. Collect dependency license texts and report using a pinned go-licenses tool; fail on unknown or unreviewed license classes. Include Go's own license and bundled third-party notices. Record build inputs and source revision; do not claim fully reproducible or independently audited builds.

Implementation order: failure-first verification tests; downloader and CLI; build and manifest tests; release builder and dependency notices; pinned manual release workflow; documentation, whole suite and CI. Verification uses GitHub CLI with fixed policy flags and bounded calls. GitHub authentication/trust remains a bootstrap dependency, documented explicitly. No bypass flag is provided.

The user delegated routine design approval on 2026-09-25 and asked not to stop between milestones. Work remains isolated, and no service runs on the developer Mac.

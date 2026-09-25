# Recover an application node's network identity before reinstalling its services

Date: 2026-09-25. This closes a gap found during gateway recovery review. Existing disposable application recovery restores a prepared installation; a fresh replacement initially has a different enrolled VPN identity/address. A signed gateway cannot be installed against that different address, and retaining service listeners for the temporary address would also be incorrect after restoring the original VPN state.

## Chosen sequence

Use a two-stage fenced recovery on a fresh supported Ubuntu peer. First install/enroll the replacement temporarily into the intended controller, with the same recorded institution and node labels and explicit temporary storage access. Import independently saved repository credentials. Select the exact full application snapshot and the expected package. Download and validate its entire fixed catalogue and ownership without executing any archived code. Derive a private network-only staging directory containing only the recorded Tailscale state and network ownership manifest, with the corresponding original binary hashes and capture time.

The operator reviews the source snapshot identity, package, institution, node/controller and capture time, independently fences the old instance, then invokes the existing journalled network restore. It checks the exact network binaries, retains the replacement's local ownership configuration, restores the original VPN identity and verifies enrollment while service ingress is isolated. No application may already be installed on the replacement. The selected repository snapshot remains unchanged.

Once the original network address is restored, install the same reviewed application/gateway component version and identities with a fresh valid certificate. Extend backup scope explicitly to that package, stage the same original full snapshot through the normal path, then restore application data. Gateway restoration retains the fresh certificate and demands newly issued bilateral approvals. Application connectors remain suspended. No automatic takeover, identity reset, alternate controller or execution of archived scripts is introduced.

## Why this approach

A full operating-system image would require a separate boot/recovery product. Installing a gateway against a temporary unsigned address weakens the signed identity contract. A narrowly derived network stage reuses the existing isolation, exact component check, independent fencing and durable journal, while addressing the dependency in the correct order. Downloading and validating the full source also ensures application recovery material is available before switching network identity.

## Interface and boundaries

Add `backup bootstrap-stage SNAPSHOT --package matrix|nextcloud|gateway`, `bootstrap-plan SNAPSHOT` and `bootstrap-apply SNAPSHOT`. Store source and derived data separately under private `WORK/bootstrap/SNAPSHOT/`. The normal `restore-recover` journal handles interrupted promotion. Require network-only configured scope and no installed or partly installed application directories. No bootstrap operation initializes a repository. A package selector is a constraint checked against authenticated snapshot metadata, not a script name.

The stage validates the complete source with existing package validators, compares its network ownership to the replacement, and verifies the source network-component hashes against the installed binaries. The derived stage has exactly the existing network snapshot schema and paths; it cannot contain an application file or a link outside the narrower catalogue. Revalidate source identity and the derived stage before every plan/apply, refuse existing stages rather than silently overwrite, and never accept `latest` or an abbreviated identifier. A failed preparation removes only its newly created private workspace.

Review output states that this changes the replacement's VPN identity and requires independent console/administration access. Apply requires a distinct explicit fencing phrase. Saved drafts/status are never evidence that fencing happened. Commands dispatch structured arguments; metadata paths, labels and signed content are never executed.

## Acceptance

File tests verify source/package/owner mismatch refusal, exact network binary checks, narrow resource extraction, escape-link denial, immutable repository/source data, refusal on an installed application, and interrupted recovery. Disposable Ubuntu acceptance exercises real encrypted extraction and the journalled identity stage, then reinstalls/restores the gateway behind closed review. Actual enrolled-client identity/address continuity requires the separate real Headscale/Tailscale replacement acceptance, not the synthetic gateway fixture. Keep these evidence boundaries explicit until both pass.

## Review

This is an inline author review. Network identity is restored only from an authenticated, strictly validated package snapshot owned by the same institution/node/controller. Later unsnapshotted data cannot be recovered. Application component compatibility is checked before full application promotion; bootstrap checks only the components it actually restores. Independent old-instance fencing and retained backup credentials remain external operator responsibilities.

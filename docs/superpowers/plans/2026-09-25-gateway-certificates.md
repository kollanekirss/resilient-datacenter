# Gateway certificate activation implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. Subagents are prohibited in this side conversation. Continue under the user's explicit goal-completion mandate.

**Goal:** Replace a gateway certificate through a verified, recoverable transaction without changing partner approvals.

**Architecture:** Reuse the certificate generation engine with a gateway role. Add a fixed loopback TLS verification listener and a durable pending marker checked by startup and the guard. DNS issuance and gateway recovery are separate following increments in the lifecycle design.

**Tech Stack:** Python, cryptography, fixed Envoy image, systemd, existing scoped nftables policy.

**Spec:** `docs/superpowers/specs/2026-09-25-gateway-lifecycle-design.md` (certificate identity/activation and acceptance items 1–2).

## Global constraints

- Privileged runtime acceptance only on disposable GitHub-hosted Ubuntu 24.04 amd64.
- No changes to signed institution identity, current agreements or recorded revocations.
- Lock order: backup first when present, then gateway operation lock.
- No system CA validation bypass. Every pinned application hostname must validate.
- Interrupted certificate changes keep transport closed; HTTP verification listener has no upstream route.

## Review focus

- Gateway with both Matrix and file domains: require both SANs before changing active material (task 1).
- Reboot between pointer replacement and verification: durable pending marker prevents reopening (task 2).
- Activation and rollback both fail: retain pending marker and closed firewall (tasks 1–2).
- Existing backup/policy work: reject concurrent administration, preserve policy bytes (tasks 1–3).
- An application tries to use the health listener: loopback binding and deny-all HTTP policy (tasks 2–3).

### Task 1: Transaction and certificate identity

Files: create `scripts/gateway_certificates.py`, `tests/test_gateway_certificates.py`; extend `scripts/certificate_lifecycle.py` role map.

Interfaces: `activate_certificate(store, cert, key, *, initial=False, validator=validate_material, runtime=None, gid=0)` uses a caller-held lock. Runtime exposes `close()`, `restart(service)`, `verify(hostname, fingerprint)` and `reopen()`. `replace(certificate, private_key)` performs platform/input checks and ordered locking.

- [x] Write tests staging a certificate, reject a missing second domain, replace it, inject activation failure and double failure, and reject a different pending certificate. Assert original state bytes remain identical and marker persistence matches actual verification.
- [x] Run `.venv/bin/python -m pytest tests/test_gateway_certificates.py -q`; observe failure before implementing.
- [x] Implement all-domain validation and immutable generation staging. For changes, write the bounded material digest marker, close, activate, verify all names, remove/fsync marker, then reopen current policy. On failure retain the marker unless the old certificate was verified and current policy successfully reopened. Never delete policy intent.
- [x] Run focused and full local tests; commit the transaction with evidence.

Core transaction contract:
```python
store.identity()  # pinned service hostname catalogue
store.pending()  # policy intent blocks a separate certificate change
# Certificate intent is separate; startup and guard close for either intent.
# Removal follows actual TLS verification, and fsync precedes reopening.
```

### Task 2: Frozen runtime and installation

Files: `scripts/gateway_rendering.py`, `scripts/gateway_runtime.py`, `scripts/gateway_operations.py`; existing renderer/runtime tests.

- [x] Add tests requiring 127.0.0.1:9443 TLS with the same generation paths and no routes; require startup/guard to remain closed for a certificate intent.
- [x] Run the new tests and observe failure.
- [x] Render the health listener with deny-all RBAC and only direct 403 response. Read certificate paths under `/etc/rdc-gateway/tls/active`. Stage initial TLS in installation, reserve port9443, include the certificate module and engine in the frozen catalogue, and avoid re-reading stale input material on repeat install.
- [x] Extend readiness to verify the fixed listener belongs to the owned proxy. Check certificate pending intent in every reopening path.
- [x] Update disposable raw proxy fixtures to stage generation paths before launching. Run local suite and syntax checks; commit.

### Task 3: CLI and actual acceptance

Files: `scripts/rdc.py`, `scripts/gateway_operations.py`, `scripts/ci_regional_gateway.py`, CLI tests and `docs/regional-gateway.md`.

- [x] Add CLI parsing tests for `gateway certificate replace --certificate PATH --private-key PATH` and `gateway certificate status`.
- [x] Expose bounded replacement/status with actionable expiry, pending and served-fingerprint fields. Do not print key material.
- [x] Extend actual gateway acceptance to issue a second disposable trusted certificate, replace it and compare the real served fingerprint. Inject a failure after switching, verify rollback serves the old fingerprint, and verify policy/state bytes did not change.
- [x] Test LAN and regional attempts to reach port9443 fail, local HTTP returns403, and restarting with an abandoned certificate marker leaves federation closed until the exact change resumes.
- [x] Run hosted acceptance, inspect failures before fixes, update validation evidence and author-review the resulting diff. Continue with the fixed DNS renewal runner; do not claim gateway lifecycle complete from manual replacement alone.

### Task 4: Fixed DNS issuer for the gateway

Files: `scripts/service_issuer_contracts.py`, `scripts/service_issuer.py`, `scripts/service_issuer_setup.py`, `scripts/rdc.py`, `scripts/ci_service_issuer.py`, `scripts/ci_regional_gateway.py`, `tests/test_gateway_issuer.py`.

Interfaces: keep the existing issuer API and fixed local paths on each dedicated node. Add `kind=gateway-certificates`, `gateway_fingerprint`, and exactly the present `matrix_hostname`/`nextcloud_hostname` fields. `matching_application(profile)` returns a verified gateway Store for this kind; `activate_application` calls `activate_certificate` while holding the gateway lock. Initial issuance prepares files and does not start a gateway.

- [x] Add failing tests for one/two-domain contracts, forbidden Element/extra fields, fingerprint mismatch, exact pinned service names, isolated frozen dependency imports and wizard names derived from a signed identity.
- [x] Extend name validation and fixed issuance command, preserving provider/CA/path restrictions. Derive wizard identity fields from the imported signed public identity, display its fingerprint, and retain explicit issuer-terms consent.
- [x] Add issuer lock routing: backup, a fixed issuer setup lock, then the existing gateway lock when the gateway is installed. No gateway directory is created by pre-install issuance. Verify installed gateway ownership before enabling activation; renewal cannot change a signed hostname or identity.
- [x] Include the entire gateway runtime dependency catalogue in the frozen issuer; preserve recognition of prior application-only catalogues without silently upgrading them. Read-only status checks actual served TLS through the gateway verifier.
- [x] Reuse the disposable provider-boundary fixture with gateway ownership. Run the actual installed renewal service to activate a new trusted leaf; inject provider failure and prove it retains the active certificate. Record public DNS/ACME acceptance as not run.
- [x] Run the full suite and native gateway/application jobs, update docs/evidence, and review the final certificate diff before marking this plan complete. Gateway encrypted recovery remains the next separate plan.

Acceptance: local530 tests passed; manual gateway lifecycle run36151947546 and frozen renewal run36152384390 passed. Current-source Matrix36152384367 and Nextcloud36152384301 also passed. Author review only; public DNS/ACME and physical deployment remain external acceptance.

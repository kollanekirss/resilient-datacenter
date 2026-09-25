# Contributing

This is an experimental self-hosted service kit. Contributions should preserve the independent, join and local-node workflows and distinguish local checks from live deployment evidence.

## Work locally

1. Fork and clone the repository, then create a branch for your change.
2. Use Python 3.11+ and create a project-local virtual environment.
3. Install dependencies and run the local checks:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/check_local.py
```

The local checks do not install the network client or connect to public fixture addresses. See docs/local-install-acceptance.md for the separate live acceptance procedure.

4. Add regression coverage for changed deployment behaviour. Preserve strict input validation, ownership checks, TLS verification and explicit enrollment.
5. Open a pull request describing the user-visible change, checks performed and any untested behaviour.

The common `./rdc` interface and private support reports are documented in [operations](docs/operations.md). New commands must preserve typed pending/blocked outcomes and keep raw diagnostics out of saved reports. GitHub Local checks runs the same local suite on Ubuntu without deployment permissions.

## Useful first contributions

- Run the documented acceptance flow on disposable Ubuntu machines and report sanitized results.
- Improve beginner setup instructions based on an actual setup attempt.
- Report reproducible installation problems with the commit, operating system, stage and sanitized error.

Do not put real inventories, private keys, enrollment links, credentials or personal data in commits or public issues. The ignored inventories/lab directory is for private operator configuration.

## Scope

Preserve the networking, application, backup/recovery and regional boundaries described in the product design. Actual server/client/container execution belongs on disposable Ubuntu acceptance machines, not a contributor’s preparation computer. Automatic failover, SSO and new architectures need their own design and acceptance. Networking enrollment alone is not evidence of application resilience.

Report suspected vulnerabilities through [private reporting](SECURITY.md), not public issues.

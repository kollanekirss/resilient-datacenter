#!/usr/bin/env python3
"""Read-only preflight. Real KVM scenarios and physical qualification are NOT RUN.

See appliance.lab for the explicit owned-workspace profile. A future runner
must boot pinned media, enforce isolated switches and bounded scenario timeouts,
capture serial/network evidence, and compare disk hashes for refusal cases.
This command deliberately cannot create images, launch QEMU or modify networks.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appliance.lab import SUITES, collect_platform, inspect_lab


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, default="all")
    parser.add_argument("--lab-config", type=Path)
    args = parser.parse_args(argv)
    config = {}
    reasons = []
    config_digest = None
    try:
        if args.lab_config is None or args.lab_config.is_symlink() or not args.lab_config.is_file():
            raise ValueError("config missing or not regular")
        with args.lab_config.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("config too large")
        config = json.loads(raw)
        if not isinstance(config, dict):
            raise ValueError("config must be an object")
        config_digest = hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, UnicodeError):
        config = {}
        reasons.append("lab-config-unreadable")
    observed = collect_platform()
    reasons.extend(inspect_lab(config, observed))
    reasons.append("scenario-runner-not-implemented")
    print(json.dumps({"schema": 1, "status": "NOT RUN", "qualification": "NOT RUN",
                      "scope": "read-only-preflight", "suite": args.suite,
                      "checked_at": datetime.now(timezone.utc).isoformat(),
                      "build_id": config.get("build_id"), "spec_id": config.get("spec_id"),
                      "lab_config_sha256": config_digest, "platform": observed,
                      "reasons": list(dict.fromkeys(reasons)),
                      "cases": [{"case_id": case, "state": "unknown", "status": "NOT RUN"}
                                for case in SUITES[args.suite]],
                      "next_action": "Provide an owned x86-64 Linux/KVM lab and implement real bounded scenarios; do not infer boot qualification from preflight."}, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

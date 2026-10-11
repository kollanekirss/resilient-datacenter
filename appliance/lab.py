"""Read-only lab preflight and evidence-integrity checks, not a boot runner.

A lab config has schema=1, workspace, owner_id, build_id, spec_id (SHA256),
and images mapping installer/target/canary/uefi_code/uefi_vars to absolute
path + sha256 records. The pre-existing dedicated workspace must contain
.rdc-appliance-lab.json with schema=1 and the same owner_id. Nothing here
creates that marker, changes a file, launches a VM, or authorizes erasure.

Real qualification still requires the bounded KVM scenarios and physical
operator exercises in the V1 specification. A supplied result's file hashes
can establish record integrity, not whether its claimed assertions occurred.
"""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat


IMAGE_ROLES = ("installer", "target", "canary", "uefi_code", "uefi_vars")
SUITES = {
    "media-gate": ("offline-install", "erase-refusals", "wan-exposure"),
    "host-network": ("port-mapping", "wan-exposure", "router-down-management"),
    "offline-install": ("offline-install", "no-wan-boot"),
    "router-policy": ("routed-policy", "wan-exposure"),
    "base-operations": ("router-down-management", "no-wan-boot", "wan-return", "interrupted-resume"),
    "repair": ("export-repair",),
}
SUITES["all"] = tuple(dict.fromkeys(case for cases in SUITES.values() for case in cases)) + ("physical-operator",)


def _sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is not None


def _file_problem(path):
    """Inspect before opening, including ancestors and non-regular devices."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return "path-invalid"
    item = Path(path)
    if not item.is_absolute() or ".." in item.parts:
        return "path-invalid"
    try:
        if any(parent.is_symlink() for parent in (item, *item.parents)):
            return "symlink"
        info = item.stat()
        if not stat.S_ISREG(info.st_mode):
            return "not-regular"
        if info.st_nlink != 1:
            return "hardlink"
        if info.st_uid != os.getuid():
            return "not-owned"
    except (OSError, ValueError):
        return "missing"
    return None


def file_sha256(path):
    """Hash an existing regular owned file without following a final symlink."""
    problem = _file_problem(str(path))
    if problem:
        raise ValueError(problem)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid():
            raise ValueError("not-owned-regular-file")
        result = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
        after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError("file-changed")
        return result.hexdigest()


def collect_platform():
    """Observe platform prerequisites; do not invoke QEMU or open KVM."""
    try:
        kvm = stat.S_ISCHR(os.stat("/dev/kvm").st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK)
    except OSError:
        kvm = False
    return {"system": platform.system(), "machine": platform.machine(),
            "kvm_available": kvm, "qemu_path": shutil.which("qemu-system-x86_64")}


def inspect_lab(config: dict, platform_record: dict) -> list[str]:
    """Return every observed blocking prerequisite; an empty list is not PASS."""
    reasons = []
    observed = platform_record if isinstance(platform_record, dict) else {}
    if observed.get("system") != "Linux":
        reasons.append("linux-required")
    if observed.get("machine") != "x86_64":
        reasons.append("x86-64-required")
    if observed.get("kvm_available") is not True:
        reasons.append("kvm-unavailable")
    qemu = observed.get("qemu_path")
    if not isinstance(qemu, str) or not os.path.isabs(qemu) or not os.path.isfile(qemu) or not os.access(qemu, os.X_OK):
        reasons.append("qemu-unavailable")
    if not isinstance(config, dict):
        return reasons + ["lab-config-invalid"]
    if type(config.get("schema")) is not int or config["schema"] != 1:
        reasons.append("lab-schema-invalid")
    for key in ("owner_id", "build_id"):
        if not _identifier(config.get(key)):
            reasons.append(key.replace("_", "-") + "-invalid")
    if not _sha256(config.get("spec_id")):
        reasons.append("spec-identity-invalid")
    value = config.get("workspace")
    work = Path(value) if isinstance(value, str) and value and "\x00" not in value else None
    usable = False
    if work is None or not work.is_absolute() or ".." in work.parts or work == Path("/"):
        reasons.append("workspace-invalid")
    else:
        try:
            if any(p.is_symlink() for p in (work, *work.parents)):
                reasons.append("workspace-symlink")
            elif not work.is_dir():
                reasons.append("workspace-missing")
            elif work.stat().st_uid != os.getuid():
                reasons.append("workspace-not-owned")
            else:
                usable = True
                marker = work / ".rdc-appliance-lab.json"
                problem = _file_problem(str(marker))
                if problem:
                    reasons.append("workspace-marker-" + problem)
                elif marker.stat().st_size > 4096:
                    reasons.append("workspace-marker-invalid")
                else:
                    data = json.loads(marker.read_text(encoding="utf-8"))
                    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("owner_id") != config.get("owner_id"):
                        reasons.append("workspace-owner-mismatch")
        except (OSError, ValueError, UnicodeError):
            reasons.append("workspace-marker-invalid")
    images = config.get("images")
    images = images if isinstance(images, dict) else {}
    seen = set()
    for name in IMAGE_ROLES:
        image = images.get(name)
        if not isinstance(image, dict):
            reasons.append("image-config-missing:" + name)
            continue
        path = image.get("path")
        problem = _file_problem(path)
        if problem:
            reasons.append("image-" + problem + ":" + name)
            continue
        item = Path(path)
        if item in seen:
            reasons.append("image-path-reused:" + name)
        seen.add(item)
        if not usable or not item.is_relative_to(work):
            reasons.append("image-outside-workspace:" + name)
            continue
        if not _sha256(image.get("sha256")):
            reasons.append("image-sha256-invalid:" + name)
            continue
        try:
            if file_sha256(path) != image["sha256"]:
                reasons.append("image-sha256-mismatch:" + name)
        except (OSError, ValueError):
            reasons.append("image-unreadable-or-changed:" + name)
    return list(dict.fromkeys(reasons))


def evaluate_results(expected_cases: list[str], results: list[dict], build_id: str) -> dict:
    """Validate supplied records and actual file digests, never certify a boot.

    Caller must independently establish the trusted runner, approved spec,
    required subordinate assertions and current plan/configuration identity.
    No authenticity is inferred from a self-reported 'real-execution' label.
    """
    reasons = []
    if not isinstance(expected_cases, list) or not expected_cases or not all(_identifier(case) for case in expected_cases):
        expected_cases = []
        reasons.append("expected-cases-invalid")
    if len(set(expected_cases)) != len(expected_cases):
        reasons.append("expected-cases-duplicate")
    if not _identifier(build_id):
        reasons.append("build-identity-invalid")
    if not isinstance(results, list):
        results = []
        reasons.append("results-invalid")
    by_case = {}
    specs = set()
    for record in results:
        if not isinstance(record, dict) or not _identifier(record.get("case_id")):
            reasons.append("result-invalid")
            continue
        case = record["case_id"]
        if case in by_case:
            reasons.append("duplicate-case:" + case)
        by_case[case] = record
        if case not in expected_cases:
            reasons.append("unexpected-case:" + case)
        if record.get("build_id") != build_id:
            reasons.append("build-mismatch:" + case)
        if not _sha256(record.get("spec_id")):
            reasons.append("spec-identity-invalid:" + case)
        else:
            specs.add(record["spec_id"])
        if record.get("state") != "verified":
            reasons.append("case-not-verified:" + case)
        if record.get("method") != "real-execution" or record.get("environment") not in ("nested-kvm", "physical") or any(record.get(key) for key in ("fixture", "mock", "simulated", "test_only")):
            reasons.append("synthetic-result:" + case)
        if case == "physical-operator" and record.get("environment") != "physical":
            reasons.append("physical-evidence-required:" + case)
        try:
            when = datetime.fromisoformat(record.get("checked_at", ""))
            if when.tzinfo is None:
                raise ValueError("timezone missing")
        except (TypeError, ValueError):
            reasons.append("timestamp-invalid:" + case)
        assertions = record.get("assertions")
        if not isinstance(assertions, list) or not assertions or any(not isinstance(item, dict) or not _identifier(item.get("name")) or item.get("passed") is not True for item in assertions):
            reasons.append("assertion-failed:" + case)
        evidence = record.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            reasons.append("evidence-missing:" + case)
            continue
        for item in evidence:
            if not isinstance(item, dict) or not _sha256(item.get("sha256")):
                reasons.append("evidence-invalid:" + case)
                continue
            problem = _file_problem(item.get("path"))
            if problem:
                reasons.append("evidence-" + problem + ":" + case)
                continue
            try:
                if file_sha256(item["path"]) != item["sha256"]:
                    reasons.append("evidence-sha256-mismatch:" + case)
            except (OSError, ValueError):
                reasons.append("evidence-unreadable-or-changed:" + case)
    if len(specs) > 1:
        reasons.append("spec-identity-mismatch")
    for case in expected_cases:
        if case not in by_case:
            reasons.append("missing-case:" + case)
    return {"state": "blocked" if reasons else "verified", "scope": "evidence-integrity-only",
            "qualification": "NOT RUN", "reasons": list(dict.fromkeys(reasons)),
            "expected_cases": expected_cases, "observed_cases": sorted(by_case)}

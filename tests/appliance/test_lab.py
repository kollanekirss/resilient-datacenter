"""Safety checks use real temporary files; no VM execution is simulated as proof."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def api():
    return importlib.import_module("appliance.lab")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def lab(tmp_path):
    work = tmp_path / "owned-lab"
    work.mkdir()
    (work / ".rdc-appliance-lab.json").write_text(json.dumps({"schema": 1, "owner_id": "lab-unit"}))
    images = {}
    for name in ("installer", "target", "canary", "uefi_code", "uefi_vars"):
        path = work / (name + ".img")
        path.write_bytes(("unit input: " + name).encode())
        images[name] = {"path": str(path), "sha256": digest(path)}
    qemu = tmp_path / "qemu-test-file"
    qemu.write_text("not executed by this gate\n")
    qemu.chmod(0o700)
    return ({"schema": 1, "workspace": str(work), "owner_id": "lab-unit",
             "build_id": "unit-build", "spec_id": "a" * 64, "images": images},
            {"system": "Linux", "machine": "x86_64", "kvm_available": True,
             "qemu_path": str(qemu)})


def test_preflight_checks_files_without_modifying_them(lab):
    config, platform = lab
    before = {p: digest(Path(p)) for p in (r["path"] for r in config["images"].values())}
    assert api().inspect_lab(config, platform) == []
    assert before == {p: digest(Path(p)) for p in before}


@pytest.mark.parametrize("field,value,reason", [
    ("system", "Darwin", "linux-required"),
    ("machine", "arm64", "x86-64-required"),
    ("kvm_available", False, "kvm-unavailable"),
    ("qemu_path", None, "qemu-unavailable"),
])
def test_unsupported_platform_blocks_lab(lab, field, value, reason):
    config, platform = lab
    platform[field] = value
    assert reason in api().inspect_lab(config, platform)


@pytest.mark.parametrize("mode,reason", [
    ("outside", "image-outside-workspace:target"),
    ("symlink", "image-symlink:target"),
    ("parent-symlink", "image-symlink:target"),
    ("device", "image-not-regular:target"),
    ("hardlink", "image-hardlink:target"),
    ("missing", "image-missing:target"),
    ("bad-hash", "image-sha256-mismatch:target"),
    ("duplicate", "image-path-reused:target"),
])
def test_unsafe_image_paths_never_pass(lab, tmp_path, mode, reason):
    config, platform = lab
    target = Path(config["images"]["target"]["path"])
    if mode == "outside":
        target = tmp_path / "outside.img"
        target.write_bytes(b"outside")
    elif mode == "symlink":
        target.unlink()
        target.symlink_to(config["images"]["canary"]["path"])
    elif mode == "parent-symlink":
        link = tmp_path / "linked-workspace"
        link.symlink_to(config["workspace"], target_is_directory=True)
        target = link / target.name
    elif mode == "device":
        target = Path("/dev/null")
    elif mode == "hardlink":
        os.link(target, tmp_path / "second-name")
    elif mode == "missing":
        target.unlink()
    elif mode == "duplicate":
        target = Path(config["images"]["installer"]["path"])
    else:
        target.write_bytes(b"changed after approval")
    config["images"]["target"]["path"] = str(target)
    assert reason in api().inspect_lab(config, platform)


def test_missing_or_mismatched_ownership_marker_blocks(lab):
    config, platform = lab
    marker = Path(config["workspace"]) / ".rdc-appliance-lab.json"
    marker.write_text('{"schema":1,"owner_id":"another-job"}')
    assert "workspace-owner-mismatch" in api().inspect_lab(config, platform)
    marker.unlink()
    assert "workspace-marker-missing" in api().inspect_lab(config, platform)


def test_missing_firmware_and_invalid_config_fail_closed(lab):
    config, platform = lab
    del config["images"]["uefi_code"]
    assert "image-config-missing:uefi_code" in api().inspect_lab(config, platform)
    assert api().inspect_lab({}, {})
    assert api().inspect_lab(None, {})


def result_file(tmp_path):
    path = tmp_path / "serial.log"
    path.write_bytes(b"captured bytes for evidence-integrity unit test\n")
    return {"case_id": "offline-install", "build_id": "build-1", "spec_id": "a" * 64,
            "state": "verified", "environment": "nested-kvm", "method": "real-execution",
            "checked_at": "2026-10-11T15:00:00+00:00",
            "assertions": [{"name": "disk-only-boot", "passed": True}],
            "evidence": [{"path": str(path), "sha256": digest(path)}]}


def test_complete_evidence_only_claims_record_integrity(tmp_path):
    record = result_file(tmp_path)
    result = api().evaluate_results(["offline-install"], [record], "build-1")
    assert result["state"] == "verified"
    assert result["scope"] == "evidence-integrity-only"
    assert result["qualification"] == "NOT RUN"


@pytest.mark.parametrize("mutation,reason", [
    ("missing", "missing-case:offline-install"),
    ("duplicate", "duplicate-case:offline-install"),
    ("build", "build-mismatch:offline-install"),
    ("fixture", "synthetic-result:offline-install"),
    ("mock", "synthetic-result:offline-install"),
    ("state", "case-not-verified:offline-install"),
    ("assertion", "assertion-failed:offline-install"),
    ("empty-evidence", "evidence-missing:offline-install"),
    ("tamper", "evidence-sha256-mismatch:offline-install"),
    ("spec", "spec-identity-invalid:offline-install"),
])
def test_untrustworthy_evidence_is_not_verified(tmp_path, mutation, reason):
    record = result_file(tmp_path)
    records = [record]
    if mutation == "missing":
        records = []
    elif mutation == "duplicate":
        records.append(record.copy())
    elif mutation == "build":
        record["build_id"] = "old-build"
    elif mutation in ("fixture", "mock"):
        record[mutation] = True
    elif mutation == "state":
        record["state"] = "unknown"
    elif mutation == "assertion":
        record["assertions"][0]["passed"] = False
    elif mutation == "empty-evidence":
        record["evidence"] = []
    elif mutation == "tamper":
        Path(record["evidence"][0]["path"]).write_bytes(b"tampered")
    else:
        record["spec_id"] = ""
    result = api().evaluate_results(["offline-install"], records, "build-1")
    assert result["state"] != "verified"
    assert reason in result["reasons"]


def test_empty_expected_cases_do_not_vacuously_pass():
    assert api().evaluate_results([], [], "build-1")["state"] != "verified"


def test_cli_missing_configuration_is_structured_not_run(tmp_path):
    command = [sys.executable, str(ROOT / "scripts" / "ci_appliance_base.py"),
               "--suite", "all", "--lab-config", str(tmp_path / "missing.json")]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    output = json.loads(result.stdout)
    assert output["status"] == "NOT RUN"
    assert "lab-config-unreadable" in output["reasons"]
    assert output["qualification"] == "NOT RUN"


def test_cli_never_turns_preflight_into_boot_qualification(lab, tmp_path):
    config, _ = lab
    path = tmp_path / "lab.json"
    path.write_text(json.dumps(config))
    before = {p.name: digest(p) for p in Path(config["workspace"]).iterdir()}
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "ci_appliance_base.py"),
                             "--suite", "media-gate", "--lab-config", str(path)],
                            capture_output=True, text=True, check=False)
    output = json.loads(result.stdout)
    assert result.returncode != 0
    assert output["status"] == "NOT RUN"
    assert "execution-not-requested" in output["reasons"]
    assert all(case["state"] == "unknown" for case in output["cases"])
    assert before == {p.name: digest(p) for p in Path(config["workspace"]).iterdir()}


def test_cli_text_report_is_allowlisted_and_keeps_unrun_cases(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/ci_appliance_base.py'),
                             '--suite', 'all', '--format', 'text'], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'Appliance acceptance: NOT RUN' in result.stdout
    assert 'physical-operator: NOT RUN' in result.stdout


def test_duplicate_configuration_fields_are_rejected(tmp_path):
    path = tmp_path / 'duplicate.json'
    path.write_text('{"schema":1,"schema":2}')
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/ci_appliance_base.py'),
                             '--lab-config', str(path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'lab-config-unreadable' in json.loads(result.stdout)['reasons']

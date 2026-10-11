"""Exercise the preparation command at its actual process boundary."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.run([sys.executable, "-m", "appliance", "--json", *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=10)


@pytest.fixture
def inputs(tmp_path, site, release):
    site_file, release_file = tmp_path / "site.json", tmp_path / "release.json"
    site_file.write_text(json.dumps(site))
    release_file.write_text(json.dumps(release))
    return site_file, release_file


def test_preview_reports_layout_without_authorizing_install(inputs):
    site, release = inputs
    result = run("preview", str(site), "--release", str(release))
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["destructive_actions_enabled"] is False
    assert data["networks"]["management"]["host_ip"] == "10.77.0.2"


def test_install_is_explicitly_disabled_even_with_force():
    result = run("install")
    assert result.returncode == 2
    assert json.loads(result.stdout)["code"] == "installer-adapter-unqualified"
    assert run("install", "--force").returncode != 0


def test_malformed_plan_reports_redacted_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("TOP-SECRET-BROKEN-JSON")
    result = run("preview", str(path))
    assert result.returncode == 2
    assert "TOP-SECRET" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_status_reports_incomplete_delivery():
    result = run("status")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["installer"] == "not-implemented"
    assert data["boot_qualification"] == "not-run"
    assert data["destructive_actions_enabled"] is False


def test_release_check_accepts_real_pins_without_claiming_qualification():
    result = run("release-check")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data["state"] == "inputs-validated"
    assert data["installable"] is False
    assert {"proxmox-iso", "opnsense-dvd", "probe-image", "restic"} <= set(data["components"])


def test_preflight_does_not_treat_input_inventory_as_boot_proof(inputs, inventory, tmp_path):
    site, release = inputs
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory))
    result = run("preflight", str(site), "--release", str(release), "--inventory", str(path))
    assert result.returncode == 2
    assert "installer-adapter-unqualified" in json.loads(result.stdout)["blockers"]


def test_verify_tampered_artifact_fails_without_printing_contents(tmp_path):
    path = tmp_path / "image"
    path.write_text("SECRET-ARTIFACT")
    result = run("media", "verify", "opnsense-dvd", "--file", str(path))
    assert result.returncode == 2
    assert "SECRET-ARTIFACT" not in result.stdout + result.stderr


def test_readiness_does_not_call_itself_hardware_inventory():
    result = run("inspect")
    assert result.returncode == 0
    assert json.loads(result.stdout)["scope"] == "build-platform-only"

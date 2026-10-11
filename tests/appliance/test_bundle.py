"""Prepared media is immutable and cannot masquerade as a bootable image."""
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from appliance.contracts import ApplianceError


def _bundle_module():
    return importlib.import_module("appliance.installer.media")


@pytest.fixture
def bundle_inputs(tmp_path, release, monkeypatch):
    release.pop("test_only")
    files = {}
    for component_id in ("proxmox-iso", "opnsense-dvd", "probe-image", "restic"):
        raw = ("artifact-" + component_id).encode()
        path = tmp_path / component_id
        path.write_bytes(raw)
        files[component_id] = path
        release["components"].append({"id": component_id, "version": "1.0",
            "url": f"https://downloads.example.org/{component_id}",
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw), "max_bytes": len(raw),
            "provenance": {"kind": "official-checksum", "url": "https://downloads.example.org/SHA256SUMS"},
            "required_for": ["base"]})
    module = _bundle_module()
    monkeypatch.setattr(module, "prepare_component", lambda item, cache: files[item["id"]])
    return module, release, files


def test_bundle_copies_verified_media_and_never_claims_bootable(bundle_inputs, tmp_path):
    module, release, files = bundle_inputs
    destination = tmp_path / "bundle"
    result = module.prepare_bundle(release, tmp_path / "cache", destination)
    assert result["bootable"] is False and result["state"] == "prepared"
    manifest = json.loads((destination / "bundle.json").read_text())
    assert manifest["release_id"] == "test-release"
    assert len(manifest["files"]) == 4
    for item in manifest["files"]:
        assert (destination / item["path"]).read_bytes() == files[item["id"]].read_bytes()
        assert (destination / item["path"]).stat().st_ino != files[item["id"]].stat().st_ino


def test_bundle_rechecks_inputs_and_does_not_publish_corruption(bundle_inputs, tmp_path):
    module, release, files = bundle_inputs
    files["opnsense-dvd"].write_bytes(b"corrupt")
    destination = tmp_path / "bundle"
    with pytest.raises(ApplianceError):
        module.prepare_bundle(release, tmp_path / "cache", destination)
    assert not (destination / "bundle.json").exists()


def test_existing_unrelated_directory_is_never_overwritten(bundle_inputs, tmp_path):
    module, release, _ = bundle_inputs
    destination = tmp_path / "bundle"
    destination.mkdir()
    (destination / "valuable").write_bytes(b"keep")
    with pytest.raises(ApplianceError, match="bundle-destination-exists"):
        module.prepare_bundle(release, tmp_path / "cache", destination)
    assert (destination / "valuable").read_bytes() == b"keep"


def test_bundle_reverification_detects_changed_media(bundle_inputs, tmp_path):
    module, release, _ = bundle_inputs
    destination = tmp_path / "bundle"
    module.prepare_bundle(release, tmp_path / "cache", destination)
    (destination / "media" / "probe-image").write_bytes(b"tampered")
    with pytest.raises(ApplianceError):
        module.verify_bundle(destination, release)


def test_editing_bundle_marker_cannot_enable_boot_claim(bundle_inputs, tmp_path):
    module, release, _ = bundle_inputs
    destination = tmp_path / "bundle"
    module.prepare_bundle(release, tmp_path / "cache", destination)
    marker = destination / "bundle.json"
    manifest = json.loads(marker.read_text())
    manifest["bootable"] = True
    marker.write_text(json.dumps(manifest))
    with pytest.raises(ApplianceError, match="bundle-contract"):
        module.verify_bundle(destination, release)

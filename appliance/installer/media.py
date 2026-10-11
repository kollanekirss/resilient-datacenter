"""Assemble and recheck an offline input bundle, never a bootable ISO."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from appliance.contracts import ApplianceError, canonical, identity, load_json, require
from appliance.media import prepare_component, verify_file
from appliance.plan import validate_release

BASE_COMPONENTS = ("proxmox-iso", "opnsense-dvd", "probe-image", "restic")


def _safe_parents(path):
    path = Path(path).absolute()
    require(".." not in path.parts, "bundle-path")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "bundle-path")
    return path


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def _copy_verified(source, destination, expected):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source_file:
        require(stat.S_ISREG(os.fstat(source_file.fileno()).st_mode), "media-file")
        out_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out_fd, "wb") as output:
            count, digest = 0, hashlib.sha256()
            while True:
                chunk = source_file.read(min(1024 * 1024, expected["size_bytes"] - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= expected["size_bytes"], "media-size")
                digest.update(chunk)
                output.write(chunk)
            require(count == expected["size_bytes"], "media-size")
            require(digest.hexdigest() == expected["sha256"], "media-digest")
            output.flush()
            os.fsync(output.fileno())


def _file_records(release):
    by_id = {item["id"]: item for item in release["components"]}
    result = []
    for component_id in BASE_COMPONENTS:
        item = by_id[component_id]
        content = item.get("expanded", item)
        result.append({"id": component_id, "path": "media/" + component_id,
                       **{k: content[k] for k in ("sha256", "size_bytes", "max_bytes")}})
    return result


def _manifest(release):
    return {"schema": 1, "state": "prepared", "bootable": False,
            "release_id": release["release_id"], "release_identity": identity(release),
            "qualification": "not-run", "files": _file_records(release)}


def verify_bundle(destination: Path, release: dict) -> dict:
    release = validate_release(release, production=True)
    destination = _safe_parents(destination)
    require(destination.is_dir(), "bundle-missing")
    recorded = load_json(destination / "bundle.json")
    require(recorded == _manifest(release), "bundle-contract")
    require(load_json(destination / "release.lock.json") == release, "bundle-release-mismatch")
    require(not (destination / "incomplete.json").exists(), "bundle-incomplete")
    require({p.name for p in destination.iterdir()} == {"media", "bundle.json", "release.lock.json"}, "bundle-extra-files")
    media = _safe_parents(destination / "media")
    require(media.is_dir() and {p.name for p in media.iterdir()} == set(BASE_COMPONENTS), "bundle-extra-files")
    for item in recorded["files"]:
        verify_file(destination / item["path"], item)
    return recorded


def prepare_bundle(release: dict, cache: Path, destination: Path) -> dict:
    release = validate_release(release, production=True)
    destination = _safe_parents(destination)
    require(destination.parent.is_dir(), "bundle-parent-missing")
    if destination.exists():
        require((destination / "bundle.json").is_file(), "bundle-destination-exists")
        return verify_bundle(destination, release)
    try:
        destination.mkdir(mode=0o700)
        _write_new(destination / "incomplete.json", canonical({"state": "incomplete", "release_identity": identity(release)}))
        media = destination / "media"
        media.mkdir(mode=0o700)
        by_id = {item["id"]: item for item in release["components"]}
        manifest = _manifest(release)
        for expected in manifest["files"]:
            source = prepare_component(by_id[expected["id"]], cache)
            _copy_verified(source, destination / expected["path"], expected)
        _write_new(destination / "release.lock.json", canonical(release))
        # Publish the completion record last; every failure remains incomplete.
        (destination / "incomplete.json").unlink()
        _write_new(destination / "bundle.json", canonical(manifest))
        for directory in (media, destination, destination.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return manifest
    except ApplianceError:
        raise
    except OSError:
        raise ApplianceError("bundle-io") from None

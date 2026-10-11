"""Preparation and local appliance commands; hardware qualification is separate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from appliance import __version__
from appliance.contracts import ApplianceError, identity, load_json, require
from appliance.installer.live import preflight, preview
from appliance.installer.media import prepare_bundle, verify_bundle
from appliance.lab import collect_platform
from appliance.media import prepare_component, verify_file
from appliance.plan import validate_release

DEFAULT_RELEASE = Path(__file__).resolve().parent / "releases" / "v1.lock.json"


def parser():
    result = argparse.ArgumentParser(description="Build and operate the two-port appliance development candidate.")
    result.add_argument("--json", action="store_true", help="Emit structured results")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show implemented and unqualified capabilities")
    commands.add_parser("inspect", help="Read build-platform prerequisites only")
    check = commands.add_parser("release-check", help="Validate reviewed artifact pins")
    check.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    for name in ("preview", "preflight"):
        cmd = commands.add_parser(name, help="Check a site plan without changing the machine")
        cmd.add_argument("plan", type=Path)
        cmd.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
        if name == "preflight":
            cmd.add_argument("--inventory", type=Path, required=True,
                             help="Previously captured inventory for consistency checking only")
    media = commands.add_parser("media", help="Prepare or check an individual pinned artifact")
    operations = media.add_subparsers(dest="action", required=True)
    for name in ("prepare", "verify"):
        cmd = operations.add_parser(name)
        cmd.add_argument("component")
        cmd.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
        if name == "prepare":
            cmd.add_argument("--cache", type=Path, required=True)
        else:
            cmd.add_argument("--file", type=Path, required=True)
            cmd.add_argument("--expanded", action="store_true")
    bundle = commands.add_parser("bundle", help="Prepare offline inputs; output is not a bootable image")
    operations = bundle.add_subparsers(dest="action", required=True)
    for name in ("prepare", "verify"):
        cmd = operations.add_parser(name)
        cmd.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
        cmd.add_argument("--output", type=Path, required=True)
        if name == "prepare":
            cmd.add_argument("--cache", type=Path, required=True)
    install = commands.add_parser("install", help="Install only inside the guarded live USB session")
    install.add_argument("--plan", type=Path)
    install.add_argument("--bundle", type=Path)
    install.add_argument("--confirmation")
    install.add_argument("--boot-id")
    from .operations import add_commands
    add_commands(commands, DEFAULT_RELEASE)
    return result


def execute(args):
    if args.command == "status":
        from .operations import status_if_installed
        installed = status_if_installed()
        if installed is not None: return installed, 0
        return {"schema": 1, "version": __version__, "state": "development-candidate",
                "installer": "implemented-unqualified", "boot_qualification": "not-run",
                "destructive_actions_enabled": False,
                "available": ["release-check", "preview", "preflight", "media", "bundle", "iso", "network", "router", "probe", "menu", "export", "repair"],
                "next_action": "Assemble and qualify a development image on disposable x86-64 Linux; hardware acceptance is pending."}, 0
    if args.command == "inspect":
        return {"schema": 1, "scope": "build-platform-only", "platform": collect_platform(),
                "disk_inspection": "not-performed", "destructive_actions_enabled": False}, 0
    if args.command == "install":
        if not all((args.plan, args.bundle, args.confirmation, args.boot_id)):
            raise ApplianceError("installer-adapter-unqualified", "Use the guarded live USB menu; no workstation installation is allowed.")
        from .operations import install_live
        return install_live(args), 0
    if args.command not in {"release-check", "preview", "preflight", "media", "bundle"}:
        from .operations import execute_operation
        return execute_operation(args)
    release = load_json(args.release)
    if args.command in ("preview", "preflight"):
        site = load_json(args.plan)
        result = preview(site, release)
        if args.command == "preflight":
            result["blockers"] = preflight(site, release, load_json(args.inventory))
            result["state"] = "blocked"
            result["inventory_assurance"] = "input-consistency-only"
            return result, 2
        return result, 0
    release = validate_release(release, production=True)
    if args.command == "release-check":
        return {"schema": 1, "state": "inputs-validated", "release_id": release["release_id"],
                "release_identity": identity(release), "components": [i["id"] for i in release["components"]],
                "missing_components": release.get("missing_components", []),
                "profile_qualification": release["profile"]["qualification"],
                "installable": False}, 0
    if args.command == "media":
        components = [i for i in release["components"] if i["id"] == args.component]
        require(len(components) == 1, "unknown-component")
        item = components[0]
        if args.action == "prepare":
            path = prepare_component(item, args.cache)
            receipt = verify_file(path, item.get("expanded", item))
            return {"schema": 1, "state": "prepared", "component": item["id"],
                    "path": str(path), "integrity": receipt, "bootable": False}, 0
        expected = item
        if args.expanded:
            require("expanded" in item, "component-not-compressed")
            expected = item["expanded"]
        return {"schema": 1, "state": "verified", "assurance": "pinned-content-integrity",
                "component": item["id"], "integrity": verify_file(args.file, expected)}, 0
    if args.command == "bundle":
        if args.action == "prepare":
            return prepare_bundle(release, args.cache, args.output), 0
        return verify_bundle(args.output, release), 0
    raise ApplianceError("unsupported-command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        data, status = execute(args)
    except ApplianceError as error:
        data, status = {"schema": 1, "state": "blocked", "code": error.code,
                        "message": str(error)}, 2
    except OSError:
        data, status = {"schema": 1, "state": "blocked", "code": "local-io-error",
                        "message": "A required local file could not be accessed."}, 2
    if args.json:
        print(json.dumps(data, sort_keys=True, indent=2))
    else:
        print("Two-port appliance — " + data.get("state", data.get("scope", "result")))
        for key, value in data.items():
            if key in ("schema", "state"):
                continue
            rendered = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list, bool)) else str(value)
            print(f"{key.replace('_', ' ')}: {rendered}")
    return status

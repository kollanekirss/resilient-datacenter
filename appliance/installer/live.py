"""Non-destructive preflight for the earliest future live-media entry.

Passing a pure gate is not an authorization to run an installer. A live
adapter must collect fresh trustworthy inventory itself, suppress initial
networking and pass the real boot qualification before it can be shipped.
"""
from __future__ import annotations

import copy

from appliance.contracts import ApplianceError, identity, require
from appliance.plan import resource_requirements, validate_site


def live_gate(plan, current, confirmed_identity):
    require(confirmed_identity == identity(plan), "erase-not-confirmed")
    require(type(current) is dict, "inventory-incomplete")
    required = {"boot_id", "supported", "boot_media_ids", "disks", "ports", "addresses",
                "storage_conflicts", "link_checks"}
    require(required <= current.keys(), "inventory-incomplete")
    require(type(current["boot_id"]) is str and bool(current["boot_id"]), "inventory-incomplete")
    media = current["boot_media_ids"]
    require(type(media) is list and bool(media) and all(type(i) is str for i in media), "inventory-incomplete")
    require(plan["target"]["by_id"] not in media, "target-is-boot-media")
    disks = current["disks"]
    require(type(disks) is list and all(type(d) is dict and type(d.get("identity")) is dict for d in disks),
            "inventory-incomplete")
    matching = [d for d in disks if d["identity"] == plan["target"]]
    same_path = [d for d in disks if d["identity"].get("by_id") == plan["target"]["by_id"]]
    same_serial = [d for d in disks if plan["target"]["serial"]
                   and d["identity"].get("serial") == plan["target"]["serial"]]
    same_wwn = [d for d in disks if plan["target"]["wwn"]
                and d["identity"].get("wwn") == plan["target"]["wwn"]]
    require(len(matching) == len(same_path) == 1 and len(same_serial) <= 1 and len(same_wwn) <= 1,
            "target-identity-changed-or-ambiguous")
    require(current["ports"] == plan["ports"], "port-identity-changed")
    require(type(current["addresses"]) is dict and "wan" in current["addresses"]
            and type(current["addresses"]["wan"]) is list, "inventory-incomplete")
    require(not current["addresses"]["wan"], "wan-host-address")
    require(type(current["storage_conflicts"]) is list, "inventory-incomplete")
    require(not current["storage_conflicts"], "non-target-storage-conflict")
    require(current["supported"] is True, "unsupported-hardware")
    require(type(current["link_checks"]) is dict
            and all(current["link_checks"].get(role) is True for role in ("management", "wan")),
            "port-identification-incomplete")


def preflight(plan, release, observed):
    """Return blockers. Operator-supplied inventory is preview evidence only."""
    validate_site(plan, release)
    require(type(observed) is dict, "inventory-incomplete")
    problems = []
    try:
        # This checks consistency without generating an actual erase consent.
        live_gate(plan, observed, identity(plan))
    except ApplianceError as error:
        problems.append(error.code)
    for key, wanted in (("arch", "x86_64"), ("virtualization", True),
                        ("firmware", "uefi"), ("secure_boot", False)):
        if type(observed.get(key)) is not type(wanted) or observed.get(key) != wanted:
            problems.append("unsupported-" + key.replace("_", "-"))
    resources = resource_requirements(plan, release)
    for key, reason in (("memory_mib", "insufficient-memory"), ("vcpus", "insufficient-cpu")):
        if type(observed.get(key)) is not int or observed[key] < resources[key]:
            problems.append(reason)
    if release["budgets"]["qualification"] != "qualified":
        problems.append("resource-budgets-unqualified")
    # A mutable input field cannot qualify an adapter that does not exist.
    problems.append("installer-adapter-unqualified")
    return problems


def preview(plan, release):
    plan = validate_site(plan, release)
    return {"schema": 1, "state": "preview", "plan_id": identity(plan),
            "site_id": plan["site_id"], "release_id": plan["release_id"],
            "target": copy.deepcopy(plan["target"]), "ports": copy.deepcopy(plan["ports"]),
            "networks": copy.deepcopy(plan["networks"]), "resources": resource_requirements(plan, release),
            "destructive_actions_enabled": False,
            "blockers": ["installer-adapter-unqualified"],
            "next_action": "Qualify the live boot adapter on a disposable x86-64 Linux/KVM machine."}

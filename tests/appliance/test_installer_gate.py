"""A confirmation or old inventory cannot authorize a changed machine."""
import copy
import importlib

import pytest

from appliance.contracts import ApplianceError, identity


def gate():
    return importlib.import_module("appliance.installer.live")


def test_consistent_inventory_passes_pure_gate(site, inventory):
    assert gate().live_gate(site, inventory, identity(site)) is None


@pytest.mark.parametrize("confirmation", [None, "", "yes", "0" * 64])
def test_confirmation_is_bound_to_the_whole_plan(site, inventory, confirmation):
    with pytest.raises(ApplianceError, match="erase-not-confirmed"):
        gate().live_gate(site, inventory, confirmation)


@pytest.mark.parametrize("fault,code", [
    ("boot-target", "target-is-boot-media"), ("renamed-disk", "target-identity-changed-or-ambiguous"),
    ("removed", "target-identity-changed-or-ambiguous"), ("duplicate", "target-identity-changed-or-ambiguous"),
    ("replaced-port", "port-identity-changed"), ("addressed-wan", "wan-host-address"),
    ("wan-link-local", "wan-host-address"), ("unsafe-vg", "non-target-storage-conflict"),
    ("unsupported", "unsupported-hardware"), ("bad-link-check", "port-identification-incomplete"),
    ("missing-boot-media", "inventory-incomplete"), ("empty-boot-media", "inventory-incomplete"),
    ("pretend-supported", "unsupported-hardware"),
])
def test_unsafe_inventory_stops_before_handoff(site, inventory, fault, code):
    if fault == "boot-target": inventory["boot_media_ids"].append(site["target"]["by_id"])
    elif fault == "renamed-disk": inventory["disks"][0]["identity"]["serial"] = "OTHER"
    elif fault == "removed": inventory["disks"] = []
    elif fault == "duplicate": inventory["disks"].append(copy.deepcopy(inventory["disks"][0]))
    elif fault == "replaced-port": inventory["ports"]["wan"]["permanent_mac"] = "02:aa:00:00:00:09"
    elif fault == "addressed-wan": inventory["addresses"]["wan"] = ["192.168.1.50/24"]
    elif fault == "wan-link-local": inventory["addresses"]["wan"] = ["fe80::123/64"]
    elif fault == "unsafe-vg": inventory["storage_conflicts"] = ["foreign-pve-vg"]
    elif fault == "unsupported": inventory["supported"] = False
    elif fault == "bad-link-check": inventory["link_checks"]["management"] = False
    elif fault == "missing-boot-media": del inventory["boot_media_ids"]
    elif fault == "empty-boot-media": inventory["boot_media_ids"] = []
    elif fault == "pretend-supported": inventory["supported"] = "yes"
    with pytest.raises(ApplianceError) as err:
        gate().live_gate(site, inventory, identity(site))
    assert err.value.code == code


def test_unknown_hardware_capabilities_are_not_accepted(site, release, inventory):
    inventory["memory_mib"] = 4096
    problems = gate().preflight(site, release, inventory)
    assert "insufficient-memory" in problems
    assert "installer-adapter-unqualified" in problems


def test_even_declared_qualification_does_not_enable_missing_adapter(site, release, inventory):
    release["profile"]["qualification"] = "qualified"
    release["budgets"]["qualification"] = "qualified"
    assert "installer-adapter-unqualified" in gate().preflight(site, release, inventory)


def test_preview_does_not_mutate_or_open_target(site, release):
    before = copy.deepcopy(site)
    result = gate().preview(site, release)
    assert result["destructive_actions_enabled"] is False
    assert result["target"]["serial"] == "PILOT_123"
    assert result["networks"]["management"]["host_ip"] == "10.77.0.2"
    assert site == before

"""Catch unsafe plans before any host operation is possible."""
import copy
import importlib
import json

import pytest


def modules():
    return importlib.import_module("appliance.contracts"), importlib.import_module("appliance.plan")


def test_valid_base_plan_is_copied_and_canonical(site, release):
    contracts, plan = modules()
    result = plan.validate_site(site, release)
    assert result == site and result is not site
    assert contracts.identity(site) == contracts.identity(json.loads(json.dumps(site, sort_keys=True)))
    result["ports"]["management"]["driver"] = "changed"
    assert site["ports"]["management"]["driver"] == "igc"


@pytest.mark.parametrize("fault,code", [
    ("schema", "unsupported-schema"), ("extra", "unknown-field"),
    ("ipv6", "ipv4-required"), ("overlay", "subnet-overlap"),
    ("upstream", "subnet-overlap"), ("bridge", "bridge-assignment"),
    ("host-wan", "unknown-field"), ("duplicate-id", "duplicate-vmid"),
    ("duplicate-mac", "duplicate-mac"), ("shared-port", "duplicate-port"),
    ("guest-management", "forbidden-zone"), ("small-vm", "insufficient-vm-resources"),
    ("disk-id", "unstable-disk-identity"), ("bad-admin", "address-collision"),
    ("bool-id", "invalid-integer"), ("secret", "unknown-field"),
    ("missing-router-zone", "router-zone-assignment"),
])
def test_unsafe_site_is_rejected(site, release, fault, code):
    contracts, plan = modules()
    if fault == "schema": site["schema"] = 2
    elif fault == "extra": site["commands"] = ["erase"]
    elif fault == "ipv6": site["networks"]["workload"]["cidr"] = "fd00::/64"
    elif fault == "overlay": site["overlay_cidrs"] = ["10.77.0.0/16"]
    elif fault == "upstream": site["upstream"]["cidrs"] = ["10.77.2.0/24"]
    elif fault == "bridge": site["networks"]["workload"]["bridge"] = "vmbr1"
    elif fault == "host-wan": site["networks"]["workload"]["host_ip"] = "10.77.2.20"
    elif fault == "duplicate-id": site["vms"]["probe"]["vmid"] = 101
    elif fault == "duplicate-mac": site["vms"]["probe"]["nics"][0]["mac"] = "02:bb:00:00:00:01"
    elif fault == "shared-port": site["ports"]["wan"] = copy.deepcopy(site["ports"]["management"])
    elif fault == "guest-management": site["vms"]["probe"]["nics"][0]["zone"] = "management"
    elif fault == "small-vm": site["vms"]["router"]["memory_mib"] = 512
    elif fault == "disk-id": site["target"]["serial"] = ""
    elif fault == "bad-admin": site["networks"]["management"]["admin_ip"] = "10.77.0.2"
    elif fault == "bool-id": site["vms"]["router"]["vmid"] = True
    elif fault == "secret": site["roles"]["connector"]["auth_key"] = "NEVER_LOG_THIS"
    elif fault == "missing-router-zone": site["vms"]["router"]["nics"].pop()
    with pytest.raises(contracts.ApplianceError) as err:
        plan.validate_site(site, release)
    assert err.value.code == code
    assert "NEVER_LOG_THIS" not in str(err.value)


def test_bad_static_gateway_rejected(site, release):
    contracts, plan = modules()
    site["upstream"] = {"mode": "static", "cidrs": ["192.168.1.0/24"],
                        "address": "192.168.1.5/24", "gateway": "192.168.2.1", "dns": ["1.1.1.1"]}
    with pytest.raises(contracts.ApplianceError, match="upstream-gateway"):
        plan.validate_site(site, release)


def test_test_release_cannot_be_production(release):
    contracts, plan = modules()
    with pytest.raises(contracts.ApplianceError, match="test-artifact"):
        plan.validate_release(release, production=True)


def test_duplicate_json_fields_and_nonfinite_numbers_rejected(tmp_path):
    contracts, _ = modules()
    for content in ('{"a":1,"a":2}', '{"value":NaN}', '{"value":1.2}'):
        path = tmp_path / "plan.json"
        path.write_text(content)
        with pytest.raises(contracts.ApplianceError):
            contracts.load_json(path)


def test_invalid_json_and_symlinks_do_not_leak_content(tmp_path):
    contracts, _ = modules()
    source = tmp_path / "secret"
    source.write_text("SECRET-BAD-JSON")
    link = tmp_path / "plan.json"
    link.symlink_to(source)
    with pytest.raises(contracts.ApplianceError) as err:
        contracts.load_json(link)
    assert "SECRET" not in str(err.value)


def test_required_selected_role_requires_guest(site, release):
    contracts, plan = modules()
    site["roles"]["connector"] = {"selected": True, "controller": "https://control.example.org"}
    with pytest.raises(contracts.ApplianceError, match="selected-role-missing-vm"):
        plan.validate_site(site, release)


def test_insufficient_target_disk_rejected(site, release):
    contracts, plan = modules()
    site["target"]["size_bytes"] = 20 * 1024**3
    with pytest.raises(contracts.ApplianceError, match="insufficient-disk"):
        plan.validate_site(site, release)


def test_malformed_vm_container_is_a_contract_error(site, release):
    contracts, plan = modules()
    site["roles"]["connector"]["selected"] = True
    site["vms"] = None
    with pytest.raises(contracts.ApplianceError, match="object-required"):
        plan.validate_site(site, release)


@pytest.mark.parametrize("field,value", [("filename", 42), ("required_for", [{}])])
def test_malformed_component_fields_are_contract_errors(release, field, value):
    contracts, plan = modules()
    item = {"id": "probe-image", "version": "1", "url": "https://example.org/image",
            "sha256": "a" * 64, "size_bytes": 1, "max_bytes": 1,
            "provenance": {"kind": "official-checksum", "url": "https://example.org/SHA256SUMS"}}
    item[field] = value
    release["components"] = [item]
    with pytest.raises(contracts.ApplianceError):
        plan.validate_release(release, production=False)

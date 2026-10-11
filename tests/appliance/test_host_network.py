import importlib
import os
from pathlib import Path
import stat

import pytest

from appliance.contracts import ApplianceError


def api():
    return importlib.import_module("appliance.host_network")


PORTS = {"management": "enp1s0", "wan": "enp2s0"}


def observed_ports(site):
    return [{"name": PORTS[role], **record} for role, record in site["ports"].items()]


def test_resolve_uses_all_stable_identity_fields_not_order(site):
    records = list(reversed(observed_ports(site)))
    assert api().resolve_ports(site, records) == PORTS
    records[0]["permanent_mac"] = "02:ff:00:00:00:01"
    with pytest.raises(ApplianceError, match="port-identity-unresolved"):
        api().resolve_ports(site, records)


def test_ambiguous_port_identity_and_name_injection_are_rejected(site):
    records = observed_ports(site)
    with pytest.raises(ApplianceError, match="port-identity-unresolved"):
        api().resolve_ports(site, records + records[:1])
    with pytest.raises(ApplianceError):
        api().render_host(site, {**PORTS, "wan": "wan\nup evil"})


def interfaces(data):
    result = {}
    current = None
    auto = set()
    for line in data.decode().splitlines():
        words = line.split()
        if not words or words[0] == "#":
            continue
        if words[0] == "auto":
            auto.update(words[1:])
        elif words[0] == "iface":
            current = words[1]
            result[current] = {"method": words[3]}
        elif line.startswith(" ") and current:
            result[current][words[0]] = " ".join(words[1:])
    return result, auto


def test_full_layout_has_only_management_l3_and_one_router_default(site):
    files = api().render_host(site, PORTS)
    iface, auto = interfaces(files["/etc/network/interfaces"])
    assert iface["vmbr0"]["address"] == "10.77.0.2/24"
    assert iface["vmbr0"]["gateway"] == "10.77.0.1"
    assert iface["vmbr0"]["bridge-ports"] == "enp1s0"
    assert iface["vmbr1"]["bridge-ports"] == "enp2s0"
    for name in ("enp1s0", "enp2s0", "vmbr1", "vmbr2", "vmbr3"):
        assert iface[name]["method"] == "manual"
        assert "address" not in iface[name] and "gateway" not in iface[name]
    assert iface["vmbr2"]["bridge-ports"] == iface["vmbr3"]["bridge-ports"] == "none"
    assert auto == {"lo", "vmbr0"}  # Other bridges wait for post-PVE policy.
    assert not any(path.startswith("/etc/pve/") for path in files)


def test_first_install_fallback_only_activates_static_management(site):
    files = api().safe_management_files(site, PORTS)
    iface, auto = interfaces(files["/etc/network/interfaces"])
    assert auto == {"lo", "vmbr0"}
    assert "gateway" not in iface["vmbr0"]
    assert all("gateway" not in record for record in iface.values())
    assert iface["vmbr0"]["address"] == "10.77.0.2/24"


def test_guard_limits_host_access_by_ingress_and_preserves_update_replies(site):
    files = api().render_host(site, PORTS)
    rules = api().host_policy(site)
    assert rules["management_interface"] == "vmbr0"
    assert rules["management_address"] == "10.77.0.2"
    assert rules["management_tcp_ports"] == [22, 8006]
    assert rules["reply_interface"] == "vmbr0"
    assert rules["dns_time_address"] == "10.77.0.1"
    assert rules["forwarding"] is False and rules["ipv6"] is False
    guard = files["/etc/rdc-appliance/host-guard.nft"].decode()
    assert guard.index('iifname != "vmbr0" drop') < guard.index("ct state established,related accept")
    assert "10.77.0.2" in guard and "8006" in guard
    # Locally generated replies acquire conntrack state at output priority -200.
    # A raw-priority (-300) output drop would reject SSH replies before lookup.
    assert 'type filter hook output priority 0; policy drop;' in guard


def test_guard_allows_restricted_router_ssh_only_at_management_gateway(site):
    guard = api().render_host(site, PORTS)[api().GUARD].decode()
    output = guard.split('chain output {', 1)[1]
    assert 'ip daddr 10.77.0.1 tcp dport { 22, 53 } accept' in output
    assert '\n  tcp dport 22 accept' not in output


def clean_observation(site):
    return {"addresses": {"lo": ["127.0.0.1/8", "::1/128"], "enp1s0": [], "enp2s0": [],
                           "vmbr0": ["10.77.0.2/24"], "vmbr1": [], "vmbr2": [], "vmbr3": []},
            "default_routes": [{"dev": "vmbr0", "gateway": "10.77.0.1"}],
            "forwarding": False, "ipv6_disabled": True, "firewall_active": True, "nat_active": False,
            "management_ingress_only": True,
            "bridge_members": {"vmbr0": ["enp1s0"], "vmbr1": ["enp2s0"], "vmbr2": [], "vmbr3": []},
            "resolved_ports": PORTS, "ports": observed_ports(site)}


def test_host_audit_reports_missing_observations_and_foreign_paths(site):
    assert api().audit_host(site, {})
    observed = clean_observation(site)
    assert api().audit_host(site, observed) == []
    observed["addresses"]["vmbr1"] = ["fe80::1/64"]
    assert "wan-host-address" in api().audit_host(site, observed)
    observed = clean_observation(site)
    observed["bridge_members"]["vmbr0"].append("enp9s0")
    assert "management-bridge-foreign-member" in api().audit_host(site, observed)
    observed["default_routes"].append({"dev": "enp2s0", "gateway": "192.0.2.1"})
    assert "host-default-route" in api().audit_host(site, observed)


def test_generic_files_are_atomic_and_reject_symlink_inheritance(tmp_path):
    files = importlib.import_module("appliance.files")
    files.atomic_write(tmp_path, "/etc/network/interfaces", b"one", mode=0o644)
    assert files.read_optional(tmp_path, "/etc/network/interfaces") == b"one"
    assert stat.S_IMODE((tmp_path / "etc/network/interfaces").stat().st_mode) == 0o644
    original = tmp_path / "elsewhere"
    original.mkdir()
    (tmp_path / "linked").symlink_to(original, target_is_directory=True)
    with pytest.raises(ApplianceError):
        files.atomic_write(tmp_path, "/linked/file", b"bad")
    assert not list(original.iterdir())
    with pytest.raises(ApplianceError):
        files.atomic_write(tmp_path, "/etc/../outside", b"bad")


def test_generic_files_reject_hardlinks_and_unowned_changes(tmp_path):
    files = importlib.import_module("appliance.files")
    files.atomic_write(tmp_path, "/owned", b"old")
    os.link(tmp_path / "owned", tmp_path / "second")
    with pytest.raises(ApplianceError):
        files.atomic_write(tmp_path, "/owned", b"new")
    assert (tmp_path / "second").read_bytes() == b"old"
    with pytest.raises(ApplianceError):
        files.delete_owned(tmp_path, "/second", expected_sha256="0" * 64)


def test_audit_accepts_only_declared_guest_taps_and_refuses_host_nat(site):
    observed = clean_observation(site)
    # The VM adapter sorts WAN before management, independent of plan order.
    observed["bridge_members"]["vmbr0"].append("tap101i1")
    observed["bridge_members"]["vmbr1"].append("fwpr101p0")
    observed["bridge_members"]["vmbr3"] = ["tap101i3", "tap102i0"]
    observed["nat_active"] = False
    assert api().audit_host(site, observed) == []
    observed["bridge_members"]["vmbr3"].append("enp9s0")
    assert "guest-bridge-foreign-member" in api().audit_host(site, observed)
    observed["nat_active"] = True
    assert "host-nat-active" in api().audit_host(site, observed)

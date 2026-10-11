"""Pure validation of public appliance plans and reviewed release inputs."""
from __future__ import annotations

import copy
import ipaddress
import re
from urllib.parse import urlsplit

from .contracts import ApplianceError, Json, fields, integer, require

BRIDGES = {"management": "vmbr0", "infrastructure": "vmbr2", "workload": "vmbr3", "relay": "vmbr4"}
ROLES = {"connector", "headscale", "derp"}
ZONES = {"router": {"management", "wan", "infrastructure", "workload", "relay"},
         "probe": {"workload"}, "connector": {"infrastructure"},
         "headscale": {"infrastructure"}, "derp": {"relay"}}
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_DRIVER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _text(value, *, maximum=256):
    require(type(value) is str and 0 < len(value) <= maximum
            and all(32 <= ord(c) < 127 for c in value), "invalid-text")
    return value


def _name(value):
    require(type(value) is str and _NAME.fullmatch(value) is not None, "invalid-name")
    return value


def _driver(value):
    require(type(value) is str and _DRIVER.fullmatch(value) is not None, "invalid-driver")
    return value


def _mac(value):
    require(type(value) is str and _MAC.fullmatch(value) is not None, "invalid-mac")
    require(value != "00:00:00:00:00:00" and not int(value[:2], 16) & 1, "invalid-mac")
    return value


def _network(value):
    try:
        require(type(value) is str, "ipv4-required")
        network = ipaddress.ip_network(value, strict=True)
        require(network.version == 4, "ipv4-required")
        return network
    except ValueError as error:
        if isinstance(error, ApplianceError):
            raise
        raise ApplianceError("invalid-subnet") from None


def _address(value, network=None):
    try:
        require(type(value) is str, "ipv4-required")
        address = ipaddress.ip_address(value)
        require(address.version == 4, "ipv4-required")
        require(not (address.is_unspecified or address.is_multicast or address.is_loopback
                     or address.is_link_local or address == ipaddress.IPv4Address("255.255.255.255")),
                "invalid-address")
        if network is not None:
            require(address in network and address not in (network.network_address, network.broadcast_address),
                    "address-outside-subnet")
        return address
    except ValueError as error:
        if isinstance(error, ApplianceError):
            raise
        raise ApplianceError("invalid-address") from None


def _https(value):
    try:
        parsed = urlsplit(_text(value, maximum=2048))
        require(parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
                and not parsed.password and not parsed.fragment and not parsed.query
                and parsed.port in (None, 443), "https-url-required")
    except ValueError as error:
        if isinstance(error, ApplianceError):
            raise
        raise ApplianceError("https-url-required") from None


def _controller(value):
    _https(value)
    parsed = urlsplit(value)
    require(parsed.path in ('', '/'), 'controller-origin-required')
    _hostname(parsed.hostname)


def _hostname(value):
    require(type(value) is str and len(value) <= 253 and value == value.lower()
            and '.' in value and not value.endswith('.')
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in value.split('.')), 'invalid-hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ApplianceError('hostname-required')


def require_disjoint(networks):
    for index, left in enumerate(networks):
        for right in networks[index + 1:]:
            require(not left.overlaps(right), "subnet-overlap")


def validate_release(lock: Json, *, production: bool) -> Json:
    fields(lock, {"schema", "release_id", "adapter_id", "components", "profile", "budgets"},
           {"test_only", "notes", "adapter", "missing_components"})
    require(type(lock["schema"]) is int and lock["schema"] == 1, "unsupported-schema")
    if production:
        require(not lock.get("test_only", False), "test-artifact")
    _name(lock["release_id"])
    _name(lock["adapter_id"])
    profile = lock["profile"]
    fields(profile, {"arch", "firmware", "secure_boot", "storage", "network", "qualification"})
    require((profile["arch"], profile["firmware"], profile["secure_boot"], profile["storage"], profile["network"])
            == ("x86_64", "uefi", False, "ext4-lvmthin", "ethernet-ipv4"), "unsupported-profile")
    require(type(profile["secure_boot"]) is bool, "unsupported-profile")
    require(profile["qualification"] in ("unqualified", "qualified"), "invalid-qualification")
    budgets = lock["budgets"]
    fields(budgets, {"host", "router", "probe", *ROLES, "qualification"})
    require(budgets["qualification"] in ("unqualified", "qualified"), "invalid-qualification")
    for role in ("host", "router", "probe", *sorted(ROLES)):
        fields(budgets[role], {"memory_mib", "disk_gib"}, {"vcpus"})
        integer(budgets[role]["memory_mib"], 256, 1048576)
        integer(budgets[role]["disk_gib"], 1, 1048576)
        if role != "host":
            require("vcpus" in budgets[role], "missing-field")
        if "vcpus" in budgets[role]:
            integer(budgets[role]["vcpus"], 1, 1024)
    require(type(lock["components"]) is list and len(lock["components"]) <= 64, "invalid-components")
    seen = set()
    for item in lock["components"]:
        fields(item, {"id", "version", "url", "sha256", "size_bytes", "max_bytes", "provenance"},
               {"compression", "expanded", "test_only", "filename", "required_for", "license", "source"})
        _name(item["id"])
        require(item["id"] not in seen, "duplicate-component")
        seen.add(item["id"])
        _text(item["version"])
        _https(item["url"])
        require(type(item["sha256"]) is str and _HASH.fullmatch(item["sha256"]), "invalid-digest")
        integer(item["size_bytes"], 1, 64 * 1024**3)
        integer(item["max_bytes"], item["size_bytes"], 64 * 1024**3)
        require(item.get("compression", "none") in ("none", "bz2"), "unsupported-compression")
        if item.get("compression") == "bz2":
            require("expanded" in item, "missing-expanded-identity")
            fields(item["expanded"], {"sha256", "size_bytes", "max_bytes"})
            require(type(item["expanded"]["sha256"]) is str and _HASH.fullmatch(item["expanded"]["sha256"]), "invalid-digest")
            integer(item["expanded"]["size_bytes"], 1, 64 * 1024**3)
            integer(item["expanded"]["max_bytes"], item["expanded"]["size_bytes"], 64 * 1024**3)
        elif "expanded" in item:
            raise ApplianceError("unexpected-expanded-identity")
        provenance = item["provenance"]
        fields(provenance, {"kind", "url"}, {"sha256"})
        require(provenance["kind"] == "official-checksum", "unsupported-provenance")
        _https(provenance["url"])
        if "sha256" in provenance:
            require(type(provenance["sha256"]) is str and _HASH.fullmatch(provenance["sha256"]), "invalid-digest")
        if production:
            require(not item.get("test_only", False), "test-artifact")
        if "required_for" in item:
            require(type(item["required_for"]) is list and bool(item["required_for"])
                    and all(type(r) is str and r in {"base", *ROLES} for r in item["required_for"]), "invalid-component-role")
        if "filename" in item:
            require(type(item["filename"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}", item["filename"]) is not None,
                    "unsafe-filename")
    if production:
        require({"proxmox-iso", "opnsense-dvd", "probe-image", "restic"} <= seen, "missing-base-component")
    return copy.deepcopy(lock)


def validate_site(plan: Json, release: Json) -> Json:
    validate_release(release, production=False)
    fields(plan, {"schema", "site_id", "revision", "release_id", "target", "ports", "networks",
                  "upstream", "overlay_cidrs", "vms", "roles"}, {'probe_endpoint'})
    require(type(plan["schema"]) is int and plan["schema"] == 1, "unsupported-schema")
    _name(plan["site_id"])
    integer(plan["revision"], 1, 2**31 - 1)
    require(plan["release_id"] == release["release_id"], "release-mismatch")
    if 'probe_endpoint' in plan:
        probe = plan['probe_endpoint']
        fields(probe, {'id', 'host_id', 'admin_id', 'appliance_host_id', 'appliance_admin_id', 'key_sha256'})
        for key, value in probe.items():
            if key == 'key_sha256':
                require(type(value) is str and _HASH.fullmatch(value), 'probe-key-identity')
            else:
                require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value), 'probe-identity')
        require(probe['host_id'] != probe['appliance_host_id'] and
                probe['admin_id'] != probe['appliance_admin_id'], 'probe-not-independent')
    target = plan["target"]
    fields(target, {"by_id", "serial", "wwn", "size_bytes", "model", "transport"})
    require(type(target["by_id"]) is str
            and re.fullmatch(r"/dev/disk/by-id/[A-Za-z0-9_.:+-]+", target["by_id"])
            and target["by_id"].rsplit("/", 1)[-1] not in (".", ".."),
            "unstable-disk-identity")
    require(type(target["serial"]) is str and type(target["wwn"]) is str
            and bool(target["serial"].strip() or target["wwn"].strip()), "unstable-disk-identity")
    for key in ("serial", "wwn"):
        require(len(target[key]) <= 256 and all(32 <= ord(c) < 127 for c in target[key]), "unstable-disk-identity")
    integer(target["size_bytes"], 1, 1024**5)
    _text(target["model"])
    require(target["transport"] in ("sata", "nvme", "sas", "virtio", "scsi"), "unsupported-storage")
    fields(plan["ports"], {"management", "wan"})
    macs, pci = set(), set()
    for port in plan["ports"].values():
        fields(port, {"permanent_mac", "pci_path", "driver"})
        mac = _mac(port["permanent_mac"])
        require(type(port["pci_path"]) is str and re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", port["pci_path"]),
                "unstable-port-identity")
        require(mac not in macs and port["pci_path"] not in pci, "duplicate-port")
        macs.add(mac)
        pci.add(port["pci_path"])
        _driver(port["driver"])
    fields(plan["networks"], {"management", "infrastructure", "workload"}, {"relay"})
    networks, assigned = {}, {}
    for zone, settings in plan["networks"].items():
        extra = {"host_ip", "admin_ip"} if zone == "management" else set()
        fields(settings, {"bridge", "cidr", "gateway", "allocation"} | extra)
        require(settings["bridge"] == BRIDGES[zone], "bridge-assignment")
        network = _network(settings["cidr"])
        require(network.prefixlen <= 30, "subnet-too-small")
        expected = "reservation" if zone == "workload" else "static"
        require(settings["allocation"] == expected, "invalid-allocation")
        values = [_address(settings[key], network) for key in ("gateway", *sorted(extra))]
        require(len(set(values)) == len(values), "address-collision")
        networks[zone], assigned[zone] = network, set(values)
    require(type(plan["overlay_cidrs"]) is list and 0 < len(plan["overlay_cidrs"]) <= 16, "invalid-overlay-ranges")
    upstream = plan["upstream"]
    require(type(upstream) is dict and upstream.get("mode") in ("dhcp", "static"), "unsupported-upstream")
    fields(upstream, {"mode", "cidrs"} | ({"address", "gateway", "dns"} if upstream["mode"] == "static" else set()))
    require(type(upstream["cidrs"]) is list and len(upstream["cidrs"]) <= 16, "invalid-upstream-ranges")
    upstream_networks = [_network(value) for value in upstream["cidrs"]]
    if upstream["mode"] == "static":
        try:
            address = ipaddress.IPv4Interface(upstream["address"])
        except (ValueError, TypeError):
            raise ApplianceError("invalid-static-upstream") from None
        require(address.network in upstream_networks, "upstream-network-missing")
        gateway = _address(upstream["gateway"])
        require(gateway in address.network and gateway != address.ip
                and gateway not in (address.network.network_address, address.network.broadcast_address), "upstream-gateway")
        _address(str(address.ip), address.network)
        require(type(upstream["dns"]) is list and 0 < len(upstream["dns"]) <= 3, "invalid-dns")
        for value in upstream["dns"]:
            _address(value)
    require_disjoint([*networks.values(), *upstream_networks, *map(_network, plan["overlay_cidrs"])])
    fields(plan["roles"], ROLES)
    fields(plan["vms"], {"router", "probe"}, ROLES)
    role_fields = {
        'connector': {'controller'},
        'headscale': {'hostname', 'authority', 'public_ipv4', 'certificate_ref', 'exposure', 'upstream_owner'},
        'derp': {'hostname', 'public_ipv4', 'certificate_ref', 'region_id', 'controller_url',
                 'routed_prefix', 'gateway', 'upstream_owner'},
    }
    required_settings = {
        'connector': {'controller'},
        'headscale': {'hostname', 'authority', 'public_ipv4', 'certificate_ref'},
        'derp': role_fields['derp'],
    }
    for role, settings in plan["roles"].items():
        fields(settings, {"selected"}, role_fields[role])
        require(type(settings["selected"]) is bool, "invalid-selection")
        for key, value in settings.items():
            if key == "selected":
                continue
            if key == "region_id": integer(value, 1, 65535)
            elif key in {"controller", "controller_url"}: _controller(value)
            elif key in {"public_ipv4", "gateway"}: _address(value)
            elif key == "routed_prefix": _network(value)
            elif key == 'hostname': _hostname(value)
            elif key == 'exposure': require(value in ('direct', 'upstream-dnat'), 'unsupported-exposure')
            elif key in {'authority', 'certificate_ref'}: _name(value)
            else: _text(value)
        if settings["selected"]:
            require(role in plan["vms"], "selected-role-missing-vm")
            require(required_settings[role] <= set(settings), 'role-settings-missing')
            if role == 'headscale' and settings.get('exposure') == 'upstream-dnat':
                require('upstream_owner' in settings, 'upstream-owner-required')
    vmids = set()
    disk_gib = release["budgets"]["host"]["disk_gib"]
    for role, vm in plan["vms"].items():
        fields(vm, {"role", "vmid", "name", "memory_mib", "vcpus", "disk_gib", "storage", "nics"})
        require(vm["role"] == role, "vm-role-mismatch")
        integer(vm["vmid"], 100, 999999999)
        require(vm["vmid"] not in vmids, "duplicate-vmid")
        vmids.add(vm["vmid"])
        _name(vm["name"])
        _name(vm["storage"])
        for key, maximum in (("memory_mib", 1048576), ("disk_gib", 1048576), ("vcpus", 1024)):
            integer(vm[key], 1, maximum)
            require(vm[key] >= release["budgets"][role][key], "insufficient-vm-resources")
        disk_gib += vm["disk_gib"]
        require(type(vm["nics"]) is list and 0 < len(vm["nics"]) <= 5, "invalid-nics")
        zones = set()
        for nic in vm["nics"]:
            fields(nic, {"zone", "mac"}, {"connected", "address"})
            require(type(nic["zone"]) is str and nic["zone"] in ZONES[role], "forbidden-zone")
            zone = nic["zone"]
            require(zone not in zones, "duplicate-zone")
            zones.add(zone)
            mac = _mac(nic["mac"])
            require(mac not in macs, "duplicate-mac")
            macs.add(mac)
            if "connected" in nic:
                require(type(nic["connected"]) is bool, "invalid-link-state")
            if role != "router":
                require(zone in networks, "missing-network")
                require("address" in nic, "guest-address-required")
                address = _address(nic["address"], networks[zone])
                require(address not in assigned[zone], "address-collision")
                assigned[zone].add(address)
            else:
                require("address" not in nic, "router-address-from-network")
        expected_zones = set(plan["networks"]) | {"wan"}
        if role == "router":
            require(zones == expected_zones, "router-zone-assignment")
        else:
            require(len(zones) == 1, "invalid-nics")
    require(target["size_bytes"] >= disk_gib * 1024**3, "insufficient-disk")
    return copy.deepcopy(plan)


def resource_requirements(plan: Json, release: Json) -> Json:
    validate_site(plan, release)
    return {"memory_mib": release["budgets"]["host"]["memory_mib"] + sum(v["memory_mib"] for v in plan["vms"].values()),
            "disk_bytes": (release["budgets"]["host"]["disk_gib"] + sum(v["disk_gib"] for v in plan["vms"].values())) * 1024**3,
            "vcpus": max(v["vcpus"] for v in plan["vms"].values())}

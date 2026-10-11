"""Fresh non-deployable inputs for the appliance contract tests."""
import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def release():
    return {
        "schema": 1, "release_id": "test-release", "adapter_id": "pve-test",
        "test_only": True, "components": [],
        "profile": {"arch": "x86_64", "firmware": "uefi", "secure_boot": False,
                    "storage": "ext4-lvmthin", "network": "ethernet-ipv4",
                    "qualification": "unqualified"},
        "budgets": {"host": {"memory_mib": 2048, "disk_gib": 16},
                    "router": {"memory_mib": 4096, "disk_gib": 16, "vcpus": 2},
                    "probe": {"memory_mib": 1024, "disk_gib": 8, "vcpus": 1},
                    "connector": {"memory_mib": 1024, "disk_gib": 8, "vcpus": 1},
                    "headscale": {"memory_mib": 1024, "disk_gib": 8, "vcpus": 1},
                    "derp": {"memory_mib": 1024, "disk_gib": 8, "vcpus": 1},
                    "qualification": "unqualified"},
    }


@pytest.fixture
def site():
    zones = {
        "management": {"bridge": "vmbr0", "cidr": "10.77.0.0/24",
                       "gateway": "10.77.0.1", "allocation": "static",
                       "host_ip": "10.77.0.2", "admin_ip": "10.77.0.3"},
        "infrastructure": {"bridge": "vmbr2", "cidr": "10.77.1.0/24",
                           "gateway": "10.77.1.1", "allocation": "static"},
        "workload": {"bridge": "vmbr3", "cidr": "10.77.2.0/24",
                     "gateway": "10.77.2.1", "allocation": "reservation"},
    }
    return {
        "schema": 1, "site_id": "pilot", "revision": 1, "release_id": "test-release",
        "target": {"by_id": "/dev/disk/by-id/ata-PILOT_123", "serial": "PILOT_123",
                   "wwn": "", "size_bytes": 137438953472, "model": "Pilot disk", "transport": "sata"},
        "ports": {"management": {"permanent_mac": "02:aa:00:00:00:01", "pci_path": "0000:01:00.0", "driver": "igc"},
                  "wan": {"permanent_mac": "02:aa:00:00:00:02", "pci_path": "0000:02:00.0", "driver": "igc"}},
        "networks": zones, "upstream": {"mode": "dhcp", "cidrs": ["192.168.1.0/24"]},
        "overlay_cidrs": ["100.64.0.0/10"],
        "vms": {
            "router": {"role": "router", "vmid": 101, "name": "pilot-router", "memory_mib": 4096,
                       "vcpus": 2, "disk_gib": 16, "storage": "local-lvm",
                       "nics": [{"zone": z, "mac": f"02:bb:00:00:00:{i:02x}", "connected": False}
                                for i, z in enumerate(("management", "wan", "infrastructure", "workload"), 1)]},
            "probe": {"role": "probe", "vmid": 102, "name": "pilot-probe", "memory_mib": 1024,
                      "vcpus": 1, "disk_gib": 8, "storage": "local-lvm",
                      "nics": [{"zone": "workload", "mac": "02:bb:00:00:00:05", "connected": False,
                                "address": "10.77.2.10"}]},
        },
        "roles": {name: {"selected": False} for name in ("connector", "headscale", "derp")},
    }


@pytest.fixture
def inventory(site):
    return {
        "boot_id": "live-boot-one", "supported": True, "arch": "x86_64",
        "virtualization": True, "firmware": "uefi", "secure_boot": False,
        "memory_mib": 16384, "vcpus": 4,
        "boot_media_ids": ["/dev/disk/by-id/usb-INSTALLER"],
        "disks": [{"identity": copy.deepcopy(site["target"]), "path": "/dev/sda"}],
        "ports": copy.deepcopy(site["ports"]), "addresses": {"management": [], "wan": []},
        "storage_conflicts": [], "link_checks": {"management": True, "wan": True},
    }

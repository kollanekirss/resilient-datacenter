"""Read-only preflight and guarded installation in the custom live entry.

Passing a pure gate is not an authorization to run an installer. A live
adapter collects fresh inventory itself and suppresses initial networking.
The implementation remains a qualification candidate until boot tests pass.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path

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
    require(current.get('unselected_active', False) is False, 'unselected-interface-active')
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
    # A mutable input field cannot qualify an adapter without boot evidence.
    problems.append("installer-adapter-unqualified")
    return problems


def live_environment(*, root=Path('/')) -> bool:
    """Strict actual-live check; a JSON preview cannot grant host mutations."""
    from appliance.state import read
    try:
        if root != Path('/') or os.geteuid() != 0:
            return False
        flags = (root / 'proc/cmdline').read_text().split()
        if 'rdc.appliance=1' not in flags or 'ipv6.disable=1' not in flags:
            return False
        pid1 = (root / 'proc/1/cmdline').read_bytes()
        if not any(path in pid1.split(b'\0') for path in (b'/sbin/unconfigured.sh', b'/usr/sbin/unconfigured.sh')):
            return False
        boot_id = (root / 'proc/sys/kernel/random/boot_id').read_text().strip()
        context = read(root / 'run/rdc-appliance/live.json')
        return context.get('boot_id') == boot_id and context.get('schema') == 1
    except (ApplianceError,OSError):
        return False


def install_site(plan, bundle: Path, confirmation: str, runner, *, password_hash: str,
                 consent_boot_id: str, root=Path('/')) -> dict:
    """Only the interactive live session can authorize this guarded handoff."""
    from appliance.state import lock, read
    from appliance.installer.inventory import inventory
    from appliance.installer.payload import verify_install_payload
    from appliance.installer.adapters import pve
    require(live_environment(root=root),'live-environment-required')
    require(bundle == Path('/cdrom/rdc-appliance'),'live-payload-location')
    release,build = verify_install_payload(bundle)
    plan = validate_site(plan,release)
    context = read(root / 'run/rdc-appliance/live.json')
    require(context.get('build_id') == identity(build),'live-build-mismatch')
    require(consent_boot_id == context['boot_id'],'erase-session-changed')
    directory = root / 'run/rdc-appliance'
    with lock(directory / 'install-lock'):
        require(not (directory / 'install-started.json').exists(),'installation-needs-inspection')
        observed = inventory(runner,root=root,plan=plan)
        live_gate(plan,observed,confirmation)
        require(observed['boot_id'] == consent_boot_id,'erase-session-changed')
        problems = preflight(plan,release,observed)
        # User explicitly chose this unqualified local installer candidate.
        # Only the two qualification labels may be deferred; hardware safety
        # and resource observations remain mandatory before any disk write.
        require(not set(problems) - {'resource-budgets-unqualified','installer-adapter-unqualified'}, 'installer-preflight')
        disk = next(d for d in observed['disks'] if d['identity'] == plan['target'])
        answer = pve.answer_bytes(plan,password_hash,disk_path=disk['path'],management_name=observed['port_names']['management'])
        pve.verify_upstream_selection(runner,disk_path=disk['path'],management_name=observed['port_names']['management'],root=root)
        # The pinned auto-installer parses and validates the TOML before
        # spawning its low-level installer. The builder's separate assistant
        # is not required in the live filesystem. Keep answers only in RAM.
        import tomllib
        require(tomllib.loads(answer.decode())['network']['source'] == 'from-answer','installer-answer')
        refreshed = inventory(runner,root=root,plan=plan)
        live_gate(plan,refreshed,confirmation)
        require(refreshed['boot_id'] == consent_boot_id and refreshed['port_names'] == observed['port_names']
                and next(d['path'] for d in refreshed['disks'] if d['identity'] == plan['target']) == disk['path'],
                'installer-inventory-changed')
        from appliance.state import write
        write(directory / 'install-started.json',{'schema':1,'plan_id':identity(plan),'boot_id':consent_boot_id,'phase':'pending'})
        # No automatic retry on any failure after this intent.
        receipt = pve.install(answer,runner,disk_path=disk['path'],management_name=observed['port_names']['management'],root=root,
                              prepared=True)
        receipt.update(target=plan['target'],plan_id=identity(plan),build_id=identity(build))
        staged = pve.stage_target(receipt,bundle,plan,runner)
        write(directory / 'install-started.json',{'schema':1,'plan_id':identity(plan),'boot_id':consent_boot_id,
                                                 'phase':'complete','build_id':staged['build_id']})
        return {'schema':1,'state':'staged','plan_id':identity(plan),'build_id':staged['build_id'],
                'qualification':'not-run','next_action':'Remove USB and boot the internal disk; keep router links disconnected.'}


def preview(plan, release):
    plan = validate_site(plan, release)
    return {"schema": 1, "state": "preview", "plan_id": identity(plan),
            "site_id": plan["site_id"], "release_id": plan["release_id"],
            "target": copy.deepcopy(plan["target"]), "ports": copy.deepcopy(plan["ports"]),
            "networks": copy.deepcopy(plan["networks"]), "resources": resource_requirements(plan, release),
            "destructive_actions_enabled": False,
            "blockers": ["installer-adapter-unqualified"],
            "next_action": "Qualify the live boot adapter on a disposable x86-64 Linux/KVM machine."}

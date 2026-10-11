"""Fresh, pinned router management and explicit gates for physical link changes.

No persisted/runtime JSON file is an activation capability. Management requires
an explicit in-process console attestation; WAN recollects the restricted SSH
channel and current PVE process on every call. Packet qualification is separate.
"""
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .contracts import ApplianceError, fields, identity, require
from . import proxmox, state as records
from .router_config import audit_router, parse_xml, render_router, zone_interfaces, FORCED_COMMAND

CHANNEL=Path("/etc/rdc-appliance/router-channel.json")
HELPER_SOURCE=Path(__file__).with_name("router")/"helper.php"
CONSOLE_CHECKS=("installed_disk","mac_mapping","management_dhcp_off","management_ra_off","ipv6_off",
                "unique_credentials","management_only_admin","restricted_helper","host_key_compared")
_ATTESTATION=object()


@dataclass(frozen=True)
class ConsoleAttestation:
    plan_id:str
    vmid:int
    boot_id:str
    config_id:str
    checked_at:float
    token:object


def _vm(plan,runner):
    spec=proxmox.vm_spec(plan,"router");observed=proxmox.observe_vm(spec["vmid"],runner)
    require(observed["running"] and observed["boot_id"] and observed["boot_order"]=="order=scsi0" and not observed["iso_present"],"router-installed-disk-required")
    require(observed["config"].get("description")==spec["ownership"] and observed["config"].get("onboot")=="0","router-vm-ownership")
    wanted={"net"+str(n["index"]):{"mac":n["mac"],"bridge":n["bridge"]} for n in spec["nics"]}
    require(set(observed["nics"])==set(wanted) and all({k:n[k] for k in ("mac","bridge")}==wanted[key] for key,n in observed["nics"].items()),"router-vm-network")
    return spec,observed


def attest_console(plan,checks,confirmation,runner):
    require(type(checks) is dict and set(checks)==set(CONSOLE_CHECKS) and all(v is True for v in checks.values()),"router-console-checks")
    require(confirmation=="CONNECT MANAGEMENT "+str(plan["vms"]["router"]["vmid"]),"router-console-confirmation")
    spec,observed=_vm(plan,runner)
    require(all(not n["connected"] for n in observed["nics"].values()),"router-console-isolation")
    return ConsoleAttestation(identity(plan),spec["vmid"],observed["boot_id"],identity(observed["config"]),time.monotonic(),_ATTESTATION)


def _private_file(path):
    require(type(path) is str and Path(path).is_absolute(),"router-channel-path")
    candidate=Path(path)
    try:
        require(not any(p.is_symlink() for p in (candidate,*candidate.parents)),"router-channel-symlink")
        fd=os.open(candidate,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size<=65536,"router-channel-private")
            return os.read(fd,65537)
        finally:os.close(fd)
    except OSError:raise ApplianceError("router-channel-file") from None


def _channel(plan):
    record=records.read(CHANNEL)
    fields(record,{"schema","plan_id","address","private_key","known_hosts","host_public_key","helper_sha256"})
    require(record["schema"]==1 and record["plan_id"]==identity(plan) and record["address"]==plan["networks"]["management"]["gateway"],"router-channel-binding")
    require(record["helper_sha256"]==hashlib.sha256(HELPER_SOURCE.read_bytes()).hexdigest(),"router-helper-version")
    require(_private_file(record["private_key"]),"router-channel-key")
    known=_private_file(record["known_hosts"])
    require(known==(record["address"]+" "+record["host_public_key"]+"\n").encode(),"router-channel-host-key")
    return record


def _request(plan,runner,action,**parameters):
    require(action in ("inspect","apply-policy","export-config"),"router-action")
    channel=_channel(plan);nonce=secrets.token_hex(16)
    request={"action":action,"plan_id":identity(plan),"nonce":nonce,**parameters}
    argv=["/usr/bin/ssh","-F","/dev/null","-T","-p","22","-i",channel["private_key"]]
    for option in ("BatchMode=yes","IdentitiesOnly=yes","IdentityAgent=none","StrictHostKeyChecking=yes",
                   "UserKnownHostsFile="+channel["known_hosts"],"GlobalKnownHostsFile=/dev/null","ClearAllForwardings=yes",
                   "ForwardAgent=no","RequestTTY=no","PermitLocalCommand=no","ProxyCommand=none","ProxyJump=none",
                   "ConnectTimeout=10","ConnectionAttempts=1","ServerAliveInterval=5","ServerAliveCountMax=2",
                   "HostKeyAlgorithms=ssh-ed25519","LogLevel=ERROR"):
        argv += ["-o",option]
    argv += ["root@"+channel["address"],"rdc-router"]
    result=runner.run(argv,stdin=json.dumps(request,sort_keys=True,separators=(",",":")).encode(),timeout_s=120 if action=="apply-policy" else 30)
    require(result.returncode==0 and type(result.stdout) is bytes and len(result.stdout)<=1048576,"router-channel-response")
    try:response=json.loads(result.stdout)
    except (ValueError,UnicodeError,RecursionError):raise ApplianceError("router-channel-response") from None
    require(type(response) is dict and response.get("nonce")==nonce,"router-channel-freshness")
    return response


def collect_router(plan,runner):
    spec,before=_vm(plan,runner);result=_request(plan,runner,"inspect")
    _,after=_vm(plan,runner)
    require(before["boot_id"]==after["boot_id"] and before["config"]==after["config"],"router-vm-changed")
    require(result.get("plan_id")==identity(plan) and result.get("vmid")==spec["vmid"]
            and isinstance(result.get("config_xml"),str),"router-observation")
    require(all(type(result.get(key)) is str and 0<len(result[key])<=524288 for key in
                ("boot_id","config_digest","root_kind","root_device","os_version","stage","rules_id","nat_id")),"router-observation")
    try:xml=result["config_xml"].encode()
    except UnicodeError:raise ApplianceError("router-observation") from None
    result["vm_boot_id"]=after["boot_id"];result["packet_tests"]="not-performed"
    # The full result is private: config_xml contains password hashes and keys.
    result["checks"]=audit_router(plan,xml,result)
    result["source"]="pinned-router-channel"
    return result


def router_ready(plan,runtime):
    xml=runtime.get("config_xml")
    problems=audit_router(plan,xml.encode(),runtime) if isinstance(xml,str) else ["router-installed-disk-required"]
    if not runtime.get("boot_id") or not runtime.get("vm_boot_id"):problems.append("router-boot-binding")
    # This is operational configuration readiness, not the B8 wire/packet verdict.
    return {"schema":1,"capability":"router-configuration","state":"configured" if not problems else "blocked",
            "checks_passed":not problems,"plan_id":identity(plan),"boot_id":runtime.get("boot_id"),
            "vm_boot_id":runtime.get("vm_boot_id"),"config_digest":runtime.get("config_digest"),
            "packet_tests":"not-performed","problems":sorted(set(problems)),
            "next_action":"Run the real guest and packet qualification checks." if not problems else "Check installed-disk boot and the restricted router channel."}


def _link(plan,zone,connected,runner,state,proof):
    spec,observed=_vm(plan,runner);receipt=proxmox._receipt(spec["vmid"],state)
    receipt=proxmox._bind(spec,receipt,observed,state)
    require(receipt["phase"]=="disk-ready","router-vm-not-ready")
    nic=next(n for n in spec["nics"] if n["zone"]==zone)
    if next(n for n in observed["nics"].values() if n["mac"]==nic["mac"])["connected"]==connected:return
    path=Path(state)/"router"/(zone+"-link.json")
    if path.exists():require(records.read(path).get("status")=="complete","router-operation-needs-inspection")
    sequence=records.read(path).get("sequence",0)+1 if path.exists() else 1
    desired=dict(receipt,links=dict(receipt["links"]))
    desired["links"][nic["mac"]]=connected
    expected=dict(observed["config"]);expected["net"+str(nic["index"])]=proxmox._nic_text(nic,connected)
    intent={"kind":"router-"+zone,"plan_id":identity(plan),"vmid":spec["vmid"],"boot_id":observed["boot_id"],"sequence":sequence,"proof":proof,
            "connected":connected,"target_config_id":identity(expected),"desired_receipt_id":identity(desired)}
    op=records.begin(Path(state)/"operations",intent)
    records.write(path,{"status":"pending","operation_id":op,"sequence":sequence,"desired_receipt":desired})
    proxmox.set_link(spec["vmid"],nic["mac"],connected,runner)
    proxmox.record_link(spec["vmid"],nic["mac"],connected,state)
    fresh=proxmox.observe_vm(spec["vmid"],runner)
    records.finish(Path(state)/"operations",op,{"config_id":identity(fresh["config"]),"boot_id":fresh["boot_id"]})
    records.write(path,{"status":"complete","operation_id":op,"sequence":sequence})


def enable_router_management(plan,console_observation,runner,state):
    item=console_observation
    require(type(item) is ConsoleAttestation and item.token is _ATTESTATION,"router-console-attestation-required")
    _,observed=_vm(plan,runner)
    require(item.plan_id==identity(plan) and item.vmid==observed["vmid"] and item.boot_id==observed["boot_id"]
            and item.config_id==identity(observed["config"]) and 0<=time.monotonic()-item.checked_at<=300,"router-console-attestation-stale")
    _channel(plan)  # No first-network-contact host key enrollment.
    _link(plan,"management",True,runner,state,{"console_checks":list(CONSOLE_CHECKS),"config_id":item.config_id})


def enable_wan(plan,runtime,runner,state):
    # Deliberately do not trust the optional caller-provided/saved status record.
    fresh=collect_router(plan,runner);ready=router_ready(plan,fresh)
    require(ready["checks_passed"] and fresh.get("stage")=="bootstrap" and fresh.get("guard_blocking") is True,"router-not-ready")
    _link(plan,"wan",True,runner,state,{"config_digest":fresh["config_digest"],"guest_boot_id":fresh["boot_id"]})
    records.write(Path(state)/"router"/"gate.json",ready)


def _upstream(plan,runtime):
    try:
        upstream=runtime["upstream"];networks=[ipaddress.IPv4Network(n) for n in upstream["cidrs"]]
        gateway=ipaddress.IPv4Address(upstream["gateway"])
        declared={ipaddress.IPv4Network(n) for n in plan["upstream"]["cidrs"]}
        protected=[ipaddress.IPv4Network(n["cidr"]) for n in plan["networks"].values()]+[ipaddress.IPv4Network(n) for n in plan["overlay_cidrs"]]
        require(networks and set(networks)<=declared and any(gateway in n for n in networks)
                and all(not a.overlaps(b) for a in networks for b in protected),"router-upstream-overlap")
    except (KeyError,TypeError,ValueError):raise ApplianceError("router-upstream-unobserved") from None


def apply_router_policy(plan,stage,runner,state):
    require(stage in ("bootstrap","transit"),"router-policy-stage")
    path=Path(state)/"router"/"policy.json"
    if path.exists():require(records.read(path).get("status")=="complete","router-operation-needs-inspection")
    fresh=collect_router(plan,runner);require(router_ready(plan,fresh)["checks_passed"],"router-not-ready")
    if stage=="transit":_upstream(plan,fresh)
    sequence=records.read(path).get("sequence",0)+1 if path.exists() else 1
    intent={"kind":"router-policy","stage":stage,"sequence":sequence,"plan_id":identity(plan),"boot_id":fresh["boot_id"],"config_digest":fresh["config_digest"]}
    op=records.begin(Path(state)/"operations",intent)
    records.write(path,{"status":"pending","operation_id":op,"sequence":sequence})
    response=_request(plan,runner,"apply-policy",stage=stage,operation_id=op,expected_digest=fresh["config_digest"],expected_boot_id=fresh["boot_id"])
    require(response.get("operation_id")==op and response.get("applied") is True,"router-policy-outcome")
    actual=collect_router(plan,runner);ready=router_ready(plan,actual)
    require(actual.get("stage")==stage and ready["checks_passed"] and actual["boot_id"]==fresh["boot_id"],"router-policy-outcome")
    if stage=="transit":require(actual.get("guard_blocking") is False,"router-transit-blocked")
    records.finish(Path(state)/"operations",op,{"boot_id":actual["boot_id"],"config_digest":actual["config_digest"]})
    records.write(path,{"status":"complete","operation_id":op,"sequence":sequence})
    if stage=="transit":
        for zone in ("infrastructure","workload","relay"):
            if zone in plan["networks"]:_link(plan,zone,True,runner,state,{"config_digest":actual["config_digest"],"guest_boot_id":actual["boot_id"]})
    return ready


def _pending_intent(plan,path,state,kind):
    pending=records.read(path)
    require(pending.get("status")=="pending","router-no-pending-operation")
    op=pending.get("operation_id")
    require(type(op) is str and re.fullmatch(r"[0-9a-f]{64}",op),"router-operation-identity")
    journal=records.read(Path(state)/"operations"/(op+".json"));intent=journal.get("operation",{})
    require(type(intent) is dict and identity(intent)==op and intent.get("kind")==kind
            and intent.get("plan_id")==identity(plan) and intent.get("sequence")==pending.get("sequence"),"router-operation-identity")
    return pending,op,intent


def reconcile_router_policy(plan,runner,state):
    """Reconcile an acknowledged guest completion; never retry guest mutation."""
    path=Path(state)/"router"/"policy.json"
    pending,op,intent=_pending_intent(plan,path,state,"router-policy")
    fresh=collect_router(plan,runner);ready=router_ready(plan,fresh);last=fresh.get("last_operation")
    require(ready["checks_passed"] and not fresh.get("pending_operation") and type(last) is dict,"router-policy-needs-console-inspection")
    expected={"status":"complete","operation_id":op,"stage":intent["stage"],"plan_id":identity(plan),
              "boot_id":fresh["boot_id"],"config_digest":fresh["config_digest"]}
    require(last==expected and fresh["boot_id"]==intent["boot_id"] and fresh["stage"]==intent["stage"],"router-policy-reconcile-mismatch")
    if intent["stage"]=="transit":
        require(fresh.get("guard_blocking") is False,"router-transit-blocked");_upstream(plan,fresh)
    records.finish(Path(state)/"operations",op,{"boot_id":fresh["boot_id"],"config_digest":fresh["config_digest"]})
    records.write(path,{"status":"complete","operation_id":op,"sequence":pending["sequence"]})
    # Links are intentionally untouched. Their own intents reconcile separately.
    return ready


def reconcile_router_link(plan,zone,runner,state):
    """Observe an exact saved link target and its live gate; publish no command."""
    require(zone in ("management","wan","infrastructure","workload","relay"),"router-link-zone")
    path=Path(state)/"router"/(zone+"-link.json")
    pending,op,intent=_pending_intent(plan,path,state,"router-"+zone)
    desired=pending.get("desired_receipt")
    require(type(desired) is dict and identity(desired)==intent.get("desired_receipt_id"),"router-link-reconcile-target")
    spec,observed=_vm(plan,runner)
    require(desired.get("spec")==spec and intent.get("vmid")==spec["vmid"]
            and observed["boot_id"]==intent["boot_id"] and identity(observed["config"])==intent["target_config_id"],"router-link-reconcile-mismatch")
    proxmox._owned(spec,observed,desired)
    fresh=collect_router(plan,runner);ready=router_ready(plan,fresh)
    require(ready["checks_passed"] and fresh["vm_boot_id"]==observed["boot_id"],"router-not-ready")
    proof=intent["proof"]
    if zone=="management":require(proof.get("console_checks")==list(CONSOLE_CHECKS),"router-console-attestation-required")
    else:
        require(fresh["config_digest"]==proof.get("config_digest") and fresh["boot_id"]==proof.get("guest_boot_id"),"router-link-proof-changed")
        if zone=="wan":require(fresh["stage"]=="bootstrap" and fresh.get("guard_blocking") is True,"router-not-ready")
        else:
            require(fresh["stage"]=="transit" and fresh.get("guard_blocking") is False,"router-transit-blocked");_upstream(plan,fresh)
    # Reobserve after SSH so no PVE config race is silently accepted.
    after=proxmox.observe_vm(spec["vmid"],runner)
    require(after["boot_id"]==observed["boot_id"] and after["config"]==observed["config"],"router-vm-changed")
    records.finish(Path(state)/"operations",op,{"config_id":identity(after["config"]),"boot_id":after["boot_id"]})
    records.write(proxmox._path(state,spec["vmid"]),desired)
    records.write(path,{"status":"complete","operation_id":op,"sequence":pending["sequence"]})
    return ready


def export_router(plan,runner):
    before=collect_router(plan,runner);require(router_ready(plan,before)["checks_passed"],"router-not-ready")
    result=_request(plan,runner,"export-config",expected_digest=before["config_digest"],expected_boot_id=before["boot_id"])
    require(type(result.get("config_xml")) is str,"router-export")
    xml=result["config_xml"].encode();parse_xml(xml)
    require(result.get("config_digest")==before["config_digest"]==hashlib.sha256(xml).hexdigest()
            and result.get("boot_id")==before["boot_id"],"router-export-changed")
    after=collect_router(plan,runner)
    require(after["config_digest"]==before["config_digest"] and after["boot_id"]==before["boot_id"] and after["vm_boot_id"]==before["vm_boot_id"],"router-export-changed")
    return xml


def bootstrap_files(plan,credentials):
    """Return private console-transfer files; caller must publish them with 0600.

    No key, password or file is generated on a router over an unpinned network.
    The caller supplies a unique password hash and observed MAC mapping.
    """
    bootstrap=render_router(plan,dict(credentials,stage="bootstrap"))
    transit=render_router(plan,dict(credentials,stage="transit"));helper=HELPER_SOURCE.read_bytes()
    plugin=b"<?php\nrequire_once '/conf/rdc-appliance/helper.php';\n"
    interfaces=zone_interfaces(plan)
    manifest={"schema":1,"plan_id":identity(plan),"vmid":plan["vms"]["router"]["vmid"],"version":"26.7",
        "host_ip":plan["networks"]["management"]["host_ip"],"management_ip":plan["networks"]["management"]["gateway"],
        "interface_map":credentials["interface_map"],"zone_interfaces":interfaces,
        "devices":{interfaces[n["zone"]]:credentials["interface_map"][n["mac"]] for n in plan["vms"]["router"]["nics"]},
        "guest_cidrs":[n["cidr"] for zone,n in plan["networks"].items() if zone!="management"],
        "upstream_cidrs":plan["upstream"]["cidrs"],"protected_cidrs":[n["cidr"] for n in plan["networks"].values()]+plan["overlay_cidrs"],
        "policies":{"bootstrap":hashlib.sha256(bootstrap).hexdigest(),"transit":hashlib.sha256(transit).hexdigest()},"helper_sha256":hashlib.sha256(helper).hexdigest(),"plugin_sha256":hashlib.sha256(plugin).hexdigest()}
    ssh=("# Managed appliance: OpenSSH reads this include before defaults.\n"
         "PasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\n"
         "PermitRootLogin forced-commands-only\nPermitTTY no\nAllowTcpForwarding no\nAllowStreamLocalForwarding no\n"
         "AllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\nPermitUserRC no\n"
         "ForceCommand "+FORCED_COMMAND+"\n").encode()
    return {"bootstrap.xml":bootstrap,"transit.xml":transit,"manifest.json":json.dumps(manifest,sort_keys=True).encode()+b"\n",
            "helper.php":helper,"rdcappliance.inc":plugin,"00-rdc-appliance.conf":ssh}

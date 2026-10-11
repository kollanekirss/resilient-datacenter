"""Local PVE operations with owned resources and durable, non-replayable intent.

No operation runs until called by the privileged appliance boundary. A running
QEMU process is configuration evidence, never proof of an installed guest OS.
"""
import copy
import json
from pathlib import Path
import re

from .contracts import ApplianceError, fields, identity, integer, require
from . import state as records

QM = "/usr/sbin/qm"
PVESH = "/usr/bin/pvesh"
ORDER = ("wan", "management", "infrastructure", "workload", "relay")
BRIDGES = dict(zip(ORDER, ("vmbr1", "vmbr0", "vmbr2", "vmbr3", "vmbr4")))
ZONES = {"router": set(ORDER), "probe": {"workload"}, "connector": {"infrastructure"},
         "headscale": {"infrastructure"}, "derp": {"relay"}}
MARKER = "rdc-appliance-v1:"


def _name(value):
    require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value), "vm-name")
    return value


def _mac(value):
    require(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value)
            and not int(value[:2],16)&1 and value!="00:00:00:00:00:00", "vm-mac")
    return value


def vm_spec(plan, role):
    require(role in ZONES and role in plan.get("vms",{}), "vm-role")
    vm=copy.deepcopy(plan["vms"][role])
    fields(vm,{"role","vmid","name","memory_mib","vcpus","disk_gib","storage","nics"})
    require(vm["role"]==role,"vm-role")
    integer(vm["vmid"],100,999999999)
    for key in ("name","storage"): _name(vm[key])
    for key in ("memory_mib","vcpus","disk_gib"): integer(vm[key],1,1048576)
    require(type(vm["nics"]) is list and 0<len(vm["nics"])<=5,"vm-nics")
    seen=set(); macs=set()
    for nic in vm["nics"]:
        fields(nic,{"zone","mac"},{"address","connected"})
        zone=nic["zone"]
        require(zone in ZONES[role] and zone not in seen,"vm-zone")
        require(_mac(nic["mac"]) not in macs,"vm-mac-duplicate")
        seen.add(zone);macs.add(nic["mac"])
        if zone!="wan": require(plan["networks"][zone]["bridge"]==BRIDGES[zone],"vm-bridge")
        nic.update(bridge=BRIDGES[zone],connected=False)
    require(seen==(set(plan["networks"])|{"wan"}) if role=="router" else len(seen)==1,"vm-zone")
    vm["nics"].sort(key=lambda nic: ORDER.index(nic["zone"]))
    for index,nic in enumerate(vm["nics"]): nic["index"]=index
    vm["site_id"]=_name(plan["site_id"])
    vm["ownership"]=MARKER+identity(vm)
    vm["plan_id"]=identity(plan)
    return vm


def _spec(spec):
    value=copy.deepcopy(spec)
    marker=value.pop("ownership",None)
    value.pop("plan_id",None)
    require(marker==MARKER+identity(value),"vm-spec-ownership")
    require(value.get("role") in ZONES,"vm-role")
    integer(value.get("vmid"),100,999999999)
    for key in ("name","storage"): _name(value.get(key))
    for key in ("memory_mib","vcpus","disk_gib"): integer(value.get(key),1,1048576)
    require(type(value.get("nics")) is list and 0<len(value["nics"])<=5,"vm-nics")
    for index,nic in enumerate(value["nics"]):
        require(nic["zone"] in ZONES[value["role"]] and nic["bridge"]==BRIDGES[nic["zone"]]
                and nic["index"]==index and nic["connected"] is False,"vm-spec-network")
        _mac(nic["mac"])
    return spec


def _run(runner,argv,*,timeout=30):
    result=runner.run(argv,timeout_s=timeout)
    require(result.returncode==0 and type(result.stdout) is bytes and len(result.stdout)<=1024*1024,"vm-command")
    try: return result.stdout.decode("utf-8")
    except UnicodeError: raise ApplianceError("vm-command") from None


def _json(runner,path,*args):
    try: return json.loads(_run(runner,[PVESH,"get",path,*args,"--output-format","json"]))
    except (ValueError,RecursionError): raise ApplianceError("vm-observation") from None


def _properties(raw):
    result={}
    for line in raw.splitlines():
        if not line or line.startswith("#"): continue
        require(":" in line,"vm-observation")
        key,value=line.split(":",1)
        require(re.fullmatch(r"[a-z][a-z0-9_]*",key) and key not in result,"vm-observation")
        result[key]=value.strip()
    return result


def _nic(value):
    parts=value.split(","); record={}
    for part in parts:
        require("=" in part,"vm-nic-config")
        key,data=part.split("=",1)
        require(key not in record,"vm-nic-config");record[key]=data
    require(set(record)=={"virtio","bridge","link_down","firewall"} and record["link_down"] in ("0","1")
            and record["firewall"]=="1","vm-nic-config")
    _mac(record["virtio"].lower());_name(record["bridge"])
    return {"mac":record["virtio"].lower(),"bridge":record["bridge"],"connected":record["link_down"]=="0"}


def observe_vm(vmid,runner):
    integer(vmid,100,999999999); key=str(vmid)
    current=_properties(_run(runner,[QM,"config",key,"--current","1"]))
    effective=_properties(_run(runner,[QM,"config",key]))
    require(current==effective,"vm-pending-drift")
    # qm's official print_recursive_hash emits nested telemetry. Only top-level
    # process/status scalars participate; nested device names are not config keys.
    raw_status=_run(runner,[QM,"status",key,"--verbose","1"])
    status=_properties("\n".join(line for line in raw_status.splitlines() if re.match(r"^(?:pid|status|qmpstatus):",line)))
    require(status.get("status") in ("running","stopped"),"vm-status")
    require(status.get("qmpstatus",status["status"]) in ("running","stopped"),"vm-paused-or-changing")
    boot=None
    if status["status"]=="running":
        require(re.fullmatch(r"[1-9][0-9]{0,9}",status.get("pid","")),"vm-process")
        host=_run(runner,["/usr/bin/cat","/proc/sys/kernel/random/boot_id"]).strip()
        process=_run(runner,["/usr/bin/cat","/proc/"+status["pid"]+"/stat"])
        require(") " in process,"vm-process")
        stat=process.rsplit(") ",1)[1].split()
        require(len(stat)>19 and stat[19].isdigit(),"vm-process")
        boot=identity({"host":host,"pid":status["pid"],"ticks":stat[19]})
    nics={key:_nic(value) for key,value in current.items() if re.fullmatch(r"net[0-9]+",key)}
    disk=current.get("scsi0","").split(",")[0]
    return {"vmid":vmid,"state":"configured","config":current,"nics":nics,"disk_volume":disk,
            "boot_order":current.get("boot",""),"iso_present":any("media=cdrom" in value for value in current.values()),
            "running":status["status"]=="running","boot_id":boot,"guest_verification":"not-performed"}


def _nic_text(nic,connected=False):
    return "virtio="+nic["mac"]+",bridge="+nic["bridge"]+",firewall=1,link_down="+("0" if connected else "1")


def _base(spec):
    return {"name":spec["name"],"description":spec["ownership"],"cores":str(spec["vcpus"]),"sockets":"1",
            "memory":str(spec["memory_mib"]),"balloon":"0","onboot":"0","ostype":"other" if spec["role"]=="router" else "l26",
            "scsihw":"virtio-scsi-single","boot":"order=scsi0",
            **{"net"+str(n["index"]):_nic_text(n) for n in spec["nics"]}}


def _owned(spec,observed,receipt):
    cfg=observed["config"];expected=_base(spec)
    require(not any(cfg.get(key) for key in ("args","hookscript","cicustom","lock","template","hostpci0")),"vm-unsafe-config")
    for key,value in expected.items():
        if key.startswith("net"):
            nic=observed["nics"].get(key,{})
            wanted=next(n for n in spec["nics"] if key=="net"+str(n["index"]))
            require(nic=={"mac":wanted["mac"],"bridge":wanted["bridge"],"connected":receipt.get("links",{}).get(wanted["mac"],False)},"vm-network-drift")
        elif key=="boot":
            require(cfg.get(key)==("order=ide2;scsi0" if receipt.get("iso") else value),"vm-boot-drift")
        else: require(cfg.get(key)==value,"vm-config-drift")
    allowed={"scsi0",*("net"+str(n["index"]) for n in spec["nics"])}
    if receipt.get("iso"):
        allowed.add("ide2"); require(cfg.get("ide2")==receipt["iso"]+",media=cdrom","vm-media-drift")
    devices={k for k in cfg if re.fullmatch(r"(?:net|scsi|sata|ide|virtio|unused|hostpci|usb|efidisk|tpmstate)[0-9]+",k)}
    require(devices==allowed,"vm-device-drift")
    disk=cfg.get("scsi0","");parts=disk.split(",")
    require(re.fullmatch(re.escape(spec["storage"])+":vm-"+str(spec["vmid"])+r"-disk-[0-9]+",parts[0]),"vm-disk-ownership")
    require(set(parts[1:])=={"size="+str(spec["disk_gib"])+"G"},"vm-disk-drift")
    if receipt.get("disk_volume"): require(observed["disk_volume"]==receipt["disk_volume"],"vm-disk-drift")


def _path(state,vmid): return Path(state)/"vms"/(str(vmid)+".json")


def _receipt(vmid,state):
    receipt=records.read(_path(state,vmid))
    require(not receipt.get("pending"),"vm-operation-needs-inspection")
    _spec(receipt["spec"])
    require(receipt["spec"]["vmid"]==vmid,"vm-receipt")
    return receipt


def _bind(spec,receipt,observed,state):
    # Allocation identity is immutable; the current plan revision is evidence,
    # not resource ownership. Rebind only after observing the original resource.
    require(receipt["spec"]["ownership"]==spec["ownership"],"vm-receipt-mismatch")
    _owned(spec,observed,receipt)
    if receipt["spec"]["plan_id"]!=spec["plan_id"]:
        receipt=dict(receipt,spec=spec)
        records.write(_path(state,spec["vmid"]),receipt)
    return receipt


def _mutate(receipt,kind,argv,runner,state,*,updates=None):
    spec=receipt["spec"];seq=receipt.get("sequence",0)+1
    intent={"kind":kind,"vmid":spec["vmid"],"ownership":spec["ownership"],"sequence":seq}
    updated=dict(receipt,sequence=seq,**(updates or {}));updated.pop("pending",None)
    running=kind in ("vm-start-installer","vm-start-disk","vm-start-owned")
    op=records.begin(Path(state)/"operations",intent)
    pending=dict(receipt,pending=op,desired={"receipt":updated,"running":running})
    records.write(_path(state,spec["vmid"]),pending)
    _run(runner,argv,timeout=180)
    observation=observe_vm(spec["vmid"],runner)
    _owned(spec,observation,updated)
    require(observation["running"] is running,"vm-running-outcome")
    updated["disk_volume"]=observation["disk_volume"]
    records.finish(Path(state)/"operations",op,{"vmid":spec["vmid"],"config_id":identity(observation["config"]),"boot_id":observation["boot_id"]})
    records.write(_path(state,spec["vmid"]),updated)
    return observation


def reconcile_vm(vmid,runner,state):
    """Resolve only an already-applied, exact journal target; never replay it."""
    integer(vmid,100,999999999)
    pending=records.read(_path(state,vmid))
    op=pending.get("pending");desired=pending.get("desired")
    require(type(op) is str and re.fullmatch(r"[0-9a-f]{64}",op) and type(desired) is dict,"vm-no-pending-operation")
    fields(desired,{"receipt","running"});require(type(desired["running"]) is bool,"vm-pending-operation")
    receipt=desired["receipt"];spec=_spec(receipt["spec"])
    require(spec["vmid"]==vmid and spec==pending["spec"] and not receipt.get("pending"),"vm-pending-operation")
    journal=records.read(Path(state)/"operations"/(op+".json"))
    intent=journal.get("operation",{})
    require(identity(intent)==op and intent.get("vmid")==vmid and intent.get("ownership")==spec["ownership"]
            and intent.get("sequence")==receipt["sequence"],"vm-pending-operation")
    observed=observe_vm(vmid,runner);_owned(spec,observed,receipt)
    require(observed["running"] is desired["running"],"vm-running-outcome")
    receipt=dict(receipt,disk_volume=observed["disk_volume"])
    records.finish(Path(state)/"operations",op,{"vmid":vmid,"config_id":identity(observed["config"]),"boot_id":observed["boot_id"]})
    records.write(_path(state,vmid),receipt)
    return observed


def ensure_vm(spec,runner,state):
    _spec(spec); path=_path(state,spec["vmid"])
    if path.exists():
        receipt=_receipt(spec["vmid"],state)
        observed=observe_vm(spec["vmid"],runner);_bind(spec,receipt,observed,state)
        return observed
    resources=_json(runner,"/cluster/resources","--type","vm")
    require(type(resources) is list and all(r.get("vmid")!=spec["vmid"] for r in resources),"vmid-in-use")
    node=_name(_run(runner,["/usr/bin/hostname","-s"]).strip())
    base="/nodes/"+node+"/storage/"+spec["storage"]
    storage=_json(runner,base+"/status")
    require(storage.get("active")==1 and storage.get("enabled")==1 and storage.get("type")=="lvmthin"
            and "images" in storage.get("content","").split(",")
            and type(storage.get("avail")) is int and storage["avail"] >= (spec["disk_gib"]+2)*1024**3,"vm-storage")
    require(_json(runner,base+"/content","--content","images","--vmid",str(spec["vmid"]))==[],"vm-unowned-disk")
    receipt={"schema":1,"spec":spec,"phase":"allocated","links":{},"sequence":0}
    options=dict(_base(spec),scsi0=spec["storage"]+":"+str(spec["disk_gib"]))
    argv=[QM,"create",str(spec["vmid"])]
    for key,value in options.items():argv += ["--"+key,value]
    return _mutate(receipt,"vm-create",argv,runner,state)


def attach_installer(spec,iso_volume,runner,state):
    _spec(spec)
    require(type(iso_volume) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,62}:iso/[A-Za-z0-9][A-Za-z0-9._-]*\.iso",iso_volume),"vm-iso")
    receipt=_receipt(spec["vmid"],state);require(receipt["phase"]=="allocated","vm-install-phase")
    observed=observe_vm(spec["vmid"],runner);receipt=_bind(spec,receipt,observed,state)
    require(not observed["running"],"vm-must-be-stopped")
    return _mutate(receipt,"vm-attach-iso",[QM,"set",str(spec["vmid"]),"--ide2",iso_volume+",media=cdrom","--boot","order=ide2;scsi0"],runner,state,
                   updates={"iso":iso_volume,"phase":"media-attached"})


def start_installer(vmid,runner,state):
    receipt=_receipt(vmid,state);require(receipt["phase"]=="media-attached","vm-install-phase")
    observed=observe_vm(vmid,runner);_owned(receipt["spec"],observed,receipt)
    require(not observed["running"] and all(not n["connected"] for n in observed["nics"].values()),"vm-installer-exposed")
    return _mutate(receipt,"vm-start-installer",[QM,"start",str(vmid)],runner,state,updates={"phase":"installing"})


def disk_boot(vmid,runner,state):
    receipt=_receipt(vmid,state);require(receipt["phase"] in ("installing","disk-ready"),"vm-install-phase")
    observed=observe_vm(vmid,runner);_owned(receipt["spec"],observed,receipt)
    require(not observed["running"],"vm-must-be-stopped")
    if receipt["phase"]=="installing":
        _mutate(receipt,"vm-detach-iso",[QM,"set",str(vmid),"--delete","ide2","--boot","order=scsi0"],runner,state,
                updates={"iso":None,"phase":"disk-ready"})
        receipt=_receipt(vmid,state)
    return _mutate(receipt,"vm-start-disk",[QM,"start",str(vmid)],runner,state)


def start_owned(plan,role,runner,state):
    spec=vm_spec(plan,role);receipt=_receipt(spec["vmid"],state)
    require(receipt["phase"]=="disk-ready" and not receipt.get("iso"),"vm-not-disk-ready")
    observed=observe_vm(spec["vmid"],runner);receipt=_bind(spec,receipt,observed,state)
    if observed["running"]:return observed
    if role=="router":
        # Persistent PVE links survive a host power loss. Withdraw upstream and
        # guest transport before cold boot; retain only confirmed management.
        links=dict(receipt["links"]);argv=[QM,"set",str(spec["vmid"])]
        for nic in spec["nics"]:
            if nic["zone"]!="management" and links.get(nic["mac"],False):
                links[nic["mac"]]=False
                argv += ["--net"+str(nic["index"]),_nic_text(nic,False)]
        if len(argv)>3:
            _mutate(receipt,"vm-cold-start-isolate",argv,runner,state,updates={"links":links})
            receipt=_receipt(spec["vmid"],state)
    return _mutate(receipt,"vm-start-owned",[QM,"start",str(spec["vmid"])],runner,state)


def set_link(vmid,mac,connected,runner):
    _mac(mac);require(type(connected) is bool,"vm-link-state")
    before=observe_vm(vmid,runner)
    require(re.fullmatch(re.escape(MARKER)+r"[0-9a-f]{64}",before["config"].get("description","")),"vm-not-owned")
    keys=[k for k,n in before["nics"].items() if n["mac"]==mac]
    require(len(keys)==1,"vm-link-identity")
    key=keys[0]; expected=dict(before["config"])
    expected[key]=_nic_text(before["nics"][key],connected)
    if before["nics"][key]["connected"]==connected:return
    _run(runner,[QM,"set",str(vmid),"--"+key,expected[key]])
    after=observe_vm(vmid,runner)
    require(after["config"]==expected,"vm-link-outcome")


def record_link(vmid,mac,connected,state):
    """Call only after a separately journaled and observed gate changes a link."""
    receipt=_receipt(vmid,state)
    require(mac in {n["mac"] for n in receipt["spec"]["nics"]},"vm-link-identity")
    receipt["links"][mac]=connected
    records.write(_path(state,vmid),receipt)

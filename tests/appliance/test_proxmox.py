"""Scripted PVE command boundary, without VM or host mutations."""
import copy
import json
import subprocess

import pytest

from appliance.contracts import ApplianceError
from appliance import proxmox


class Pve:
    def __init__(self):
        self.config = None
        self.status = "stopped"
        self.mutations = []
        self.lose = False
        self.foreign_disk = False
    def run(self, argv, stdin=b"", timeout_s=30):
        def result(value):
            return subprocess.CompletedProcess(argv, 0, value.encode(), b"")
        if argv[0] == "/usr/bin/hostname":
            return result("pve\n")
        if argv[0] == "/usr/bin/cat":
            return result("host-boot\n" if argv[1].endswith("boot_id") else "123 (qemu) S " + "0 " * 18 + "456 0\n")
        if argv[0] == "/usr/bin/pvesh":
            path = argv[2]
            if path == "/cluster/resources":
                return result(json.dumps([] if self.config is None else [{"vmid":101,"node":"pve","type":"qemu"}]))
            if path.endswith("/content"):
                return result(json.dumps([{"volid":"local-lvm:vm-101-disk-0"}] if self.foreign_disk else []))
            if path.endswith("/status"):
                return result(json.dumps({"active":1,"enabled":1,"avail":100*1024**3,"type":"lvmthin","content":"images"}))
        if argv[:2] == ["/usr/sbin/qm", "config"]:
            assert self.config is not None
            return result("\n".join(k+": "+str(v) for k,v in self.config.items())+"\n")
        if argv[:2] == ["/usr/sbin/qm", "status"]:
            return result("status: "+self.status+"\npid: "+("123" if self.status=="running" else "0")+"\n")
        self.mutations.append(argv)
        if argv[1] == "create":
            values = dict(zip([x[2:] for x in argv[3::2]], argv[4::2]))
            size = values["scsi0"].split(":")[1]
            values["scsi0"] = "local-lvm:vm-101-disk-0,size="+size+"G"
            self.config = values
        elif argv[1] == "set":
            for key,value in zip(argv[3::2],argv[4::2]):
                if key == "--delete":
                    for field in value.split(","): self.config.pop(field,None)
                else: self.config[key[2:]] = value
        elif argv[1] == "start": self.status = "running"
        else: raise AssertionError(argv)
        if self.lose: raise ApplianceError("runner-timeout")
        return result("")


def test_create_is_fixed_mac_disconnected_and_repeat_preserves_disk(site,tmp_path):
    spec=proxmox.vm_spec(site,"router"); run=Pve()
    first=proxmox.ensure_vm(spec,run,tmp_path/"state")
    assert first["state"]=="configured"
    assert run.config["onboot"]=="0"
    assert all("link_down=1" in run.config["net"+str(n)] for n in range(4))
    assert site["vms"]["router"]["nics"][0]["mac"] in run.config["net1"]
    changes=len(run.mutations)
    assert proxmox.ensure_vm(spec,run,tmp_path/"state")["disk_volume"]==first["disk_volume"]
    assert len(run.mutations)==changes


@pytest.mark.parametrize("fault",["foreign","mac","extra-nic","disk","onboot","args"])
def test_existing_drift_is_never_changed(site,tmp_path,fault):
    spec=proxmox.vm_spec(site,"router"); run=Pve()
    proxmox.ensure_vm(spec,run,tmp_path/"state")
    if fault=="foreign": run.config["description"]="unrelated"
    if fault=="mac": run.config["net0"]=run.config["net0"].replace("02:bb","02:cc")
    if fault=="extra-nic": run.config["net9"]="virtio=02:dd:00:00:00:01,bridge=vmbr0"
    if fault=="disk": run.config["scsi0"]="other:vm-101-disk-0,size=16G"
    if fault=="onboot": run.config["onboot"]="1"
    if fault=="args": run.config["args"]="-netdev something"
    changes=len(run.mutations)
    with pytest.raises(ApplianceError): proxmox.ensure_vm(spec,run,tmp_path/"state")
    assert len(run.mutations)==changes


def test_unknown_create_result_is_not_retried_or_silently_adopted(site,tmp_path):
    spec=proxmox.vm_spec(site,"router"); run=Pve();run.lose=True
    with pytest.raises(ApplianceError): proxmox.ensure_vm(spec,run,tmp_path/"state")
    run.lose=False
    with pytest.raises(ApplianceError): proxmox.ensure_vm(spec,run,tmp_path/"state")
    assert len(run.mutations)==1


def test_unused_foreign_disk_blocks_allocation(site,tmp_path):
    run=Pve();run.foreign_disk=True
    with pytest.raises(ApplianceError): proxmox.ensure_vm(proxmox.vm_spec(site,"router"),run,tmp_path/"state")
    assert not run.mutations


def test_iso_cannot_be_removed_from_running_installer(site,tmp_path):
    run=Pve();spec=proxmox.vm_spec(site,"router");state=tmp_path/"state"
    proxmox.ensure_vm(spec,run,state)
    proxmox.attach_installer(spec,"local:iso/opnsense.iso",run,state)
    proxmox.start_installer(101,run,state)
    count=len(run.mutations)
    with pytest.raises(ApplianceError): proxmox.disk_boot(101,run,state)
    assert len(run.mutations)==count
    run.status="stopped"
    result=proxmox.disk_boot(101,run,state)
    assert result["running"] and result["boot_order"]=="order=scsi0" and not result["iso_present"]
    assert result["state"]=="configured" and result["guest_verification"]=="not-performed"


def test_start_owned_never_creates_or_accepts_iso_boot(site,tmp_path):
    run=Pve();state=tmp_path/"state"
    with pytest.raises(ApplianceError): proxmox.start_owned(site,"router",run,state)
    assert not run.mutations
    spec=proxmox.vm_spec(site,"router")
    proxmox.ensure_vm(spec,run,state)
    proxmox.attach_installer(spec,"local:iso/opnsense.iso",run,state)
    with pytest.raises(ApplianceError): proxmox.start_owned(site,"router",run,state)


def test_only_router_can_join_management_or_wan(site):
    site["vms"]["probe"]["nics"][0]["zone"]="management"
    with pytest.raises(ApplianceError): proxmox.vm_spec(site,"probe")


def test_plan_revision_does_not_change_vm_allocation_owner(site):
    first=proxmox.vm_spec(site,"router")
    site["revision"]+=1
    second=proxmox.vm_spec(site,"router")
    assert first["ownership"]==second["ownership"]
    assert first["plan_id"]!=second["plan_id"]


def test_plan_revision_rebinds_receipt_without_vm_mutation(site,tmp_path):
    run=Pve();state=tmp_path/"state"
    proxmox.ensure_vm(proxmox.vm_spec(site,"router"),run,state)
    count=len(run.mutations)
    site["revision"]+=1
    proxmox.ensure_vm(proxmox.vm_spec(site,"router"),run,state)
    assert len(run.mutations)==count


def test_unknown_create_can_be_observed_and_reconciled_without_replay(site,tmp_path):
    spec=proxmox.vm_spec(site,"router");run=Pve();run.lose=True;state=tmp_path/"state"
    with pytest.raises(ApplianceError):proxmox.ensure_vm(spec,run,state)
    run.lose=False
    result=proxmox.reconcile_vm(101,run,state)
    assert result["disk_volume"]=="local-lvm:vm-101-disk-0"
    assert len(run.mutations)==1
    proxmox.ensure_vm(spec,run,state)
    assert len(run.mutations)==1


def test_reconcile_never_adopts_a_modified_unknown_outcome(site,tmp_path):
    spec=proxmox.vm_spec(site,"router");run=Pve();run.lose=True;state=tmp_path/"state"
    with pytest.raises(ApplianceError):proxmox.ensure_vm(spec,run,state)
    run.lose=False;run.config["onboot"]="1"
    with pytest.raises(ApplianceError):proxmox.reconcile_vm(101,run,state)
    assert len(run.mutations)==1


def test_verbose_status_accepts_nested_proxmox_telemetry(site,tmp_path):
    run=Pve();spec=proxmox.vm_spec(site,"router");proxmox.ensure_vm(spec,run,tmp_path/"state")
    normal=run.run
    def telemetry(argv,stdin=b"",timeout_s=30):
        if argv[:2]==[proxmox.QM,"status"]:
            return subprocess.CompletedProcess(argv,0,b"blockstat:\n\tscsi0:\n\t\trd_bytes: 12\npid: 0\nproxmox-support:\n\tbackup-fleecing: 1\nstatus: stopped\n",b"")
        return normal(argv,stdin,timeout_s)
    run.run=telemetry
    assert proxmox.observe_vm(101,run)["running"] is False


def _installed_connected(site,run,state):
    spec=proxmox.vm_spec(site,"router")
    proxmox.ensure_vm(spec,run,state)
    proxmox.attach_installer(spec,"local:iso/router.iso",run,state)
    proxmox.start_installer(101,run,state);run.status="stopped";proxmox.disk_boot(101,run,state)
    for nic in spec["nics"]:
        proxmox.set_link(101,nic["mac"],True,run)
        proxmox.record_link(101,nic["mac"],True,state)


def test_cold_start_disconnects_transit_before_start_preserving_confirmed_management(site,tmp_path):
    run=Pve();state=tmp_path/"state";_installed_connected(site,run,state)
    run.status="stopped";count=len(run.mutations)
    observed=proxmox.start_owned(site,"router",run,state)
    assert observed["running"]
    changes=run.mutations[count:]
    assert [a[1] for a in changes]==["set","start"]
    assert "link_down=0" in run.config["net1"]
    assert all("link_down=1" in run.config[key] for key in ("net0","net2","net3"))


def test_start_owned_does_not_change_a_running_router_with_wan_connected(site,tmp_path):
    run=Pve();state=tmp_path/"state";_installed_connected(site,run,state);count=len(run.mutations)
    assert proxmox.start_owned(site,"router",run,state)["running"]
    assert len(run.mutations)==count


def test_unknown_cold_start_disconnect_stays_stopped_until_reconciled(site,tmp_path):
    run=Pve();state=tmp_path/"state";_installed_connected(site,run,state)
    run.status="stopped";run.lose=True;count=len(run.mutations)
    with pytest.raises(ApplianceError):proxmox.start_owned(site,"router",run,state)
    assert run.status=="stopped" and len(run.mutations)==count+1
    run.lose=False
    with pytest.raises(ApplianceError):proxmox.start_owned(site,"router",run,state)
    proxmox.reconcile_vm(101,run,state)
    assert proxmox.start_owned(site,"router",run,state)["running"]
    assert len(run.mutations)==count+2

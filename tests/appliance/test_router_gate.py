import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import shutil

import pytest

from appliance import proxmox, router, state as records
from appliance.contracts import ApplianceError, identity
from appliance.router_config import render_router
from test_proxmox import Pve
from test_router_config import credentials, runtime


class RouterPve(Pve):
    def __init__(self,site,xml,creds):
        super().__init__();self.site=site;self.creds=creds;self.xml=xml;self.rt=runtime(site,xml,creds);self.ssh=[];self.lose_apply=False;self.lose_after_apply=False
    def run(self,argv,stdin=b"",timeout_s=30):
        if argv[0]!="/usr/bin/ssh":return super().run(argv,stdin,timeout_s)
        request=json.loads(stdin);self.ssh.append((argv,request))
        if request["action"]=="inspect":result=dict(self.rt,config_xml=self.xml.decode())
        elif request["action"]=="export-config":result={"config_xml":self.xml.decode(),"config_digest":hashlib.sha256(self.xml).hexdigest(),"boot_id":self.rt["boot_id"]}
        elif request["action"]=="apply-policy":
            if self.lose_apply:raise ApplianceError("runner-timeout")
            self.xml=render_router(self.site,dict(self.creds,stage=request["stage"]))
            self.rt.update(stage=request["stage"],config_digest=hashlib.sha256(self.xml).hexdigest(),guard_blocking=request["stage"]=="bootstrap")
            self.rt["last_operation"]={"status":"complete","operation_id":request["operation_id"],"stage":request["stage"],
                                       "boot_id":self.rt["boot_id"],"config_digest":self.rt["config_digest"],"plan_id":request["plan_id"]}
            if self.lose_after_apply:raise ApplianceError("runner-timeout")
            result={"operation_id":request["operation_id"],"applied":True}
        else:raise AssertionError(request)
        result["nonce"]=request["nonce"]
        return subprocess.CompletedProcess(argv,0,json.dumps(result).encode(),b"")


@pytest.fixture
def channel(site,tmp_path,monkeypatch):
    creds=credentials(site);xml=render_router(site,creds);run=RouterPve(site,xml,creds);state=tmp_path/"state"
    spec=proxmox.vm_spec(site,"router");proxmox.ensure_vm(spec,run,state)
    proxmox.attach_installer(spec,"local:iso/router.iso",run,state);proxmox.start_installer(101,run,state)
    run.status="stopped";proxmox.disk_boot(101,run,state)
    directory=tmp_path/"channel";directory.mkdir(mode=0o700)
    key=directory/"key";key.write_bytes(b"not-a-real-test-key");key.chmod(0o600)
    known=directory/"known_hosts";known.write_text("10.77.0.1 "+creds["management_public_key"]+"\n");known.chmod(0o600)
    path=directory/"channel.json"
    records.write(path,{"schema":1,"plan_id":identity(site),"address":"10.77.0.1","private_key":str(key),"known_hosts":str(known),"host_public_key":creds["management_public_key"],"helper_sha256":hashlib.sha256(router.HELPER_SOURCE.read_bytes()).hexdigest()})
    monkeypatch.setattr(router,"CHANNEL",path)
    return run,state


def test_runtime_file_is_never_a_management_authorization(site,channel):
    run,state=channel;before=len(run.mutations)
    with pytest.raises(ApplianceError):router.enable_router_management(site,{"checks":{k:True for k in router.CONSOLE_CHECKS}},run,state)
    assert len(run.mutations)==before


def test_console_requires_all_checks_exact_confirmation_and_same_boot(site,channel):
    run,state=channel;checks={k:True for k in router.CONSOLE_CHECKS}
    with pytest.raises(ApplianceError):router.attest_console(site,checks,"yes",run)
    checks["management_dhcp_off"]=False
    with pytest.raises(ApplianceError):router.attest_console(site,checks,"CONNECT MANAGEMENT 101",run)
    checks["management_dhcp_off"]=True
    attest=router.attest_console(site,checks,"CONNECT MANAGEMENT 101",run)
    router.enable_router_management(site,attest,run,state)
    assert "link_down=0" in run.config["net1"]
    assert "link_down=1" in run.config["net0"]


def test_collect_pins_ssh_and_export_binds_fresh_digest(site,channel):
    run,_=channel
    result=router.collect_router(site,run)
    assert result["packet_tests"]=="not-performed"
    assert router.export_router(site,run)==run.xml
    argv=run.ssh[0][0]
    assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv and "ClearAllForwardings=yes" in argv
    assert argv[-1]=="rdc-router" and "-T" in argv


def test_host_key_change_is_refused_before_network(site,channel):
    run,_=channel;record=records.read(router.CHANNEL)
    Path(record["known_hosts"]).write_text("10.77.0.1 ssh-ed25519 changed\n")
    with pytest.raises(ApplianceError):router.collect_router(site,run)
    assert not run.ssh


@pytest.mark.parametrize("fault",["empty-digest","bad-listener","bad-xml-type","bad-interface-map"])
def test_malformed_live_response_is_a_controlled_refusal(site,channel,fault):
    run,state=channel
    if fault=="empty-digest":run.rt["rules_id"]=None
    if fault=="bad-listener":run.rt["listeners"]=[None]
    if fault=="bad-xml-type":run.rt["boot_id"]=[]
    if fault=="bad-interface-map":run.rt["interface_map"]=[]
    with pytest.raises(ApplianceError):router.enable_wan(site,{},run,state)
    assert "link_down=1" in run.config["net0"]


def test_console_attestation_becomes_stale_after_config_change(site,channel):
    run,state=channel
    item=router.attest_console(site,{k:True for k in router.CONSOLE_CHECKS},"CONNECT MANAGEMENT 101",run)
    run.config["memory"]="8192"
    count=len(run.mutations)
    with pytest.raises(ApplianceError):router.enable_router_management(site,item,run,state)
    assert len(run.mutations)==count


def test_wan_ignores_forged_pass_and_collects_actual_unsafe_guest(site,channel):
    run,state=channel;run.rt["root_kind"]="live-iso";count=len(run.mutations)
    with pytest.raises(ApplianceError):router.enable_wan(site,{"state":"verified"},run,state)
    assert len(run.mutations)==count and run.ssh


def test_wan_safe_bootstrap_is_journaled_and_never_claims_packet_pass(site,channel):
    run,state=channel
    router.enable_wan(site,{},run,state)
    assert "link_down=0" in run.config["net0"]
    receipt=records.read(state/"router"/"gate.json")
    assert receipt["packet_tests"]=="not-performed"


def test_live_disk_not_ready(site):
    result=router.router_ready(site,{"root_kind":"live-iso"})
    assert result["state"]!="verified" and "installed-disk" in result["next_action"]


def test_lost_apply_response_is_never_replayed(site,channel):
    run,state=channel;run.lose_apply=True
    with pytest.raises(ApplianceError):router.apply_router_policy(site,"bootstrap",run,state)
    run.lose_apply=False
    with pytest.raises(ApplianceError):router.apply_router_policy(site,"bootstrap",run,state)
    assert sum(r["action"]=="apply-policy" for _,r in run.ssh)==1


def test_reconcile_completed_policy_uses_receipt_and_fresh_channel_without_replay(site,channel):
    run,state=channel;run.lose_after_apply=True
    with pytest.raises(ApplianceError):router.apply_router_policy(site,"bootstrap",run,state)
    run.lose_after_apply=False
    result=router.reconcile_router_policy(site,run,state)
    assert result["checks_passed"] and records.read(state/"router"/"policy.json")["status"]=="complete"
    assert sum(r["action"]=="apply-policy" for _,r in run.ssh)==1


def test_reconcile_policy_rejects_guest_pending_or_new_config(site,channel):
    run,state=channel;run.lose_apply=True
    with pytest.raises(ApplianceError):router.apply_router_policy(site,"bootstrap",run,state)
    run.lose_apply=False
    with pytest.raises(ApplianceError):router.reconcile_router_policy(site,run,state)
    assert records.read(state/"router"/"policy.json")["status"]=="pending"


def test_reconcile_applied_link_never_replays_qm_set(site,channel):
    run,state=channel;run.lose=True
    with pytest.raises(ApplianceError):router.enable_wan(site,{},run,state)
    count=len(run.mutations);run.lose=False
    result=router.reconcile_router_link(site,"wan",run,state)
    assert result["checks_passed"] and len(run.mutations)==count
    assert records.read(state/"router"/"wan-link.json")["status"]=="complete"
    assert records.read(state/"vms"/"101.json")["links"][site["vms"]["router"]["nics"][1]["mac"]] is True


def test_reconcile_link_refuses_changed_guest_policy(site,channel):
    run,state=channel;run.lose=True
    with pytest.raises(ApplianceError):router.enable_wan(site,{},run,state)
    run.lose=False;run.rt["boot_id"]="different-boot"
    with pytest.raises(ApplianceError):router.reconcile_router_link(site,"wan",run,state)
    assert records.read(state/"router"/"wan-link.json")["status"]=="pending"


def test_transit_requires_declared_nonoverlapping_fresh_upstream(site,channel):
    run,state=channel
    run.rt["upstream"]={"cidrs":["10.77.2.0/24"],"gateway":"10.77.2.1"}
    with pytest.raises(ApplianceError):router.apply_router_policy(site,"transit",run,state)
    assert not any(r["action"]=="apply-policy" for _,r in run.ssh)


def test_transit_links_internal_interfaces_only_after_policy_verification(site,channel):
    run,state=channel
    router.enable_wan(site,{},run,state)
    run.rt["upstream"]={"cidrs":["192.168.1.0/24"],"gateway":"192.168.1.1"}
    result=router.apply_router_policy(site,"transit",run,state)
    assert result["state"]=="configured" and result["packet_tests"]=="not-performed"
    assert "link_down=0" in run.config["net2"] and "link_down=0" in run.config["net3"]
    assert "link_down=1" in run.config["net1"]


def test_bundle_plugin_loads_helper_once(site):
    bundle=router.bootstrap_files(site,credentials(site))
    assert b"require_once" in bundle["rdcappliance.inc"]
    assert b"function rdc_assert" not in bundle["rdcappliance.inc"]


def test_export_rejects_config_changed_between_inspect_and_export(site,channel):
    run,_=channel;old_run=run.run
    def changed(argv,stdin=b"",timeout_s=30):
        if argv[0]=="/usr/bin/ssh" and json.loads(stdin)["action"]=="export-config":run.xml+=b" "
        return old_run(argv,stdin,timeout_s)
    run.run=changed
    with pytest.raises(ApplianceError):router.export_router(site,run)


def test_php_dispatch_and_overlap_predicate_without_guest_execution():
    php=shutil.which("php")
    if not php:pytest.skip("PHP syntax/contract check requires PHP; guest qualification remains separate")
    source=str(router.HELPER_SOURCE)
    lint=subprocess.run([php,"-l",source],capture_output=True,check=False)
    assert lint.returncode==0,lint.stdout+lint.stderr
    script='require '+json.dumps(source)+'; '+r'''
        foreach ([['action'=>'shell'], ['action'=>'inspect','path'=>'/etc/passwd'] ] as $bad) {
            try { rdc_request($bad); exit(2); } catch (Throwable $e) {}
        }
        $m=['upstream_cidrs'=>['192.168.1.0/24'],'protected_cidrs'=>['10.77.0.0/24','100.64.0.0/10']];
        if (!rdc_upstream_allowed($m,['cidrs'=>['192.168.1.0/24'],'gateway'=>'192.168.1.1'])) exit(3);
        if (rdc_upstream_allowed($m,['cidrs'=>['10.77.0.0/24'],'gateway'=>'10.77.0.1'])) exit(4);
        if (rdc_upstream_allowed($m,['cidrs'=>[],'gateway'=>null])) exit(5);
        echo 'ok';
    '''
    result=subprocess.run([php,"-r",script],capture_output=True,check=False)
    assert result.returncode==0 and result.stdout==b"ok",result.stdout+result.stderr


def _php(script):
    php=shutil.which("php")
    if not php:pytest.skip("PHP is required for the isolated helper behavior test")
    result=subprocess.run([php,"-r",'require '+json.dumps(str(router.HELPER_SOURCE))+'; '+script],capture_output=True,check=False)
    assert result.returncode==0,result.stdout+result.stderr
    return json.loads(result.stdout)


def test_helper_quiesces_before_killing_states_and_preserves_management_flow():
    output=_php(r'''
        $m=['management_ip'=>'10.77.0.1','host_ip'=>'10.77.0.2',
            'guest_cidrs'=>['10.77.1.0/24','10.77.2.0/24'],
            'devices'=>['wan'=>'vtnet0','lan'=>'vtnet1','opt1'=>'vtnet2','opt2'=>'vtnet3']];
        $calls=[]; $run=function($argv) use (&$calls) { $calls[]=$argv; return ''; };
        rdc_quiesce($m,$run);
        echo json_encode($calls);
    ''')
    downs=[row for row in output if row[0]=="/sbin/ifconfig"]
    assert downs==[["/sbin/ifconfig",device,"down"] for device in ("vtnet2","vtnet3")]
    assert output[0]==["/sbin/sysctl","net.inet.ip.forwarding=0"]
    assert output[1:3]==downs
    assert not any("-F" in row for row in output)
    import ipaddress
    host_kills=[row for row in output if "10.77.0.2/32" in row]
    assert len(host_kills)==32
    destinations=[ipaddress.ip_network(row[-1]) for row in host_kills]
    assert not any(ipaddress.ip_address("10.77.0.1") in n for n in destinations)
    assert sum(n.num_addresses for n in destinations)==2**32-1


def test_helper_never_restores_transport_before_loaded_guard_check():
    output=_php(r'''
        $calls=[]; $loaded=false;
        $run=function($argv) use (&$calls) { $calls[]=$argv; return ''; };
        $check=function() use (&$loaded) { return $loaded; };
        try { rdc_restore_devices(['vtnet0','vtnet2'],$check,$run); } catch(Throwable $e) {}
        $before=$calls;
        $loaded=true; rdc_restore_devices(['vtnet0','vtnet2'],$check,$run);
        echo json_encode(['before'=>$before,'after'=>$calls]);
    ''')
    assert output["before"]==[]
    assert output["after"]==[["/sbin/ifconfig","vtnet0","up"],["/sbin/ifconfig","vtnet2","up"],["/sbin/sysctl","net.inet.ip.forwarding=1"]]


def test_loaded_guard_requires_explicit_labels_on_lan_and_each_guest():
    output=_php(r'''
        $m=['devices'=>['wan'=>'vtnet0','lan'=>'vtnet1','opt1'=>'vtnet2','opt2'=>'vtnet3']];
        $token=str_repeat('a',32);$text='';
        foreach(['lan','opt1','opt2'] as $if) {
            $text.='block drop in quick on '.$m['devices'][$if].' all label "rdc_guard_'.$token.'_'.$if.'"'."\n";
        }
        echo json_encode([rdc_guard_loaded($m,$token,$text),
            rdc_guard_loaded($m,$token,str_replace('rdc_guard_'.$token.'_lan','missing',$text)),
            rdc_guard_loaded($m,$token,'# RDC lease guard blocked')]);
    ''')
    assert output==[True,False,False]


def test_helper_has_no_global_state_flush():
    assert b"'-F', 'states'" not in router.HELPER_SOURCE.read_bytes()


def test_policy_transition_preserves_https_identity_without_restoring_old_policy():
    output = _php(r'''
        $current=['system'=>['hostname'=>'old','webgui'=>['ssl-certref'=>'generated-id','protocol'=>'http']],
            'cert'=>[['refid'=>'generated-id','crt'=>base64_encode('-----BEGIN CERTIFICATE-----test'),'prv'=>'private']],
            'ca'=>[['refid'=>'issuer']], 'filter'=>['old']];
        $policy=['system'=>['hostname'=>'new','webgui'=>['protocol'=>'https','interfaces'=>'lan']], 'filter'=>['new']];
        $after=rdc_preserve_web_identity($current,$policy);
        $rejected=false;$current['cert']=[];
        try { rdc_preserve_web_identity($current,$policy); } catch(Throwable $e) { $rejected=true; }
        echo json_encode(['after'=>$after,'rejected'=>$rejected]);
    ''')
    assert output['after']['system'] == {'hostname': 'new', 'webgui': {'protocol': 'https', 'interfaces': 'lan', 'ssl-certref': 'generated-id'}}
    assert output['after']['filter'] == ['new'] and output['after']['cert'][0]['prv'] == 'private'
    assert output['after']['ca'] == [{'refid': 'issuer'}] and output['rejected'] is True

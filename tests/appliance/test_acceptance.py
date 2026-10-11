"""Synthetic raw transcripts, never actual KVM or packet-qualification evidence.

Fixtures below are hand-authored command/wire records. They have not been
captured from Proxmox or OPNsense; the production parser and state machine are
real, while only the unavailable VM/serial/network boundary is substituted.
"""
import copy
import importlib
import json
import struct

import pytest


def api():
    return importlib.import_module('appliance.acceptance')


def context(site):
    from appliance.contracts import identity
    return {'plan': site, 'plan_id': identity(site), 'build_id': 'b'*64,
            'spec_id': 'c'*64, 'source_id': 'd'*64, 'run_id': 'e'*64}


def command(stdout='', returncode=0):
    return {'returncode': returncode, 'stdout': stdout, 'stderr': ''}


def network(nonce, *, denied=False):
    return {'nonce': nonce, 'attempt': command('' if denied else nonce, 28 if denied else 0),
            'source_control': command(nonce), 'destination_control': command(nonce),
            'source': '10.77.2.10', 'destination': '10.77.1.10', 'port': 443,
            'connected': not denied, 'error': 'timeout' if denied else None,
            'tls': {'verify_returncode': 0, 'peer_certificate_sha256': 'e'*64}}


def test_negative_firewall_probe_needs_both_live_controls():
    raw = network('challenge', denied=True)
    assert api().probe_result(raw, nonce='challenge', allowed=False)
    for key in ('source_control', 'destination_control'):
        bad = copy.deepcopy(raw); del bad[key]
        assert not api().probe_result(bad, nonce='challenge', allowed=False)
        bad = copy.deepcopy(raw); bad[key] = command('', 7)
        assert not api().probe_result(bad, nonce='challenge', allowed=False)


def test_network_nonce_prevents_old_controls_and_echoed_error_passing():
    raw = network('challenge', denied=True)
    raw['source_control']['stdout'] = 'old-challenge'
    assert not api().probe_result(raw, nonce='challenge', allowed=False)
    raw = network('challenge', denied=True)
    raw['attempt']['stdout'] = 'challenge'
    assert not api().probe_result(raw, nonce='challenge', allowed=False)


def test_https_requires_success_and_verified_certificate():
    raw = network('challenge')
    assert api().probe_result(raw, nonce='challenge', allowed=True, tls=True)
    raw['tls']['verify_returncode'] = 60
    assert not api().probe_result(raw, nonce='challenge', allowed=True, tls=True)
    raw = network('challenge'); raw['attempt']['returncode'] = 28
    assert not api().probe_result(raw, nonce='challenge', allowed=True, tls=True)


def test_ntp_service_response_must_match_current_request_not_claim_clock_accuracy():
    query=bytearray(48); query[0]=0x23; query[40:48]=bytes.fromhex('123456789abcdef0')
    response=bytearray(48); response[0]=0x24; response[1]=3
    response[24:32]=query[40:48]; response[40:48]=bytes.fromhex('fedcba9876543210')
    assert api().ntp_result(query.hex(),response.hex())
    response[24]=0
    assert not api().ntp_result(query.hex(),response.hex())
    response[24:32]=query[40:48]; response[1]=16; response[0]=0xe4
    assert api().ntp_result(query.hex(),response.hex())  # service alive, UTC untrusted


class RefusalDriver:
    synthetic=True
    def __init__(self,ctx,*,change_disk=False,stale=False):
        self.ctx=ctx; self.sequence=0; self.variant='normal'; self.change_disk=change_disk
        self.stale=stale; self.calls=[]
    def execute_action(self,action,parameters):
        self.calls.append((action,parameters)); self.sequence+=1
        if action=='prepare': self.variant=parameters['variant']; data={'profile':'live'}
        elif action=='observe' and parameters['kind']=='disks':
            data={'sha256':{'target':('f' if self.change_disk and self.sequence%4==0 else '1')*64,'canary':'2'*64}}
        elif action=='fault' and parameters['kind']=='erase-refusal':
            errors={'duplicate-identity':'target-identity-ambiguous','changed-capacity':'target-identity-changed',
                    'hot-remove':'target-identity-missing','spanning-storage':'storage-conflict',
                    'non-target-pve':'storage-conflict','cancel':'erase-not-confirmed',
                    'invalid-media':'payload-invalid','boot-media-target':'target-is-boot-media'}
            data=command(json.dumps({'error':errors[self.variant]}),2)
        else: raise AssertionError((action,parameters))
        return {'sequence':self.sequence,'checked_at': 0 if self.stale else 1000,
                'dependencies':{'plan':self.ctx['plan_id'],'build':self.ctx['build_id'],
                    'spec':self.ctx['spec_id'],'source':self.ctx['source_id'],'run':self.ctx['run_id'],
                    'host_boot':'live-'+self.variant}, 'data':data,
                'evidence':[{'path':'/synthetic/transcript','sha256':'a'*64}]}


def test_erase_refusals_check_all_attached_disk_hashes_and_actual_errors(site):
    ctx=context(site); result=api().run_case('erase-refusals',RefusalDriver(ctx),ctx,clock=lambda:1000)
    assert all(item['passed'] for item in result['assertions'])
    assert result['test_only'] is True and result['status']=='NOT RUN'
    assert result['state']=='unknown'
    broken=api().run_case('erase-refusals',RefusalDriver(ctx,change_disk=True),ctx,clock=lambda:1000)
    assert any(not item['passed'] and 'disk' in item['name'] for item in broken['assertions'])


def test_stale_observation_cannot_be_reused(site):
    ctx=context(site); result=api().run_case('erase-refusals',RefusalDriver(ctx,stale=True),ctx,clock=lambda:1000)
    assert result['state']!='verified'
    assert 'acceptance-observation-stale' in result['reasons']


def test_driver_cannot_submit_precomputed_passed_boolean(site):
    class BooleanDriver(RefusalDriver):
        def execute_action(self,action,parameters):
            result=super().execute_action(action,parameters)
            if action=='fault': result['data']={'passed':True}
            return result
    ctx=context(site); result=api().run_case('erase-refusals',BooleanDriver(ctx),ctx,clock=lambda:1000)
    assert any(not item['passed'] for item in result['assertions'])


def test_reused_sequence_and_changed_common_dependencies_are_refused(site):
    for mutate in ('sequence','build'):
        class Broken(RefusalDriver):
            def execute_action(self,action,parameters):
                value=super().execute_action(action,parameters)
                if mutate=='sequence': value['sequence']=1
                else: value['dependencies']['build']='f'*64
                return value
        ctx=context(site); result=api().run_case('erase-refusals',Broken(ctx),ctx,clock=lambda:1000)
        assert result['reasons'] and not all(a['passed'] for a in result['assertions'])


def test_physical_operator_never_dispatches_or_accepts_automatic_proof(site):
    ctx=context(site); driver=RefusalDriver(ctx)
    result=api().run_case('physical-operator',driver,ctx,clock=lambda:1000)
    assert driver.calls==[] and result['status']=='NOT RUN'
    assert not any(a['passed'] for a in result['assertions'])
    assert set(a['name'] for a in result['assertions'])==set(api().required_assertions('physical-operator'))


def test_every_case_has_exact_required_assertions_even_after_driver_failure(site):
    class Unavailable(RefusalDriver):
        def execute_action(self,action,parameters): raise TimeoutError('external runtime unavailable')
    ctx=context(site)
    for case in ('offline-install','erase-refusals','port-mapping','wan-exposure','routed-policy',
                 'router-down-management','no-wan-boot','wan-return','interrupted-resume','export-repair'):
        result=api().run_case(case,Unavailable(ctx),ctx,clock=lambda:1000)
        names=[a['name'] for a in result['assertions']]
        assert len(names)==len(set(names)) and set(names)==set(api().required_assertions(case))
        assert not any(a['passed'] for a in result['assertions'])
        assert result['reasons']


def test_actual_function_receipt_is_accepted_without_invented_command_stdout():
    receipt={'returncode':0,'result':{'state':'staged','plan_id':'a'*64}}
    assert api()._success(receipt)
    assert api()._json_command(receipt)['state']=='staged'


@pytest.mark.parametrize('launched,expected', [(False, 'NOT RUN'), (True, 'FAIL')])
def test_launch_observation_controls_failure_classification(site, launched, expected):
    # Only tests classification: no successful record or machine evidence exists.
    class Boundary:
        synthetic = False
        def execute_action(self, *args): raise TimeoutError('unavailable')
    driver = Boundary(); driver.launched = launched
    result = api().run_case('offline-install', driver, context(site), clock=lambda: 1000)
    assert result['status'] == expected and result['evidence'] == []
    assert api()._refused({'returncode':2,'result':{'error':'non-target-storage-conflict'}},
                          {'non-target-storage-conflict'})


def test_boot_menu_has_exact_existing_runner_assertion_contract():
    # The old console case is supplementary, but still cannot get a pass from
    # one successful prompt when the cancellation/disk checks are missing.
    assert {'closed-grub-menu-observed','installer-menu-observed','blank-selection-keeps-menu',
            'explicit-recovery-console-observed','console-exit-returns-menu','target-unchanged','canary-unchanged',
            'readonly-inputs-unchanged'} <= set(api().required_assertions('boot-menu-cancel'))


def test_command_failure_and_tls_rejection_never_prove_firewall_denial():
    for error,connected in (('tls-rejected',True),('io-error',False),('timeout',True)):
        raw=network('fresh',denied=True); raw.update(error=error,connected=connected)
        assert not api().probe_result(raw,nonce='fresh',allowed=False)


def test_router_dns_accepts_actual_peer_A_response_for_current_name_only():
    from appliance.lab_probe import dns_request
    import socket
    query=dns_request('token',transaction=23)
    response=struct.pack('!6H',23,0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+socket.inet_aton('192.168.1.1')
    assert api().dns_result(query.hex(),response.hex(),name='token.lab.invalid',address='192.168.1.1')
    assert not api().dns_result(query.hex(),response.hex(),name='old.lab.invalid',address='192.168.1.1')
    assert not api().dns_result(query.hex(),response.hex(),name='token.lab.invalid',address='192.168.1.2')


def test_admin_probes_use_real_service_certificate_instead_of_echo_server():
    nonce='n'*32
    control={'nonce':nonce,'connected':True,'protocol':'https','certificate_valid':True,
             'certificate_sha256':'a'*64,'http_status':401,'error':None,'source':'10.77.0.3',
             'destination':'10.77.0.2','port':8006}
    raw={'nonce':nonce,'admin_checks':[{'target':'host','expected_certificate_sha256':'a'*64,
        'attempt':copy.deepcopy(control),'destination_control':copy.deepcopy(control),
        'source_control':network(nonce)['source_control']}]}
    assert api().admin_probe_result(raw,nonce=nonce,targets={'host'},allowed=True)
    raw['admin_checks'][0]['attempt']['certificate_sha256']='b'*64
    assert not api().admin_probe_result(raw,nonce=nonce,targets={'host'},allowed=True)
    attempt=raw['admin_checks'][0]['attempt'];attempt.update(connected=False,error='timeout')
    assert api().admin_probe_result(raw,nonce=nonce,targets={'host'},allowed=False)
    attempt.update(connected=True,error='tls-rejected')
    assert not api().admin_probe_result(raw,nonce=nonce,targets={'host'},allowed=False)


def test_actual_startup_records_prove_installed_root_and_real_menu_execution(site):
    ctx=context(site)
    raw={'root':command(json.dumps({'filesystems':[{'source':'/dev/mapper/pve-root','fstype':'ext4','target':'/'}]})),
        'cmdline':'quiet ipv6.disable=1','staged':{'complete':True,'plan_id':ctx['plan_id'],'build_id':ctx['build_id']},
        'session':{'euid':0,'tty':True},'menu':command('Two-port appliance\nChoose an action: {"state":"exited"}\n')}
    assert api()._disk_boot(raw,ctx) and api()._local_menu(raw)
    raw['cmdline']='rdc.appliance=1 ipv6.disable=1'
    assert not api()._disk_boot(raw,ctx)
    raw['session']['tty']=False
    assert not api()._local_menu(raw)


@pytest.mark.parametrize('case,needed',[
 ('offline-install',{('recover','install'),('reboot','host'),('fault','interrupt'),('recover','usb-management')}),
 ('port-mapping',{('fault','nic-order'),('fault','replace-nic'),('fault','wrong-cable'),('recover','management-rollback')}),
 ('wan-exposure',{('probe','host-wan-addresses'),('probe','wan-admin'),('probe','physical-dhcp-ra')}),
 ('routed-policy',{('probe','dns'),('probe','ntp'),('probe','https'),('probe','zone-admin'),('probe','cross-zone')}),
 ('router-down-management',{('fault','router-stop'),('probe','management'),('probe','https')}),
 ('no-wan-boot',{('fault','wan-remove'),('reboot','host'),('probe','dns'),('probe','ntp')}),
 ('wan-return',{('fault','wan-overlap-first'),('fault','wan-overlap-renew'),('probe','forwarding-state'),('recover','explicit-transit'),('reboot','router')}),
 ('interrupted-resume',{('fault','interrupt'),('observe','journal'),('recover','resume')}),
 ('export-repair',{('recover','export'),('recover','open-export'),('fault','wrong-export-password'),('fault','corrupt-export'),('recover','usb-management'),('recover','isolated-clone')}),
])
def test_every_scenario_executes_distinct_real_actions_and_missing_data_fails(case,needed,site):
    class MissingRaw(RefusalDriver):
        def execute_action(self,action,parameters):
            self.calls.append((action,parameters));self.sequence+=1
            return {'sequence':self.sequence,'checked_at':1000,'dependencies':{
                'plan':self.ctx['plan_id'],'build':self.ctx['build_id'],'spec':self.ctx['spec_id'],
                'source':self.ctx['source_id'],'run':self.ctx['run_id'],'host_boot':'new-boot',
                'router_boot':'new-router-boot'},'data':{},'evidence':[{'path':'/synthetic/trace','sha256':'a'*64}]}
    ctx=context(site);driver=MissingRaw(ctx);result=api().run_case(case,driver,ctx,clock=lambda:1000)
    assert needed <= {(action,params.get('kind',params.get('target'))) for action,params in driver.calls}
    assert not any(a['passed'] for a in result['assertions'] if a['name']!='fresh-observations')
    assert result['status']=='NOT RUN'


class FlowDriver:
    """External-machine substitution with actual documented receipt shapes."""
    synthetic=True
    def __init__(self,ctx):self.ctx=ctx;self.sequence=0;self.calls=[];self.boot=1
    def data(self,action,p):return {}
    def execute_action(self,action,parameters):
        self.calls.append((action,parameters));self.sequence+=1
        if action=='reboot':self.boot+=1
        return {'sequence':self.sequence,'checked_at':1000,'dependencies':{
            'plan':self.ctx['plan_id'],'build':self.ctx['build_id'],'spec':self.ctx['spec_id'],
            'source':self.ctx['source_id'],'run':self.ctx['run_id'],'host_boot':'boot-'+str(self.boot),
            'router_boot':'router-'+str(self.boot),'config':'f'*64,'policy':'a'*64},
            'data':self.data(action,parameters),'evidence':[{'path':'/synthetic/flow-'+str(self.sequence),'sha256':'a'*64}]}


def admin(nonce,targets=('host',),*,denied=False):
    checks=[]
    for target in targets:
        port,address=(8006,'10.77.0.2') if target=='host' else (443,'10.77.0.1')
        control={'nonce':nonce,'connected':True,'protocol':'https','certificate_valid':True,
            'certificate_sha256':'a'*64,'http_status':401,'error':None,'source':'10.77.0.3',
            'destination':address,'port':port}
        attempt=copy.deepcopy(control)
        if denied:attempt.update(connected=False,error='timeout')
        checks.append({'target':target,'expected_certificate_sha256':'a'*64,'attempt':attempt,
                       'destination_control':control,'source_control':command(nonce)})
    return {'nonce':nonce,'admin_checks':checks}


def service(nonce,kind):
    from appliance.lab_probe import dns_request
    import socket
    raw=network(nonce)
    if kind=='dns':
        query=dns_request(nonce,transaction=123)
        response=struct.pack('!6H',123,0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+socket.inet_aton('192.168.1.1')
        raw.update(query_hex=query.hex(),response_hex=response.hex(),expected_address='192.168.1.1')
    else:
        query=bytearray(48);query[0]=0x23;query[40:48]=__import__('hashlib').sha256(nonce.encode()).digest()[:8]
        response=bytearray(48);response[0]=0xe4;response[1]=16
        response[24:32]=query[40:48];response[40:48]=b'87654321'
        raw.update(query_hex=query.hex(),response_hex=response.hex())
    return raw


def test_routed_policy_passes_only_with_independent_controls_and_real_wire_replies(site):
    class Routed(FlowDriver):
        def data(self,action,p):
            if action=='prepare':return {'profile':'routed'}
            assert action=='probe'
            kind=p['kind'];nonce=p['nonce']
            if kind in ('dns','ntp'):return service(nonce,kind)
            if kind in ('management','zone-admin'):
                return admin(nonce,('host','router') if p['target']=='both' else (p['target'],),denied=kind=='zone-admin')
            return network(nonce,denied=kind=='cross-zone')
    ctx=context(site);result=api().run_case('routed-policy',Routed(ctx),ctx,clock=lambda:1000)
    assert all(a['passed'] for a in result['assertions'])
    assert result['status']=='NOT RUN'  # No mock can manufacture network qualification.
    class MissingControl(Routed):
        def data(self,action,p):
            raw=super().data(action,p)
            if p.get('kind')=='cross-zone':raw.pop('destination_control')
            return raw
    bad=api().run_case('routed-policy',MissingControl(ctx),ctx,clock=lambda:1000)
    assert len([a for a in bad['assertions'] if not a['passed']])==3


def test_export_repair_checks_actual_stopped_clone_receipt_and_original_identity(site):
    components={name:'a'*64 for name in ('site.json','release.lock.json','build.json','vms.json','router.xml','host.json')}
    class Repair(FlowDriver):
        def data(self,action,p):
            kind=p.get('kind')
            if action=='observe' and kind=='disks':return {'sha256':{'target':'1'*64,'canary':'2'*64}}
            if action=='observe' and kind=='router':return {'config_sha256':'b'*64,'identity_sha256':'c'*64,'vm':{'running':False}}
            if action=='observe' and kind=='clone':return {'running':False,'pid':None,'config':{'onboot':'0','boot':'order=scsi0',
                'net0':'virtio=02:bb:00:00:00:02,bridge=rdcr10101,firewall=1,link_down=1'}}
            if action=='probe':return admin(p['nonce'])
            result={}
            extra={}
            if kind in ('export','open-export'):
                extra={'credential_source':'independently-held','credential_sha256':'f'*64,'guest_credential_removed':True}
            if kind=='export':result={'state':'sealed','snapshot_id':'d'*64,'ciphertext_sha256':'e'*64,'restored_bytes':'verified'}
            elif kind=='open-export':
                result={'state':'inspected','files':list(components),'services':'not-started'}
                extra.update(component_sha256=components)
            elif kind in ('wrong-export-password','corrupt-export'):
                return {'returncode':2,'result':{'error':'export-command-failed' if kind=='wrong-export-password' else 'export-ciphertext-changed'}}
            elif kind=='usb-management':
                result={'state':'configured','network_activated':False}
                target={'target':site['target'],'root':{'filesystem_uuid':'fs-one','pv_uuid':'pv-one','lv_uuid':'lv-one'}}
                extra={'target_before':target,'target_after':copy.deepcopy(target)}
            elif kind=='isolated-clone':
                result={'state':'verified','clone_vmid':10101,'source_vmid':101,'clone_stopped':True,'activation':'forbidden',
                    'network':'isolated-bridge-all-links-down','bridge_removed':True,'proofs':[
                    {'stage':'import','root_kind':'recovery-media','config_sha256':'a'*64,'version':'26.7','hook_removed':False},
                    {'stage':'verify','root_kind':'installed-disk','config_sha256':'a'*64,'version':'26.7','hook_removed':True}]}
            return {'returncode':0,'result':result,**extra}
    ctx=context(site);result=api().run_case('export-repair',Repair(ctx),ctx,clock=lambda:1000)
    assert all(a['passed'] for a in result['assertions'])
    class Unstopped(Repair):
        def data(self,action,p):
            raw=super().data(action,p)
            if action=='observe' and p['kind']=='clone':raw['running']=True;raw['pid']=123
            return raw
    broken=api().run_case('export-repair',Unstopped(ctx),ctx,clock=lambda:1000)
    assert next(a for a in broken['assertions'] if a['name']=='clone-stopped')['passed'] is False


def test_boot_menu_uses_observed_serial_journey_and_full_disk_pins(site):
    class Boot(FlowDriver):
        def data(self,action,p):
            if p.get('kind')=='disks':return {'sha256':{'target':'1'*64,'canary':'2'*64},
                'readonly_inputs':{'installer':{'initial':'3'*64,'final':'3'*64},'target':{'initial':'4'*64,'final':'4'*64},
                    'canary':{'initial':'5'*64,'final':'5'*64},'uefi_code':{'initial':'6'*64,'final':'6'*64},
                    'uefi_vars':{'initial':'7'*64,'final':'7'*64}}}
            if p.get('kind')=='startup':return {'source_identity':self.ctx['source_id'],'serial_menu':
                'Appliance local setup (serial console)\nSelect (no default): \nNo action selected.\nSelect (no default): \n'
                'Local USB recovery console.\nUSB recovery (local root) # exit\nSelect (no default): \n'
                'USB recovery (local root) # '}
            return {}
    ctx=context(site);result=api().run_case('boot-menu-cancel',Boot(ctx),ctx,clock=lambda:1000)
    assert all(a['passed'] for a in result['assertions'])
    assert result['status']=='NOT RUN'


def test_empty_or_one_sided_physical_capture_never_proves_dhcp_ra_absence(site):
    assert api().physical_capture({'frames':[],'capture_seconds':12,'control_macs':['52:54:00:77:00:fe']},site)==(False,False)
    # Packet parser fixtures are covered with real wire layouts in lab_probe;
    # even a valid one-sided control must not qualify the other physical port.
    from appliance.lab_probe import parse_frames
    mac=bytes.fromhex('5254007700fe')
    ipv6=b'\x60\0\0\0\0\x10\x3a\xff'+b'\xfe\x80'+b'\0'*14+b'\xff\x02'+b'\0'*13+b'\x01'
    ra=b'\xff'*6+mac+b'\x86\xdd'+ipv6+b'\x86'+b'\0'*15
    raw={'frames':[{'time':1000,'zone':'wan','hex':ra.hex()}],'capture_seconds':12,'control_macs':['52:54:00:77:00:fe']}
    assert api().physical_capture(raw,site)==(False,False)


def test_retained_usb_needs_real_live_root_and_handles_malformed_findmnt():
    raw={'serial_menu':'Select (no default): No action selected.', 'cmdline':'rdc.appliance=1',
         'root':command(json.dumps({'filesystems':[{'source':'overlay','fstype':'overlay','target':'/'}]}))}
    assert api()._usb_boot(raw)
    for filesystems in ([],None,[None],[{'fstype':'ext4','target':'/'}]):
        raw['root']=command(json.dumps({'filesystems':filesystems}))
        assert not api()._usb_boot(raw)


def test_failed_first_boot_requires_actual_wan_link_and_real_ssh_unit(site):
    raw={'services':command('Id=rdc-first-boot.service\nExecMainStatus=1\nActiveState=failed\n\n'
         'Id=ssh.service\nActiveState=inactive\n\nId=pveproxy.service\nActiveState=inactive'),
         'interfaces':{'links':[{'ifname':'enp2s0','address':site['ports']['wan']['permanent_mac'],'flags':['BROADCAST','MULTICAST']}]}}
    assert api()._firstboot_closed(raw,site)
    raw['interfaces']['links'][0]['flags'].append('UP')
    assert not api()._firstboot_closed(raw,site)
    raw['interfaces']['links']=[]
    assert not api()._firstboot_closed(raw,site)


def test_network_receipts_follow_observed_phase_and_transaction():
    tx='a'*48
    direct={'returncode':0,'result':{'phase':'rolled-back','transaction_id':tx,'elapsed_seconds':120}}
    assert api()._pending(direct)['phase']=='rolled-back'
    confirm={'returncode':0,'result':{'phase':'confirmed','transaction_id':tx}}
    journal={'records':{'network/pending.json':{'phase':'confirmed','transaction_id':tx}}}
    assert api()._network_confirmed(confirm,journal)
    journal['records']['network/pending.json']['transaction_id']='b'*48
    assert not api()._network_confirmed(confirm,journal)
    assert api()._pending({'phase':'rolled-back'})=={}


def test_wrong_cable_requires_failed_ssh_and_unconfirmed_transaction():
    raw={'returncode':2,'result':{'error':'management-session-required','phase':'pending',
         'ssh':{'returncode':255,'stderr':'connect timeout'}}}
    assert api()._wrong_cable_refused(raw)
    for update in ({'phase':'confirmed'},{'ssh':{'returncode':0}},{'error':'lab-action-failed'}):
        bad=copy.deepcopy(raw);bad['result'].update(update)
        assert not api()._wrong_cable_refused(bad)


def test_export_credential_custody_requires_matched_digest_and_guest_deletion():
    raw={'credential_source':'independently-held','credential_sha256':'b'*64,'guest_credential_removed':True}
    assert api()._independent_credential(raw,raw)
    for update in ({'credential_sha256':'c'*64},{'guest_credential_removed':False},{'credential_source':'guest-local'}):
        assert not api()._independent_credential(raw,{**raw,**update})
    assert not api()._independent_credential({'credential_source':'independently-held'},raw)


def test_each_interruption_starts_with_fresh_live_disk_before_later_setup(site):
    ctx=context(site);driver=FlowDriver(ctx)
    api().run_case('interrupted-resume',driver,ctx,clock=lambda:1000)
    groups=[];previous=0
    for index,(action,p) in enumerate(driver.calls):
        if action=='fault' and p.get('kind')=='interrupt':
            prepares=[q['profile'] for a,q in driver.calls[previous:index] if a=='prepare']
            groups.append((p['stage'],prepares));previous=index+1
    assert groups==[(stage,['live'] if stage=='install-staging' else ['live','routed']) for stage in api().INTERRUPTIONS]


def test_renamed_ports_use_explicit_usb_repair_before_fresh_management_confirmation(site):
    ctx=context(site);driver=FlowDriver(ctx)
    api().run_case('port-mapping',driver,ctx,clock=lambda:1000)
    before_cable=driver.calls[:next(i for i,(a,p) in enumerate(driver.calls) if a=='fault' and p.get('kind')=='replace-nic')]
    actions=[(a,p.get('kind',p.get('profile',p.get('target'))),p.get('usb')) for a,p in before_cable]
    expected=[('prepare','routed',None),('observe','host',None),('recover','export',None),('recover','open-export',None),
        ('fault','nic-order',None),('reboot','host','absent'),('observe','startup',None),
        ('reboot','host','present'),('recover','usb-management',None),('reboot','host','absent'),
        ('recover','management-rollback',None),('observe','host',None),('observe','journal',None)]
    assert actions[:len(expected)]==expected


def test_invalid_media_refusal_matches_actual_release_schema_verifier(site,release):
    from appliance.plan import validate_release
    from appliance.contracts import ApplianceError
    with pytest.raises(ApplianceError) as error:
        validate_release({**release,'schema':0},production=True)
    class InvalidMedia(RefusalDriver):
        def execute_action(self,action,parameters):
            raw=super().execute_action(action,parameters)
            if action=='fault' and self.variant=='invalid-media':
                raw['data']=command(json.dumps({'error':error.value.code}),2)
            return raw
    ctx=context(site);result=api().run_case('erase-refusals',InvalidMedia(ctx),ctx,clock=lambda:1000)
    assert next(a for a in result['assertions'] if a['name']=='invalid-media-refused')['passed']

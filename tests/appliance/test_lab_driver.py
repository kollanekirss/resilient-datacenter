"""Pure/protocol tests do not constitute disposable guest observations."""
import base64
import importlib
import json
import struct
import pytest
from appliance.contracts import ApplianceError


def api():
    return importlib.import_module('appliance.lab_driver')


def test_guest_frame_is_nonce_bound_bounded_and_not_shell_code():
    module=api()
    request=module.encode_request('observe', {'kind':'host'}, sequence=3, token='a'*64, machine='b'*36)
    assert b';' not in request and request.endswith(b'\n')
    value=json.loads(base64.b64decode(request))
    assert value['sequence']==3 and value['token']=='a'*64
    with pytest.raises(ApplianceError):
        module.encode_request('shell', {'command':'echo fake'}, sequence=1,token='a'*64,machine='b'*36)


def test_namespace_identity_must_change_before_any_tap_operation():
    module=api()
    with pytest.raises(ApplianceError,match='lab-network-namespace-required'):
        module.verify_namespace('net:[1]','net:[1]', {'lo'})
    with pytest.raises(ApplianceError,match='lab-namespace-not-empty'):
        module.verify_namespace('net:[1]','net:[2]', {'lo','eth0'})
    module.verify_namespace('net:[1]','net:[2]', {'lo'})


def test_dhcp_reply_preserves_transaction_and_declares_dns_time_and_lease():
    module=api()
    packet=bytearray(240)
    packet[0:4]=bytes([1,1,6,0]);packet[4:8]=bytes.fromhex('10203040')
    packet[28:34]=bytes.fromhex('525400770002')
    packet[236:240]=bytes.fromhex('63825363')
    packet.extend(b'\x35\x01\x01\xff')
    response=module.dhcp_reply(bytes(packet),'198.18.0.2','198.18.0.1',24,30)
    assert response[0]==2 and response[4:8]==packet[4:8]
    assert response[16:20]==bytes([198,18,0,2])
    assert b'\x35\x01\x02' in response
    assert b'\x33\x04'+struct.pack('!I',30) in response
    assert b'\x06\x04'+bytes([198,18,0,1]) in response
    assert b'\x2a\x04'+bytes([198,18,0,1]) in response
    assert module.dhcp_reply(b'bad','198.18.0.2','198.18.0.1',24,30) is None


def test_ntp_response_matches_originate_and_dns_response_matches_question():
    module=api()
    request=b'\x23'+b'\0'*39+bytes.fromhex('e987654300000001')
    answer=module.ntp_reply(request,1770000000)
    assert len(answer)==48 and answer[24:32]==request[40:48] and answer[0]&7==4
    query=bytes.fromhex('aabb01000001000000000000')+b'\x03lab\x07invalid\0\0\x01\0\x01'
    dns=module.dns_reply(query,'198.18.0.1')
    assert dns[:2]==query[:2] and dns[12:12+len(query)-12]==query[12:]
    assert dns.endswith(bytes([198,18,0,1]))
    assert module.dns_reply(query[:-2],'198.18.0.1') is None


def test_serial_response_requires_current_request_not_old_echo():
    module=api()
    expected={'schema':1,'sequence':2,'token':'a'*64,'data':{'value':4}}
    raw=b'noise\nRDC-LAB-RESULT '+base64.b64encode(json.dumps(expected).encode())+b'\n'
    assert module.decode_response(raw,sequence=2,token='a'*64)['data']=={'value':4}
    with pytest.raises(ApplianceError): module.decode_response(raw,sequence=3,token='a'*64)
    with pytest.raises(ApplianceError): module.decode_response(raw,sequence=2,token='b'*64)


def test_guest_guard_refuses_missing_machine_and_real_machine_serial(tmp_path):
    guest=importlib.import_module('appliance.lab_guest')
    with pytest.raises(ApplianceError):guest.verify_guest('a'*36,root=tmp_path)
    (tmp_path/'sys/class/dmi/id').mkdir(parents=True)
    (tmp_path/'sys/class/dmi/id/product_uuid').write_text('a'*36)
    (tmp_path/'sys/class/dmi/id/product_name').write_text('production-server')
    with pytest.raises(ApplianceError):guest.verify_guest('a'*36,root=tmp_path)


def test_guest_actions_reject_arbitrary_command_and_path_before_mutation():
    guest=importlib.import_module('appliance.lab_guest')
    with pytest.raises(ApplianceError):guest.validate_action('command',{'argv':['rm','-rf','/']})
    with pytest.raises(ApplianceError):guest.validate_action('fault',{'kind':'erase-refusal','variant':'arbitrary'})
    guest.validate_action('observe',{'kind':'host'})


def test_full_qemu_argv_uses_only_private_tap_fds_and_copies():
    module=api();handles={name:i+20 for i,name in enumerate(('uefi_code','uefi_vars_copy','installer','target_copy','canary_copy','management_tap','wan_tap'))}
    args=module.full_qemu_arguments('/qemu',handles,{'memory_mib':16384,'vcpus':4},machine='a'*36,qmp='/private/run/qmp.sock',boot='installer',variant='normal')
    assert not any('script=' in x and 'script=no' not in x for x in args)
    assert 'tap,id=management,fd=25,script=no,downscript=no' in args
    assert not any(x.startswith(('user,','bridge,','socket,')) for x in args)
    assert '-no-reboot' not in args and '-uuid' in args


def test_raw_network_error_cannot_turn_into_success_or_nonce_proof():
    module=api()
    raw={'nonce':'a'*32,'connected':True,'error':'tls-rejected','response_nonce':None,'protocol':'https','certificate_valid':False}
    result=module.probe_report(raw)
    assert result['attempt']['returncode']!=0 and result['attempt']['stdout']==''
    assert result['connected'] is True and result['tls']['verify_returncode']!=0


def test_source_control_runs_a_real_listener_and_bad_destination_stays_failed():
    from appliance.lab_probe import probe_network
    from appliance.lab_probe_guest import CONTROL_PROGRAM
    import socket
    with socket.socket() as held:
        held.bind(('127.0.0.1',0))
        namespace={'probe_network':probe_network,'kind':'http','args':{'host':'127.0.0.1','port':held.getsockname()[1],'nonce':'a'*32,'timeout_s':1}}
        exec(CONTROL_PROGRAM,namespace)
    result=namespace['result']
    assert result['source_control']['response_nonce']=='a'*32
    assert result['source_control']['connected'] is True and result['error'] in ('connection-refused','timeout')


def test_guest_nonzero_command_observation_retains_actual_code_and_stdout():
    from appliance.lab_guest import _run
    import sys
    result=_run([sys.executable,'-c','import sys;print("actual-output");sys.exit(13)'],check=False)
    assert result['returncode']==13 and result['stdout']=='actual-output\n'


def test_actual_pty_receives_frame_larger_than_canonical_terminal_limit():
    import os,pty,subprocess,sys
    master,slave=pty.openpty()
    program="from appliance.lab_guest import configure_protocol_terminal;import sys;configure_protocol_terminal(0);print('ready',flush=True);print(len(sys.stdin.buffer.readline()),flush=True)"
    child=subprocess.Popen([sys.executable,'-c',program],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.close(slave)
    try:
        assert child.stdout.readline()==b'ready\n'
        frame=b'x'*16384+b'\n';offset=0
        while offset<len(frame):offset+=os.write(master,frame[offset:offset+512])
        output,error=child.communicate(timeout=5)
        assert child.returncode==0 and output==b'16385\n' and error==b''
    finally:
        os.close(master)
        if child.poll() is None:child.kill();child.wait()


def test_command_evidence_never_reembeds_redacted_secrets_in_stdout():
    driver=api().DisposableDriver.__new__(api().DisposableDriver)
    data=driver._command({'result':{'password':'sensitive-value','config_xml':'private-content','visible':'okay'}})
    assert 'sensitive-value' not in json.dumps(data) and 'private-content' not in json.dumps(data)
    assert data['result']['visible']=='okay'


def test_renewal_keeps_dhcp_server_identity_when_offering_conflicting_subnet():
    import socket
    packet=bytearray(240);packet[:4]=bytes((1,1,6,0));packet[236:240]=bytes.fromhex('63825363')
    packet.extend(b'\x35\x01\x03\x36\x04'+socket.inet_aton('198.18.0.1')+b'\xff')
    response=api().dhcp_reply(bytes(packet),'10.77.3.20','10.77.3.1',24,30,server='198.18.0.1')
    assert response[16:20]==socket.inet_aton('10.77.3.20')
    assert b'\x36\x04'+socket.inet_aton('198.18.0.1') in response


def test_export_credential_exists_only_during_one_guest_operation(tmp_path,monkeypatch):
    from appliance import lab_guest
    private=tmp_path/'private';private.mkdir();(tmp_path/'lab').mkdir()
    monkeypatch.setattr(lab_guest,'PRIVATE',private)
    raw='a'*56+'\n'
    with lab_guest.export_credential({'export_credential':raw}) as (path,digest):
        assert path.read_text()==raw and digest==__import__('hashlib').sha256(raw.encode()).hexdigest()
    assert not path.exists()
    with pytest.raises(RuntimeError):
        with lab_guest.export_credential({'export_credential':raw}) as (path,_):raise RuntimeError('cut')
    assert not path.exists()


def test_router_reboot_compares_identity_from_before_dispatch(tmp_path,monkeypatch):
    module=api();driver=module.DisposableDriver.__new__(module.DisposableDriver)
    driver.sequence=0;driver.lastdeps={'host_boot':'host','router_boot':'old'};driver.run=tmp_path
    driver.context={name:name for name in ('plan_id','build_id','spec_id','source_id','run_id')}
    calls=[]
    def request(action,parameters):
        calls.append(action);driver.lastdeps['router_boot']='new';return {'returncode':0}
    driver._request=request
    result=driver.execute_action('reboot',{'target':'router'})
    assert calls==['reboot'] and result['dependencies']['router_boot']=='new'


def test_worker_records_actual_launch_event_before_action_failure():
    worker=api().NamespaceWorker.__new__(api().NamespaceWorker);worker.launched=False
    worker.buffer=bytearray(b'{"event":"qemu-started"}\n{"error":"lab-console-observation-timeout"}\n')
    with pytest.raises(ApplianceError,match='lab-console-observation-timeout'):worker._read(5)
    assert worker.launched is True


def test_case_deadline_expires_before_sending_next_action():
    import time
    worker=api().NamespaceWorker.__new__(api().NamespaceWorker);worker.closed=False;worker.deadline=time.monotonic()-1
    with pytest.raises(ApplianceError,match='lab-case-timeout'):worker.execute_action('observe',{'kind':'host'})


def test_installed_inventory_does_not_require_installer_iso(monkeypatch):
    from appliance import lab_guest
    from pathlib import Path
    monkeypatch.setattr(lab_guest,'live_mode',lambda:False)
    monkeypatch.setattr(Path,'read_text',lambda *a,**k:'actual-kernel-boot-id')
    monkeypatch.setattr(lab_guest,'_run',lambda argv:{'stdout':'{"blockdevices":[{"path":"/dev/sda"}]}'})
    observed=lab_guest.inventory()
    assert observed['mode']=='installed' and observed['blockdevices']==[{'path':'/dev/sda'}]

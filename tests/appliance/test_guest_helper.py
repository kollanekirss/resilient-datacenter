import json
from pathlib import Path
import pytest
from appliance.contracts import ApplianceError, identity
from appliance import state as records
from appliance.guest import helper, state as guest_state


@pytest.fixture(autouse=True)
def synthetic_boot(monkeypatch):
    monkeypatch.setattr(helper,'_boot_id',lambda:'11111111-1111-1111-1111-111111111111')
    monkeypatch.setattr(helper,'_preflight',lambda *args:None)


def request(action='configure', **parameters):
    return {'schema':1,'operation_id':'operation-1','plan_id':'a'*64,'role':'connector','action':action,'parameters':parameters}


def binding(tmp_path, role='connector'):
    guest_state.initialize(tmp_path, {'schema':1,'plan_id':'a'*64,'role':role,'vmid':103}, '1'*32)


def test_arbitrary_guest_action_is_rejected(tmp_path):
    with pytest.raises(ApplianceError,match='unsupported-guest-action'):
        helper.dispatch(request('shell'),tmp_path)


def test_guest_cannot_change_its_role_or_plan(tmp_path):
    binding(tmp_path)
    for change in ({'role':'headscale'},{'plan_id':'b'*64}):
        with pytest.raises(ApplianceError,match='guest-binding'):
            helper.dispatch(dict(request(),**change),tmp_path)


def test_guest_completed_operation_is_read_back_without_replay(tmp_path,monkeypatch):
    binding(tmp_path);calls=[]
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:calls.append(req) or {'configured':True})
    req=request(authorization='synthetic-private-key')
    first=helper.dispatch(req,tmp_path)
    assert first['phase']=='complete' and first['observations']=={'configured':True,'machine_id':'1'*32,'boot_id':'11111111-1111-1111-1111-111111111111'}
    assert helper.dispatch(req,tmp_path)==first and len(calls)==1
    assert 'synthetic-private-key' not in ''.join(p.read_text() for p in tmp_path.rglob('*.json'))
    with pytest.raises(ApplianceError,match='guest-operation-reused'):
        helper.dispatch(request(authorization='different-secret'),tmp_path)


def test_lost_mutation_outcome_stays_pending_and_never_replays(tmp_path,monkeypatch):
    binding(tmp_path); calls=[]
    def crash(req,state,runner):
        calls.append(req); raise RuntimeError('secret text must not escape')
    monkeypatch.setattr(helper,'_handler',lambda role,action:crash)
    with pytest.raises(ApplianceError,match='guest-operation-interrupted'):
        helper.dispatch(request(),tmp_path)
    assert helper.dispatch(request(),tmp_path)['phase']=='pending'
    query=request('inspect',query_operation=True)
    assert helper.dispatch(query,tmp_path)['phase']=='pending' and len(calls)==1


def test_guest_reply_rejects_secret_fields_and_values(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:{'authorization':req['parameters']['authorization']})
    with pytest.raises(ApplianceError,match='guest-reply-private'):
        helper.dispatch(request(authorization='synthetic-private-key'),tmp_path)
    assert 'synthetic-private-key' not in ''.join(p.read_text() for p in tmp_path.rglob('*.json'))


def test_machine_identity_and_authority_are_immutable(tmp_path):
    binding(tmp_path)
    with pytest.raises(ApplianceError,match='guest-machine-identity-changed'):
        guest_state.initialize(tmp_path, {'schema':1,'plan_id':'a'*64,'role':'connector','vmid':103}, '2'*32)
    guest_state.bind_authority(tmp_path,'connector',{'controller':'https://one.example'})
    guest_state.bind_authority(tmp_path,'connector',{'controller':'https://one.example'})
    with pytest.raises(ApplianceError,match='guest-authority-change'):
        guest_state.bind_authority(tmp_path,'connector',{'controller':'https://two.example'})


def test_oversized_and_duplicate_key_request_rejected():
    with pytest.raises(ApplianceError,match='guest-request-too-large'):
        helper.decode_request(b' '* (512*1024+1))
    with pytest.raises(ApplianceError):helper.decode_request(b'{"schema":1,"schema":1}')


def test_binding_machine_identity_is_added_to_every_reply(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:{'configured':True})
    reply=helper.dispatch(request(),tmp_path)
    assert reply['observations']['machine_id']=='1'*32


def test_pending_operation_blocks_different_mutation(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:(_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(ApplianceError):helper.dispatch(request(),tmp_path)
    with pytest.raises(ApplianceError,match='guest-operation-needs-inspection'):
        helper.dispatch(dict(request(),operation_id='operation-2'),tmp_path)


def test_snapshot_wrapping_preserves_private_data_only_in_read_reply(tmp_path,monkeypatch):
    binding(tmp_path)
    def snapshot(req,state,runner):
        if req['action']=='snapshot':return {'operation_id':req['operation_id'],'role':'connector','phase':'complete','snapshot':{'snapshot_id':'snap'}}
        return {'snapshot_id':'snap','relative_path':'key','chunk_base64':'c2VjcmV0','offset':0,'length':6,'digest':'c'*64}
    monkeypatch.setattr(helper,'_handler',lambda role,action:snapshot)
    capture=helper.dispatch(request('snapshot'),tmp_path)
    assert capture['observations']['snapshot']['snapshot_id']=='snap'
    read=helper.dispatch(dict(request('snapshot-read'),operation_id='read-1'),tmp_path)
    assert read['chunk_base64']=='c2VjcmV0' and 'chunk_base64' not in read['observations']
    assert 'c2VjcmV0' not in (tmp_path/'operations/read-1.json').read_text()


def test_runtime_inspection_uses_fixed_read_only_commands(tmp_path):
    from subprocess import CompletedProcess
    binding(tmp_path);records.write(tmp_path/'image.json',{'schema':1,'recipe_id':'b'*64,'versions':{'tailscale':'1.104.1'}})
    class Runtime:
        def run(self,argv,**kw):
            if argv[0]=='/usr/bin/cat':out='0\n' if argv[1].endswith('ip_forward') else '1\n'
            elif argv[0]=='/usr/sbin/ip':out=json.dumps([{'ifname':'role0','address':'02:bb:00:00:00:06','addr_info':[{'family':'inet','local':'10.77.1.10','prefixlen':24}]}] if 'address' in argv else [{'dst':'default','gateway':'10.77.1.1','dev':'role0'}])
            else:out='ActiveState=inactive\nUnitFileState=masked\n\nActiveState=inactive\nUnitFileState=masked\n'
            return CompletedProcess(argv,0,out.encode(),b'')
    reply=helper.dispatch(request('inspect',runtime=True),tmp_path,Runtime())
    assert reply['observations']['runtime']['forwarding'] is False
    assert reply['observations']['runtime']['ssh_masked'] is True
    assert reply['observations']['runtime']['image']['recipe_id']=='b'*64


def test_enrollment_reconciles_only_after_observed_original_identity(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:(_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(ApplianceError):helper.dispatch(request('enroll'),tmp_path)
    result=helper.reconcile_enrollment('operation-1',tmp_path,{'node_id':'node-1','controller':'https://one.example','registered':True})
    assert result['phase']=='complete' and helper.query_operation('operation-1',tmp_path)==result
    with pytest.raises(ApplianceError):helper.reconcile_enrollment('operation-1',tmp_path,{'node_id':'node-2','registered':True})


def test_fresh_reply_contains_current_boot_identity(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_boot_id',lambda:'12345678-1234-1234-1234-123456789abc')
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:{'configured':True})
    reply=helper.dispatch(request(),tmp_path)
    assert reply['observations']['boot_id']=='12345678-1234-1234-1234-123456789abc'


def test_preflight_failure_leaves_no_pending_journal(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_preflight',lambda *args:(_ for _ in ()).throw(ApplianceError('invalid-test-tls')))
    with pytest.raises(ApplianceError,match='invalid-test-tls'):helper.dispatch(request(),tmp_path)
    assert not (tmp_path/'operations/operation-1.json').exists()


def _connector_runtime(monkeypatch, *, lose=False):
    from appliance.guest import connector as handler
    from appliance import connector
    from subprocess import CompletedProcess
    monkeypatch.setattr(handler,'verify_controller',lambda *args:None)
    monkeypatch.setattr(connector.time,'time',lambda:1000)
    config={'controller':'https://control.example.org','advertise_routes':[],'advertise_exit_node':False,
            'accept_routes':False,'exit_node':'','tailscale_ssh':False,'accept_dns':False,'ip_forward':False}
    approval={'controller':config['controller'],'tls_sha256':'a'*64,'approved':True,'owner_reference':'owner-17',
              'node_name':'pilot','expires_at':1100,'one_use':True,'credential':'one-use-private-key'}
    class Client:
        def __init__(self):self.enrollments=0
        def run(self,argv,**kw):
            if argv[1]=='up':
                self.enrollments+=1
                if lose:raise ApplianceError('command-timeout')
            if argv[1:3]==['status','--json']:out={'BackendState':'Running','Self':{'ID':'node-1'}}
            elif argv[1:3]==['debug','prefs']:out={'ControlURL':config['controller'],'RouteAll':False,'CorpDNS':False,'RunSSH':False,'AdvertiseRoutes':[],'AdvertiseTags':[],'ExitNodeID':'','ExitNodeIP':''}
            elif argv[0].endswith('/sysctl'):return CompletedProcess(argv,0,b'0\n',b'')
            elif argv[0].endswith('/ip'):out=[{'dst':'100.64.0.2','dev':'tailscale0'}]
            else:return CompletedProcess(argv,0,b'',b'')
            return CompletedProcess(argv,0,json.dumps(out).encode(),b'')
    return config,approval,Client()


def test_readonly_inspect_before_enrollment_does_not_poison_dispatch(tmp_path,monkeypatch):
    binding(tmp_path);config,approval,runner=_connector_runtime(monkeypatch)
    with pytest.raises(ApplianceError,match='connector-not-enrolled'):
        helper.dispatch(request('verify',config=config),tmp_path,runner)
    enroll=dict(request('enroll',config=config,authorization=approval),operation_id='enroll-2')
    assert helper.dispatch(enroll,tmp_path,runner)['observations']['registered'] is True
    assert runner.enrollments==1


def test_readonly_verification_can_reconcile_uncertain_enrollment(tmp_path,monkeypatch):
    binding(tmp_path);config,approval,runner=_connector_runtime(monkeypatch,lose=True)
    enroll=request('enroll',config=config,authorization=approval)
    with pytest.raises(ApplianceError,match='command-timeout'):helper.dispatch(enroll,tmp_path,runner)
    verify=dict(request('verify',config=config),operation_id='observe-2')
    assert helper.dispatch(verify,tmp_path,runner)['observations']['registered'] is True
    assert helper.query_operation(enroll['operation_id'],tmp_path)['phase']=='complete'
    assert runner.enrollments==1


def test_hosted_reconnection_remains_a_journaled_mutation():
    assert helper._mutates(dict(request('verify',reconnect=True),role='headscale'))
    assert not helper._mutates(request('verify',config={}))


def test_cleanup_journal_retains_only_validated_snapshot_reference(tmp_path,monkeypatch):
    binding(tmp_path)
    monkeypatch.setattr(helper,'_handler',lambda role,action:lambda req,state,runner:{'cleaned':True})
    helper.dispatch(request('snapshot-cleanup',snapshot_id='capture-1'),tmp_path)
    record=records.read(tmp_path/'operations/operation-1.json')
    assert record['snapshot_id']=='capture-1' and record['mutating'] is True
    with pytest.raises(ApplianceError):
        helper.dispatch(dict(request('snapshot-cleanup',snapshot_id='../capture'),operation_id='bad'),tmp_path)
    assert not (tmp_path/'operations/bad.json').exists()

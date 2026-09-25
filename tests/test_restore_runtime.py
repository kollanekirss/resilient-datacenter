import importlib
import json
import subprocess
from pathlib import Path
import pytest


def api(): return importlib.import_module('restore_runtime')


def test_guard_blocks_pending_restore_after_reboot(tmp_path):
    m=api();pending=tmp_path/'pending';permit=tmp_path/'permit';guard=tmp_path/'guard'
    guard.write_text(m.guard_script(pending,permit));guard.chmod(0o700)
    assert subprocess.run([str(guard)]).returncode==0
    pending.write_text('{}')
    assert subprocess.run([str(guard)]).returncode!=0
    permit.touch()
    assert subprocess.run([str(guard)]).returncode==0
    permit.unlink()
    assert subprocess.run([str(guard)]).returncode!=0


def test_isolation_rejects_foreign_table_and_changed_rules():
    m=api();identifier='a'*32
    original={'nftables':[{'metainfo':{}},{'table':{'family':'inet','name':'rdc_restore','handle':1,'comment':'rdc-restore:'+identifier}}, {'chain':{'family':'inet','table':'rdc_restore','name':'input','handle':2}}]}
    digest=m.rules_digest(original,identifier)
    renumbered=json.loads(json.dumps(original));renumbered['nftables'][1]['table']['handle']=44
    assert m.rules_digest(renumbered,identifier)==digest
    changed=json.loads(json.dumps(original));changed['nftables'][2]['chain']['name']='forward'
    assert m.rules_digest(changed,identifier)!=digest
    with pytest.raises(ValueError): m.rules_digest(original,'b'*32)


def test_rule_generation_uses_fixed_role_ports_and_overlay_interface():
    m=api();identifier='a'*32
    for role in ('controller','relay','peer'):
        text=m.isolation_rules(role,identifier)
        assert 'flush' not in text and 'rdc-restore:'+identifier in text
    assert 'tcp dport 443 drop' in m.isolation_rules('controller',identifier)
    assert 'udp dport 3478 drop' in m.isolation_rules('relay',identifier)
    assert 'iifname "tailscale0" drop' in m.isolation_rules('peer',identifier)
    with pytest.raises(ValueError): m.isolation_rules('unknown',identifier)


def test_matrix_restore_clears_one_time_keys_only_while_chat_is_stopped(monkeypatch):
    import service_runtime
    m=api();owner={'applications':{'packages':['matrix']}}
    runtime=m.Runtime(owner);calls=[]
    monkeypatch.setattr(runtime,'is_active',lambda _:False)
    monkeypatch.setattr(service_runtime,'read_settings',lambda:{'ownership':owner['applications']})
    monkeypatch.setattr(service_runtime,'ready',lambda *args,**kwargs:calls.append(('ready',args[0])))
    monkeypatch.setattr(service_runtime,'podman',lambda *args,**kwargs:calls.append(('sql',args)))
    runtime.prepare_restored_application(owner)
    assert calls[0]==('ready','postgres')
    assert calls[1][1][-1]=='TRUNCATE TABLE e2e_one_time_keys_json;'
    assert 'ON_ERROR_STOP=1' in calls[1][1]
    calls.clear();monkeypatch.setattr(runtime,'is_active',lambda _:True)
    with pytest.raises(ValueError):runtime.prepare_restored_application(owner)
    assert calls==[]


def test_restored_database_cleanup_failure_prevents_synapse_start():
    import restore_transaction as transaction
    events=[]
    class Runtime:
        def start(self,name):events.append(name)
        def prepare_restored_application(self,owner):events.append('cleanup');raise ValueError('database unavailable')
    with pytest.raises(ValueError):transaction.start_candidate(('rdc-service-proxy','rdc-element','rdc-synapse','rdc-postgres','tailscaled'),Runtime(),{})
    assert events==['tailscaled','rdc-postgres','cleanup']


def test_upgrade_marker_also_blocks_automatic_startup(tmp_path):
    m=api();pending=tmp_path/'restore';permit=tmp_path/'permit';upgrade=tmp_path/'upgrade';guard=tmp_path/'guard'
    guard.write_text(m.guard_script(pending,permit,upgrade=upgrade));guard.chmod(0o700)
    upgrade.write_text('{}')
    assert subprocess.run([str(guard)],capture_output=True).returncode!=0
    permit.touch()
    assert subprocess.run([str(guard)],capture_output=True).returncode==0


def test_peer_recovery_closes_application_ingress_on_every_non_loopback_interface():
    rules=api().isolation_rules('peer','d'*32)
    assert 'tcp dport { 443, 8443, 3128 } drop' in rules
    assert rules.index('iifname "lo" accept')<rules.index('tcp dport { 443, 8443, 3128 } drop')

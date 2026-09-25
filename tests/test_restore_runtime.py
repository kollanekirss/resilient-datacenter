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

import importlib
from pathlib import Path
import pytest
from test_setup_contracts import ROOT, manifest, setup_api

def checks():
    assert (ROOT/'scripts/local_checks.py').exists(),'Local checks not implemented'
    return importlib.import_module('local_checks')

def node():
    assert (ROOT/'scripts/local_node.py').exists(),'Local dispatcher not implemented'
    return importlib.import_module('local_node')

def test_platform_blocks_mac_and_accepts_supported_linux():
    assert checks().platform_errors('Darwin','arm64',{},False)
    assert checks().platform_errors('Linux','x86_64',{'ID':'ubuntu','VERSION_ID':'24.04'},True)==[]

@pytest.mark.parametrize('actual,existing,persistent,active',[(None,True,False,False),({},True,True,False),(None,False,True,False)])
def test_unowned_or_inaccessible_identity_rejected(actual,existing,persistent,active):
    assert checks().ownership_errors(setup_api().local_ownership(manifest()),actual,existing,persistent,active)

def test_exact_ownership_is_required_even_if_daemon_stopped():
    e=setup_api().local_ownership(manifest()); a=dict(e,controller_hostname='other.test')
    assert checks().ownership_errors(e,a,True,True,False)
    assert checks().ownership_errors(e,e,True,True,False)
    assert checks().ownership_errors(e,e,True,True,True)==[]

def test_local_launcher_has_fixed_target_and_no_imported_inventory():
    command=node().install_command(Path('/tmp/manifest.yml'),as_root=True)
    assert '-i' in command and command[command.index('-i')+1]=='localhost,'
    assert any(x.endswith('playbooks/local-node.yml') for x in command)
    assert '--extra-vars' in command
    assert '--ask-become-pass' not in command

def test_invalid_manifest_never_invokes_installer():
    called=[]
    with pytest.raises(ValueError): node().apply_manifest({'kind':'bad'},Path('/tmp/manifest.yml'),runner=lambda *a,**k:called.append(a),checker=lambda m:[])
    assert called==[]

def test_platform_failure_never_invokes_installer():
    called=[]
    with pytest.raises(ValueError): node().apply_manifest(manifest(),Path('/tmp/manifest.yml'),runner=lambda *a,**k:called.append(a),checker=lambda m:['Unsupported platform'])
    assert called==[]

def test_local_playbook_installs_client_only():
    import yaml
    p=ROOT/'playbooks/local-node.yml'; assert p.exists()
    plays=yaml.safe_load(p.read_text())
    assert all(p['hosts']=='localhost' and p['connection']=='local' for p in plays)
    assert [p.get('roles') for p in plays if 'roles' in p]==[['client']]


def test_unowned_client_daemon_path_is_reserved():
    assert '/usr/local/sbin/tailscaled' in checks().RESERVED

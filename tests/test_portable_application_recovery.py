import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_portable_application_runtime import inputs
from application_access import portable_owner
from backup_scope import include


def owners(role='chat'):
    p=inputs()[role];network=portable_owner(p)
    m=importlib.import_module('service_contracts' if role=='chat' else 'nextcloud_contracts')
    return network,include(network,m.ownership(p,network))


@pytest.mark.parametrize('role', ['chat','files'])
def test_portable_backup_protects_applications_without_tailscale(role):
    from backup_contracts import resources,binary_paths,validate
    from backup_operations import match_owner
    from test_backup_contracts import profile
    network,owner=owners(role)
    resources_=resources(owner)
    assert 'tailscaled' not in resources_.services
    assert 'var/lib/tailscale' not in resources_.paths
    assert any('application_access.py' in path for path in binary_paths(owner))
    p=profile();p.update(role='portable',institution_id=network['institution_id'],node_name=network['node_name'])
    assert validate(p)==[]
    match_owner(p,network)
    changed=dict(network,access=dict(network['access'],frontend_address='10.76.30.99'))
    with pytest.raises(ValueError):match_owner(p,changed,expected=owner)


def test_portable_restore_isolates_lan_ingress_without_overlay():
    from restore_runtime import isolation_rules,guard_files
    network,owner=owners()
    rules=isolation_rules('portable','a'*32)
    assert 'tcp dport { 443, 8443, 3128 } drop' in rules
    assert 'tailscale0' not in rules
    assert all('tailscaled' not in str(path) for path in guard_files(owner))


def test_portable_upgrade_runtime_includes_access_contract():
    from upgrade_runtime import source_files
    assert 'application_access.py' in source_files('matrix',portable=True)
    assert 'application_access.py' in source_files('nextcloud',portable=True)
    assert 'application_access.py' not in source_files('matrix')


def test_portable_region_link_is_not_implicitly_enabled():
    import service_regional, nextcloud_regional
    for role,module in [('chat',service_regional),('files',nextcloud_regional)]:
        _,owner=owners(role)
        with pytest.raises(ValueError,match='Portable'):
            module.validate({}, {'ownership':owner['applications']})


@pytest.mark.parametrize('role', ['chat','files'])
def test_portable_upgrade_journal_preserves_access_and_rejects_migration(tmp_path,role):
    import copy
    import upgrade_transaction as transaction
    from test_upgrade_transaction import Backend
    from application_catalogue import predecessor
    from backup_contracts import binary_paths
    network,current=owners(role)
    package='matrix' if role=='chat' else 'nextcloud'
    old=dict(current['applications'],images={k:v['image'] for k,v in predecessor(package).items()})
    source=include(network,old)
    plan={'source_owner':source,'target_owner':current,'source_hashes':{name:'a'*64 for name in binary_paths(source)}}
    transaction.validate_plan(plan)
    changed={key:copy.deepcopy(value) for key,value in plan.items()}
    changed['target_owner']['access']['frontend_address']='10.76.30.99'
    changed['target_owner']['applications']['network']['access']['frontend_address']='10.76.30.99'
    with pytest.raises(ValueError):transaction.validate_plan(changed)
    backend=Backend('verify-new')
    with pytest.raises(transaction.UpgradeError) as error:transaction.apply(plan,backend,root=tmp_path)
    assert error.value.recovered and not error.value.committed
    assert transaction.last_result(tmp_path)['state']=='previous-version-restored'


@pytest.mark.parametrize('role',['chat','files'])
def test_native_restore_verification_checks_network_identity_and_application(role,monkeypatch):
    import application_access
    import backup_scope
    import restore_runtime
    from types import SimpleNamespace
    network,owner=owners(role);checked=[]
    monkeypatch.setattr(application_access,'verify_assigned',lambda address:checked.append(address))
    fake=SimpleNamespace(UNITS={'proxy':'proxy'},read_settings=lambda:{},ready=lambda name,settings:checked.append(name))
    monkeypatch.setattr(backup_scope,'application_runtime',lambda _:fake)
    runtime=restore_runtime.Runtime(owner)
    monkeypatch.setattr(runtime,'is_active',lambda _:True)
    runtime.verify(owner)
    assert checked==[network['access']['backend_address'],'proxy']

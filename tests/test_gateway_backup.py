import importlib
import json
from pathlib import Path
import pytest
from test_gateway_contracts import profile
from test_regional_agreements import pair
from setup_contracts import local_ownership


def network():
    p=profile()
    return local_ownership({'kind':'local-node','schema_version':1,'institution_id':p['institution_id'],'node_name':p['node_name'],
                           'headscale_hostname':p['regional_controller'],'node_tag':'tag:gateway'})


def owner():
    _,_,identity,_=pair()
    return importlib.import_module('gateway_backup').ownership(profile(),identity,network())


def test_gateway_backup_scope_binds_network_signed_identity_and_private_profile():
    m=importlib.import_module('gateway_backup');_,_,identity,_=pair();application=owner()
    from backup_scope import include,package,tag
    from backup_contracts import resources,binary_paths
    combined=include(network(),application)
    assert package(application)==tag(combined)=='gateway'
    assert resources(combined).paths==('var/lib/tailscale','etc/server-connectivity-profile.json','etc/rdc-gateway','var/lib/rdc-gateway-recovery')
    assert resources(combined).services==('rdc-regional-guard.timer','rdc-regional-gateway','tailscaled')
    assert 'usr/local/lib/rdc-gateway/gateway_recovery.py' in binary_paths(combined)
    assert 'etc/systemd/system/rdc-regional-gateway.service' in binary_paths(combined)
    for changes in ({'controller_hostname':'other.test'},{'node_name':'other'},{'institution_id':'other'}):
        with pytest.raises(ValueError):m.ownership(profile(),identity,dict(network(),**changes))


def test_gateway_is_detected_as_unprotected_by_network_only_backup(tmp_path):
    from backup_scope import installed_application,verify_installed,include
    application=owner();base=tmp_path/'etc/rdc-gateway';base.mkdir(parents=True)
    (base/'ownership.json').write_text(json.dumps(application));(base/'ownership.json').chmod(0o600)
    (tmp_path/'etc/server-connectivity-profile.json').write_text(json.dumps(network()))
    assert installed_application(tmp_path)==application
    verify_installed(tmp_path,include(network(),application))
    (base/'ownership.json').unlink()
    with pytest.raises(ValueError,match='incomplete'):installed_application(tmp_path)


def test_gateway_snapshot_rejects_unexpected_or_linked_approval_data(tmp_path):
    m=importlib.import_module('gateway_backup')
    from gateway_store import Store
    from regional_workspace import private_write
    from gateway_certificates import activate_certificate
    from test_gateway_certificates import Runtime
    from test_certificate_activation import validate
    root=tmp_path;parent=root/'etc';parent.mkdir();store=Store(parent/'rdc-gateway')
    _,_,identity,_=pair();store.initialize(profile(),identity);application=owner()
    private_write(store.base/'ownership.json',json.dumps(application).encode())
    private_write(store.base/'clock.json',b'{"schema_version":1,"latest_utc":1800000000}')
    activate_certificate(store,b'certificate',b'key',initial=True,validator=validate,runtime=Runtime(store),gid=__import__('os').getgid())
    archive=root/'var/lib/rdc-gateway-recovery';archive.mkdir(mode=0o700,parents=True)
    m.initialize_archive(archive,application)
    m.validate_data(root,application)
    (store.base/'unreviewed-script').write_text('not permitted')
    with pytest.raises(ValueError):m.validate_data(root,application)
    (store.base/'unreviewed-script').unlink();(store.base/'state.json').unlink();(store.base/'state.json').symlink_to(root/'other.json')
    with pytest.raises(ValueError):m.validate_data(root,application)


def test_scheduled_backup_contains_gateway_dependency_closure(tmp_path):
    import shutil,subprocess,sys
    m=importlib.import_module('backup_schedule');source=Path(m.__file__).parent
    for name in m.FILES:shutil.copyfile(source/name,tmp_path/name)
    command=[sys.executable,'-I','-c','import sys;sys.path.insert(0,sys.argv[1]);import gateway_backup;import gateway_backup_runtime',str(tmp_path)]
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==0,result.stderr


def issuer_source(path,application):
    from test_gateway_issuer import profile as issuer_profile
    from test_service_issuer import renewal
    from regional_workspace import private_write
    path.mkdir(mode=0o700)
    private_write(path/'configuration.json',json.dumps({'schema_version':1,'profile':issuer_profile(application['identity']),'network':application['network']}).encode())
    private_write(path/'cloudflare.ini',('dns_cloudflare_api_token = '+'c'*40+'\n').encode())
    private_write(path/'cli.ini',b'')
    (path/'certbot/renewal').mkdir(mode=0o700,parents=True)
    private_write(path/'certbot/renewal/rdc-services.conf',renewal().encode())
    return path


def test_gateway_issuer_archive_is_validated_private_data_and_survives_provider_absence(tmp_path):
    m=importlib.import_module('gateway_backup');application=owner();archive=tmp_path/'archive'
    m.initialize_archive(archive,application);source=issuer_source(tmp_path/'source',application)
    m.refresh_archive(archive,application,source)
    assert m.validate_archive(archive,application)['issuer_snapshot']
    saved=(archive/'issuer/cloudflare.ini').read_bytes()
    m.refresh_archive(archive,application,tmp_path/'not-installed')
    assert (archive/'issuer/cloudflare.ini').read_bytes()==saved
    # An unrelated or corrupted issuer cannot replace the known recovery copy.
    data=json.loads((source/'configuration.json').read_text());data['profile']['gateway_fingerprint']='f'*64
    (source/'configuration.json').write_text(json.dumps(data))
    with pytest.raises(ValueError):m.refresh_archive(archive,application,source)
    assert (archive/'issuer/cloudflare.ini').read_bytes()==saved


def test_gateway_issuer_archive_refuses_links_outside_its_account(tmp_path):
    m=importlib.import_module('gateway_backup');application=owner();archive=tmp_path/'archive'
    m.initialize_archive(archive,application);source=issuer_source(tmp_path/'source',application)
    (source/'certbot/escape').symlink_to(tmp_path/'outside')
    (tmp_path/'outside').write_text('Unrelated file')
    with pytest.raises(ValueError):m.refresh_archive(archive,application,source)
    assert not (archive/'issuer').exists()


def gateway_source(root):
    from gateway_store import Store
    from regional_workspace import private_write
    from gateway_certificates import activate_certificate
    from test_gateway_certificates import Runtime
    from test_certificate_activation import validate
    from backup_contracts import binary_paths
    from backup_scope import include
    m=importlib.import_module('gateway_backup');application=owner()
    (root/'etc').mkdir(parents=True);store=Store(root/'etc/rdc-gateway')
    store.initialize(application['profile'],application['identity'])
    private_write(store.base/'ownership.json',json.dumps(application).encode())
    private_write(store.base/'clock.json',b'{"schema_version":1,"latest_utc":1800000000}')
    private_write(root/'etc/server-connectivity-profile.json',json.dumps(network()).encode())
    activate_certificate(store,b'certificate',b'key',initial=True,validator=validate,runtime=Runtime(store),gid=__import__('os').getgid())
    (root/'var/lib/tailscale').mkdir(parents=True)
    (root/'var/lib/tailscale/tailscaled.state').write_bytes(b'network identity')
    m.initialize_archive(root/'var/lib/rdc-gateway-recovery',application)
    combined=include(network(),application)
    for name in binary_paths(combined):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'reviewed component')
    return store,combined


def test_gateway_capture_locks_policy_and_preserves_restart_order(tmp_path):
    from backup_snapshot import capture
    from test_backup_snapshot import Services
    store,combined=gateway_source(tmp_path/'root')
    class CheckingServices(Services):
        def stop(self,name):
            with pytest.raises(BlockingIOError):
                with store.lock():pass
            super().stop(name)
    services=CheckingServices(active=('rdc-regional-guard.timer','rdc-regional-gateway','tailscaled'))
    capture(tmp_path/'root',tmp_path/'stage',combined,services=services)
    assert services.events==[('stop','rdc-regional-guard.timer'),('stop','rdc-regional-gateway'),('stop','tailscaled'),
                             ('start','tailscaled'),('start','rdc-regional-gateway'),('start','rdc-regional-guard.timer')]
    assert json.loads((tmp_path/'stage/snapshot.json').read_text())['ownership']==combined


@pytest.mark.parametrize('pending',['policy','certificate','recovery'])
def test_gateway_capture_refuses_unfinished_changes_before_stopping(tmp_path,pending):
    from backup_snapshot import capture
    from test_backup_snapshot import Services
    from regional_workspace import private_write
    store,combined=gateway_source(tmp_path/'root');services=Services(active=('rdc-regional-gateway',))
    if pending=='policy':store.begin(store.candidate([],[],now=1800000000))
    elif pending=='certificate':private_write(store.base/'certificate-pending.json',b'{"schema_version":1,"material_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
    else:
        from gateway_recovery import suspend
        suspend(store,'b'*32,now=1800000000)
    with pytest.raises(ValueError):capture(tmp_path/'root',tmp_path/'stage',combined,services=services)
    assert services.events==[]


def test_gateway_admin_obeys_backup_lock_before_mutating(tmp_path):
    import fcntl,os
    from gateway_operations import backup_operation
    base=tmp_path/'backup';base.mkdir(mode=0o700)
    with (base/'operation.lock').open('a') as stream:
        os.chmod(stream.name,0o600);fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            with backup_operation(base):pytest.fail('must not enter while backup is active')
    with backup_operation(base):pass


@pytest.mark.parametrize('fail',[False,True])
def test_gateway_restore_keeps_later_revocations_tls_and_closed_review(tmp_path,fail):
    from backup_snapshot import capture
    from test_backup_snapshot import Services
    from test_restore_transaction import Runtime
    from gateway_store import Store
    import restore_transaction as restore
    source,combined=gateway_source(tmp_path/'source')
    source._write('state.json',dict(source.state(),generation=3,revoked_ids=['b'*32]))
    (source.base/'envoy.json').write_text('{"untrusted":"derived"}');(source.base/'envoy.json').chmod(0o600)
    stage=tmp_path/'stage';capture(tmp_path/'source',stage,combined,services=Services(active=()))
    target,_=gateway_source(tmp_path/'target')
    target._write('state.json',dict(target.state(),generation=8,revoked_ids=['a'*32]))
    (target.base/'tls/active/tls.crt').write_bytes(b'current replacement certificate')
    class CheckingRuntime(Runtime):
        def start(self,name):
            current=Store(target.base)
            assert current.recovery_pending()
            assert (current.base/'tls/active/tls.crt').read_bytes()==b'current replacement certificate'
            super().start(name)
    runtime=CheckingRuntime(fail=fail)
    if fail:
        with pytest.raises(restore.RestoreError) as error:
            restore.apply(stage,combined,root=tmp_path/'target',runtime=runtime,permissions=lambda *a:None)
        assert error.value.recovered
        assert target.state()['revoked_ids']==['a'*32]
    else:
        restore.apply(stage,combined,root=tmp_path/'target',runtime=runtime,permissions=lambda *a:None)
        assert target.state()['revoked_ids']==['a'*32,'b'*32]
        assert target.state()['generation']==9
        assert not (target.base/'envoy.json').exists()
    assert target.recovery_pending()
    assert target.recovery()['approval_floor']>=1800000000
    assert not (tmp_path/'target/etc/rdc-restore-pending.json').exists()


def test_restore_validation_permit_cannot_open_gateway_policy(tmp_path):
    from gateway_runtime import check_restore_boundary
    from gateway_recovery import suspend
    store,_=gateway_source(tmp_path/'root');pending=tmp_path/'pending';permit=tmp_path/'permit'
    check_restore_boundary(store,pending,permit)
    pending.write_text('{}');pending.chmod(0o600)
    with pytest.raises(ValueError):check_restore_boundary(store,pending,permit)
    permit.write_text('');permit.chmod(0o600)
    with pytest.raises(ValueError):check_restore_boundary(store,pending,permit)
    suspend(store,'a'*32,now=1800000000)
    check_restore_boundary(store,pending,permit)
    assert store.recovery_pending()
    permit.chmod(0o644)
    with pytest.raises(ValueError):check_restore_boundary(store,pending,permit)


def test_archived_provider_token_exports_privately_without_replacing_existing_files(tmp_path):
    m=importlib.import_module('gateway_backup');application=owner();archive=tmp_path/'archive'
    m.initialize_archive(archive,application);source=issuer_source(tmp_path/'source',application)
    m.refresh_archive(archive,application,source)
    output=tmp_path/'private';output.mkdir(mode=0o700);token=output/'token'
    result=m.export_token(archive,application,token)
    assert token.read_text()=='c'*40+'\n' and token.stat().st_mode&0o777==0o600
    assert 'c'*40 not in json.dumps(result)
    token.write_text('existing secret')
    with pytest.raises(ValueError):m.export_token(archive,application,token)
    assert token.read_text()=='existing secret'


def test_gateway_restore_recovers_interruption_between_directory_renames(tmp_path,monkeypatch):
    from backup_snapshot import capture
    from test_backup_snapshot import Services
    from test_restore_transaction import Runtime
    import restore_transaction as restore
    source,combined=gateway_source(tmp_path/'source')
    stage=tmp_path/'stage';capture(tmp_path/'source',stage,combined,services=Services(active=()))
    target,_=gateway_source(tmp_path/'target')
    original=restore.durable_rename
    def interrupted(source,destination):
        original(source,destination)
        if source==target.base:raise KeyboardInterrupt()
    monkeypatch.setattr(restore,'durable_rename',interrupted)
    with pytest.raises(KeyboardInterrupt):restore.apply(stage,combined,root=tmp_path/'target',runtime=Runtime(),permissions=lambda *a:None)
    assert not target.base.exists()
    monkeypatch.setattr(restore,'durable_rename',original)
    assert restore.recover(combined,root=tmp_path/'target',runtime=Runtime())['state']=='previous-data-restored'
    assert target.recovery_pending()

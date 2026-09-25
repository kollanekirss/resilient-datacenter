#!/usr/bin/env python3
"""Destructive adjacent-version acceptance; disposable GitHub-hosted Ubuntu only."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
from application_catalogue import predecessor,for_owner
from setup_contracts import local_ownership
from ci_matrix_backup import guard,prepare_network,prepare_backup,snapshot,restore
import upgrade_runtime as upgrade
import upgrade_transaction as transaction

ADDRESS='100.64.0.42'


@contextmanager
def old_installer(selected):
    guard();pins=predecessor(selected)
    if selected=='matrix':
        import service_contracts as contracts
        import service_operations as operations
        filename='service_images.json'
    else:
        import nextcloud_contracts as contracts
        import nextcloud_operations as operations
        filename='nextcloud_images.json'
    original_contract=contracts.image_pins;original_operations=operations.image_pins;source=operations.SOURCE
    with tempfile.TemporaryDirectory(prefix='rdc-ci-predecessor-') as temporary:
        folder=Path(temporary)
        for name in upgrade.source_files(selected):shutil.copy2(source/name,folder/name)
        (folder/filename).write_text(json.dumps({'schema_version':1,'components':pins},indent=2)+'\n')
        # The fixture creates exactly the reviewed predecessor. Production has
        # no arbitrary-version install switch or digest override.
        contracts.image_pins=lambda:pins;operations.image_pins=lambda:pins;operations.SOURCE=folder
        try:yield operations
        finally:contracts.image_pins=original_contract;operations.image_pins=original_operations;operations.SOURCE=source


def remote_probe():
    code='import socket,sys; socket.create_connection((sys.argv[1],443),timeout=1).close()'
    return subprocess.run(['ip','netns','exec','rdc-upgrade-user','python3','-c',code,ADDRESS],capture_output=True,timeout=3).returncode==0


def prepare_user_network():
    for args in [('ip','netns','add','rdc-upgrade-user'),('ip','link','add','rdc-upg-host','type','veth','peer','name','rdc-upg-user'),
                 ('ip','link','set','rdc-upg-user','netns','rdc-upgrade-user'),('ip','address','add','10.217.251.1/30','dev','rdc-upg-host'),
                 ('ip','link','set','rdc-upg-host','up'),('ip','netns','exec','rdc-upgrade-user','ip','address','add','10.217.251.2/30','dev','rdc-upg-user'),
                 ('ip','netns','exec','rdc-upgrade-user','ip','link','set','rdc-upg-user','up'),('ip','netns','exec','rdc-upgrade-user','ip','link','set','lo','up'),
                 ('ip','netns','exec','rdc-upgrade-user','ip','route','add','default','via','10.217.251.1')]:
        subprocess.run(args,check=True,capture_output=True,timeout=15)


def main(selected):
    guard()
    if selected not in ('matrix','nextcloud') or Path('/etc/server-connectivity-profile.json').exists():raise ValueError('Fresh disposable application runner required')
    if 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise ValueError('Ubuntu 24.04 fixture required')
    import ci_matrix_services as certificates
    host='matrix.ci.test' if selected=='matrix' else 'files.ci.test'
    certificates.MATRIX=host;certificates.ELEMENT='chat.ci.test' if selected=='matrix' else 'unused.ci.test'
    subprocess.run(['ip','address','add',ADDRESS+'/32','dev','lo'],check=True)
    with Path('/etc/hosts').open('a') as stream:stream.write('\n'+ADDRESS+' '+host+' '+certificates.ELEMENT+'\n')
    prepare_network()
    node='services' if selected=='matrix' else 'files'
    network=local_ownership({'kind':'local-node','schema_version':1,'institution_id':'ci','node_name':node,'headscale_hostname':'control.ci.test','node_tag':'tag:'+node})
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps(network))
    initial=prepare_backup(network);cert,key=certificates.certificates();password=secrets.token_urlsafe(24)
    profile={'schema_version':1,'institution_id':'ci','node_name':node,'tls_mode':'supplied','tls_certificate':str(cert),'tls_private_key':str(key)}
    if selected=='matrix':profile.update(kind='matrix-services',matrix_hostname=host,element_hostname=certificates.ELEMENT)
    else:profile.update(kind='nextcloud-services',nextcloud_hostname=host)
    real_upgrade_command=upgrade.command
    def observed_command(argv,**kwargs):
        label='rsync' if '--entrypoint=rsync' in argv else 'occ-upgrade' if 'upgrade' in argv else 'identity-export'
        try:return real_upgrade_command(argv,**kwargs)
        except BaseException:
            print('Disposable upgrade fixed-command phase failed: '+label,flush=True)
            raise
    upgrade.command=observed_command
    with old_installer(selected) as operations:
        if selected=='matrix':operations.install_or_resume(profile,network,ADDRESS)
        else:operations.install_or_resume(profile,network,ADDRESS,'cialice',password)
    if selected=='matrix':
        from service_accounts import create
        create('cialice',password,admin=True)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    token=None
    def request(method,path,data=None):
        headers={};body=None
        if selected=='nextcloud':headers['Authorization']='Basic '+base64.b64encode(('cialice:'+password).encode()).decode()
        elif token:headers['Authorization']='Bearer '+token
        if data is not None:
            body=data if isinstance(data,bytes) else json.dumps(data).encode()
            headers['Content-Type']='application/octet-stream' if isinstance(data,bytes) else 'application/json'
        with opener.open(urllib.request.Request('https://'+host+path,data=body,method=method,headers=headers),timeout=30) as response:
            result=response.read(1024*1024)
            return json.loads(result) if selected=='matrix' else result
    if selected=='matrix':
        token=request('POST','/_matrix/client/v3/login',{'type':'m.login.password','identifier':{'type':'m.id.user','user':'cialice'},'password':password})['access_token']
        room=request('POST','/_matrix/client/v3/createRoom',{'preset':'private_chat','creation_content':{'m.federate':False}})['room_id']
        endpoint='/_matrix/client/v3/rooms/'+urllib.parse.quote(room,safe='')+'/state/rdc.upgrade.proof/'
        def write_proof(value):request('PUT',endpoint,{'value':value})
        def read_proof():return request('GET',endpoint)['value']
        stable=lambda:hashlib.sha256(Path('/var/lib/rdc-services/synapse/server.signing.key').read_bytes()).hexdigest()
    else:
        endpoint='/remote.php/dav/files/cialice/upgrade-proof.txt'
        def write_proof(value):request('PUT',endpoint,value.encode())
        def read_proof():return request('GET',endpoint).decode()
        def stable():
            data=json.loads(Path('/etc/rdc-nextcloud/identity.json').read_text())
            return {k:v for k,v in data.items() if k not in ('version','data_fingerprint')}
    write_proof('before-upgrade');identity=stable();snapshot(initial)
    prepare_user_network();assert remote_probe()
    review=upgrade.check();assert review['state']=='upgrade-ready';plan=review['plan']
    from service_operations import pull_images
    pull_images(for_owner(plan['target_owner']['applications']))
    from restore_runtime import install_guards
    install_guards(plan['source_owner'],upgrade_compat=True)
    candidate_verified=[]
    class FailedCandidate(upgrade.Backend):
        def verify(self,journal,*,original=False):
            super().verify(journal,original=original)
            assert not remote_probe(),'Non-loopback user ingress opened before commit'
            if not original:
                candidate_verified.append(True)
                write_proof('candidate-only-change')
                raise ValueError('Injected failure after actual target version verification and candidate write')
    with upgrade.locks(selected):
        try:transaction.apply(plan,FailedCandidate(plan['source_owner']))
        except transaction.UpgradeError as error:
            if not candidate_verified:raise
            assert error.recovered and not error.committed
        else:raise AssertionError('Candidate verification failure was ignored')
    assert candidate_verified==[True],'Failure did not reach actual target verification'
    assert read_proof()=='before-upgrade' and stable()==identity and remote_probe()
    assert upgrade.check()['state']=='upgrade-ready'
    print(selected+': actual predecessor backup, target migration, closed non-loopback ingress and complete original code/data rollback PASS.',flush=True)
    class Interrupted(upgrade.Backend):
        def migrate(self,journal):
            super().migrate(journal);assert not remote_probe();raise KeyboardInterrupt()
    with upgrade.locks(selected):
        try:transaction.apply(plan,Interrupted(plan['source_owner']))
        except KeyboardInterrupt:pass
        else:raise AssertionError('Upgrade interruption did not reach its durable boundary')
    assert Path('/etc/rdc-upgrade-pending.json').exists()
    unit='rdc-service-proxy' if selected=='matrix' else 'rdc-nextcloud-proxy'
    subprocess.run(['systemctl','stop',unit],check=True)
    assert subprocess.run(['systemctl','start',unit],capture_output=True).returncode!=0
    subprocess.run(['systemctl','reset-failed',unit],check=True)
    with upgrade.locks(selected):assert transaction.recover(upgrade.Backend(plan['source_owner']))['state']=='previous-version-restored'
    assert read_proof()=='before-upgrade' and stable()==identity and remote_probe()
    print(selected+': interrupted real migration blocked automatic startup and recovered the original version/data PASS.',flush=True)
    class AfterPublication(upgrade.Backend):
        def publish(self,journal):
            super().publish(journal)
            if journal['phase']=='committed':
                assert remote_probe();write_proof('accepted-after-commit')
                raise ValueError('Injected interruption after actual publication and new user data')
    with upgrade.locks(selected):
        try:transaction.apply(plan,AfterPublication(plan['source_owner']))
        except transaction.UpgradeError as error:assert error.committed
        else:raise AssertionError('Committed interruption was ignored')
    assert read_proof()=='accepted-after-commit'
    with upgrade.locks(selected):assert transaction.recover(upgrade.Backend(plan['source_owner']))['state']=='upgraded-service-verified'
    assert read_proof()=='accepted-after-commit' and stable()==identity and remote_probe()
    assert upgrade.check()['state']=='already-current'
    from backup_operations import backup_now
    selected_snapshot=backup_now()['snapshot_id'];write_proof('later-change')
    restore(selected_snapshot)
    assert read_proof()=='accepted-after-commit' and stable()==identity
    print(selected+': actual new version, preserved stable identity and user data, committed recovery without stale rollback, verified new-version encrypted backup and restore PASS. VPN identity is a fixture; physical sites and public issuance NOT RUN.',flush=True)


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Choose matrix or nextcloud')
    try:main(sys.argv[1])
    except BaseException as failure:
        import traceback
        cause=failure
        while cause is not None:
            traceback.print_exception(type(cause),cause,cause.__traceback__,chain=False)
            cause=cause.__context__
        raise

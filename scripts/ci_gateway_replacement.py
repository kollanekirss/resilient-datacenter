"""Fresh owned gateway installation after fencing the old disposable fixture.

SFTP and application proxy/TLS are real. VPN enrollment remains the explicitly
labelled stub; real client identity continuity is a separate acceptance check.
"""
import json
from pathlib import Path
import shutil
import subprocess
import time


def exercise(identifier,document,fixture):
    from ci_matrix_backup import guard,restore
    ROOT=fixture.ROOT;run=fixture.run;curl=fixture.curl;APPROVAL_KEYS=fixture.APPROVAL_KEYS
    import gateway_operations as operations
    import gateway_runtime as gateway
    import gateway_backup
    import regional_agreements as agreements
    from gateway_store import Store
    from backup_operations import configured,configure
    from backup_bootstrap import stage,review
    from restore_transaction import apply
    from restore_runtime import Runtime
    guard();store=Store(gateway.BASE);profile=store.profile();identity=store.identity()
    old_config,_=configured();retired=ROOT/'fenced-installation';retired.mkdir(mode=0o700)
    # This fixture fences its old processes first, then removes only its owned
    # installation paths. The independent SFTP storage remains available.
    for unit in ('rdc-backup.timer','rdc-service-certificate.timer','rdc-regional-guard.timer','rdc-regional-gateway.service'):
        run('systemctl','disable','--now',unit)
    run('systemctl','stop','rdc-regional-guard.service','rdc-service-certificate.service','rdc-backup.service','tailscaled')
    run('podman','rm',gateway.CONTAINER)
    run('nft','delete','table','inet','rdc_gateway')
    paths=['/etc/rdc-gateway','/var/lib/rdc-gateway-recovery','/etc/rdc-gateway-recovery.json','/usr/local/lib/rdc-gateway',
           '/etc/rdc-service-acme','/opt/rdc-service-certificate-runtime','/etc/rdc-backup','/opt/rdc-backup-runtime',
           '/usr/local/bin/rdc-restic','/var/lib/rdc-backup','/var/lib/tailscale','/etc/sysctl.d/80-rdc-regional-gateway.conf']
    for name in ('rdc-regional-gateway.service','rdc-regional-guard.service','rdc-regional-guard.timer',
                 'rdc-service-certificate.service','rdc-service-certificate.timer','rdc-backup.service','rdc-backup.timer'):
        paths.extend(['/etc/systemd/system/'+name,'/etc/systemd/system/'+name+'.d'])
    for index,name in enumerate(paths):
        path=Path(name)
        if path.exists() or path.is_symlink():path.rename(retired/(str(index)+'-'+path.name))
    credentials=retired/(str(paths.index('/etc/rdc-backup'))+'-rdc-backup')
    Path('/var/lib/tailscale').mkdir(mode=0o700)
    Path('/var/lib/tailscale/ci-identity').write_text('temporary replacement identity')
    run('systemctl','daemon-reload');run('systemctl','start','tailscaled')
    configure(old_config['profile'],password_file=credentials/'password',ssh_key_file=credentials/'ssh_key')
    result=stage(identifier,'gateway');assert result['network_identity']=='not-promoted'
    data,_=configured();folder,plan=review(identifier,data['ownership'])
    assert plan['package']=='gateway' and not (folder/'network/data/etc/rdc-gateway').exists()
    class NetworkFixtureRuntime(Runtime):
        def verify(self,owner):
            assert self.is_active('tailscaled')
            assert Path('/var/lib/tailscale/ci-identity').read_text()=='explicitly synthetic gateway network identity'
    apply(folder/'network',data['ownership'],runtime=NetworkFixtureRuntime(data['ownership']))
    assert not Path('/etc/rdc-gateway').exists()
    # Issue new replacement TLS using the fixture CA and restore the original
    # reviewed input paths; no old private key is installed from the snapshot.
    issued=ROOT/'fresh-replacement-tls';issued.mkdir(mode=0o700)
    names=sorted(identity['payload']['services'].values())
    run('openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(issued/'tls.key'),'-out',str(issued/'request.csr'),'-subj','/CN='+names[0])
    (issued/'extensions').write_text('subjectAltName='+','.join('DNS:'+name for name in names)+'\nextendedKeyUsage=serverAuth\n')
    run('openssl','x509','-req','-in',str(issued/'request.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),'-CAcreateserial','-out',str(issued/'tls.crt'),'-days','30','-extfile',str(issued/'extensions'))
    for field,name in (('tls_certificate','tls.crt'),('tls_private_key','tls.key')):
        destination=Path(profile[field]);assert destination.resolve().is_relative_to(ROOT)
        shutil.copyfile(issued/name,destination);destination.chmod(0o600)
    assert operations.install(profile,identity)['partners']==0
    gateway_backup.include_services()
    restore(identifier)
    assert store.recovery_pending()
    assert (store.base/'tls/active/tls.crt').read_bytes()==(issued/'tls.crt').read_bytes()
    assert not Path('/etc/rdc-service-acme').exists()
    assert gateway_backup.validate_archive(gateway_backup.ARCHIVE,configured()[0]['ownership']['applications'])['issuer_snapshot']
    assert curl('rdc-peer','/_matrix/federation/v1/version',timeout=2).returncode!=0
    peer=document['offer']['payload']['recipient'];now=int(time.time())
    offer=agreements.offer(APPROVAL_KEYS['north'],identity,peer,['matrix'],now=now,expires_at=now+1800,expected_peer=agreements.fingerprint(peer))
    current=agreements.accept(APPROVAL_KEYS['south'],offer,now=now,expected_peer=agreements.fingerprint(identity))
    assert operations.change([current])['partners']==1
    assert curl('rdc-peer','/_matrix/federation/v1/version').stdout=='fixture:/_matrix/federation/v1/version'
    print('Fresh owned gateway replacement: old processes fenced; saved credentials import, actual encrypted network-only bootstrap, clean gateway installation, full restore retaining new TLS, issuer archived but inactive, fresh partner consent PASS. VPN identity is synthetic; no physical-site claim.',flush=True)

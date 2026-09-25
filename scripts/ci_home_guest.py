#!/usr/bin/env python3
"""Fixed in-guest personal journey phases; private inputs arrive over local console."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from setup_contracts import local_ownership


def private(path,content):
    path=Path(path);path.write_text(content);path.chmod(0o600)


def main(phase,data):
    if os.geteuid()!=0 or not Path('/var/lib/rdc-ci-ready').exists() or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise ValueError('Fresh disposable Ubuntu guest required')
    manifest=data['manifest'];owner=local_ownership(manifest)
    if phase=='network':
        from local_node import apply_manifest
        path=Path('/root/node.json');private(path,json.dumps(manifest))
        assert apply_manifest(manifest,path,confirm_fn=lambda _:'yes')['status']=='installed'
        auth=Path('/root/one-use-auth.key');private(auth,data['auth_key'])
        try:subprocess.run(['/usr/local/bin/tailscale','up','--login-server=https://'+manifest['headscale_hostname'],
            '--hostname='+manifest['node_name'],'--advertise-tags='+manifest['node_tag'],'--auth-key=file:'+str(auth),
            '--accept-dns=false','--accept-routes=false','--ssh=false','--timeout=60s'],check=True,capture_output=True,timeout=75)
        finally:auth.unlink(missing_ok=True)
        from local_checks import check_local
        assert check_local(manifest,require_owned=True)==[]
        before=network_identity()
        assert apply_manifest(manifest,path,confirm_fn=lambda _:'yes')['status']=='installed'
        assert before==network_identity()
        return before
    if phase=='services':
        profile=data['profile'];address=network_identity()['address']
        with Path('/etc/hosts').open('a') as stream:stream.write('\n'+address+' '+data['hostname']+' chat.home.ci.test\n')
        if data['package']=='matrix':
            from service_operations import install_or_resume
            from service_accounts import create
            install_or_resume(profile,owner,address);create('cialice',data['password'],admin=True)
        else:
            from nextcloud_operations import install_or_resume
            install_or_resume(profile,owner,address,'cialice',data['password'])
        return {'network':network_identity(),'application_identity':application_identity(data['package'])}
    if phase=='backup-configure':
        from backup_operations import configure
        return configure(data['backup_profile'])
    if phase=='snapshot':
        from backup_operations import configured,backup_now
        from backup_scope import installed_application,application_backup
        application_backup(installed_application()).include_services()
        _,transport=configured();transport.initialize()
        result=backup_now()
        return dict(result,network=network_identity(),application_identity=application_identity(data['package']))
    if phase=='bootstrap':
        from backup_operations import configure,configured
        configure(data['backup_profile'],password_file=Path('/root/recovery-password'),ssh_key_file=Path('/root/recovery-key'))
        from backup_bootstrap import stage,review
        stage(data['snapshot'],data['package']);configuration,_=configured()
        folder,_=review(data['snapshot'],configuration['ownership'])
        from restore_transaction import apply
        assert data['old_guest_fenced'] is True
        assert apply(folder/'network',configuration['ownership'])['state']=='restored-service-verified'
        return network_identity()
    if phase=='restore':
        from backup_operations import configured,stage_restore,WORK
        from backup_scope import installed_application,application_backup
        application_backup(installed_application()).include_services()
        stage_restore(data['snapshot']);configuration,_=configured()
        from restore_transaction import apply
        assert data['old_guest_fenced'] is True
        assert apply(WORK/'restores'/data['snapshot'],configuration['ownership'])['state']=='restored-service-verified'
        return {'network':network_identity(),'application_identity':application_identity(data['package'])}
    raise ValueError('Unknown guest phase')


def network_identity():
    status=json.loads(subprocess.run(['/usr/local/bin/tailscale','status','--json'],check=True,capture_output=True,text=True,timeout=15).stdout)
    if status['BackendState']!='Running':raise ValueError('Guest client is not running')
    return {'public_key':status['Self']['PublicKey'],'address':next(ip for ip in status['Self']['TailscaleIPs'] if '.' in ip)}


def application_identity(package):
    if package=='matrix':return hashlib.sha256(Path('/var/lib/rdc-services/synapse/server.signing.key').read_bytes()).hexdigest()
    data=json.loads(Path('/etc/rdc-nextcloud/identity.json').read_text())
    return {k:data[k] for k in ('instanceid','version')}


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('One fixed guest phase required')
    result=main(sys.argv[1],json.load(sys.stdin))
    print('RDC_RESULT:'+json.dumps(result),flush=True)

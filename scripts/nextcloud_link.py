"""Journaled attachment of the managed private file-service connector."""
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import nextcloud_regional as connector


def transition(config,settings,runtime):
    """Caller holds backup-first application lock; failure keeps internal files."""
    connector.validate(config,settings)
    existing=connector.configured(settings)
    if existing and existing['gateway_fingerprint']!=config['gateway_fingerprint']:
        raise ValueError('Changing the institution approval identity requires a reviewed migration')
    if not connector.BASE.exists():
        connector.BASE.mkdir(mode=0o750);connector.BASE.chmod(0o750)
        if os.geteuid()==0:os.chown(connector.BASE,0,33)
    pending=connector.BASE/'pending.json';disabled=connector.BASE/'disabled.json'
    if pending.exists() or pending.is_symlink():
        if json.loads(connector.read(pending))!=config:
            raise ValueError('Resume the same pending file connector or disable it before preparing another')
    connector.write(pending,json.dumps(config),mode=0o600)
    connector.write(disabled,json.dumps({'reason':'connector-configuration-in-progress'}),mode=0o600)
    try:
        runtime.stop()
        runtime.validate(config)
        connector.write(connector.BASE/'configuration.json',json.dumps(config))
        pending.unlink();disabled.unlink()
        descriptor=os.open(connector.BASE,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        runtime.restart()
    except BaseException:
        connector.write(pending,json.dumps(config),mode=0o600)
        connector.write(disabled,json.dumps({'reason':'connector-activation-failed'}),mode=0o600)
        try:runtime.restart()
        except BaseException:pass
        raise


class Runtime:
    def __init__(self,settings):self.settings=settings
    def stop(self):
        subprocess.run(['/bin/systemctl','stop','rdc-nextcloud-proxy.service','rdc-nextcloud.service'],check=True,capture_output=True,timeout=120)
    def validate(self,config):
        import nextcloud_runtime as application
        candidate=connector.BASE/'candidate.Caddyfile'
        connector.write(candidate,connector.proxy((application.BASE/'Caddyfile').read_text(),config))
        try:
            subprocess.run(['/usr/bin/podman','--runtime=/usr/bin/runc','run','--rm','--network=none','--read-only',
                '--cap-drop=ALL','--cap-add=NET_BIND_SERVICE','--security-opt=no-new-privileges',
                '--tmpfs','/config:rw,nosuid,nodev,size=16m','--tmpfs','/data:rw,nosuid,nodev,size=16m',
                '--volume',str(candidate)+':/etc/caddy/Caddyfile:ro','--volume',str(application.TLS)+':/tls:ro',
                self.settings['components']['proxy']['image'],'caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'],
                check=True,capture_output=True,timeout=60)
        finally:candidate.unlink(missing_ok=True)
    def restart(self):
        import nextcloud_runtime as application
        subprocess.run(['/bin/systemctl','restart','rdc-nextcloud.service','rdc-nextcloud-proxy.service'],check=True,capture_output=True,timeout=240)
        application.ready('nextcloud',self.settings);application.ready('proxy',self.settings)


def verify_installed_runtime():
    import nextcloud_runtime as application
    source=Path(__file__).resolve().parent
    for name in ('nextcloud_runtime.py','nextcloud_regional.py','service_runtime.py','service_regional.py','regional_http.py'):
        installed=application.INSTALLED/name;info=installed.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or installed.read_bytes()!=(source/name).read_bytes():
            raise ValueError('This file runtime needs a reviewed upgrade before attachment; no installed runtime was overwritten')


def configure(bundle,*,expected_fingerprint):
    from backup_operations import require_platform
    from service_certificates import operation_lock
    from service_link import prepare
    import nextcloud_runtime as application
    require_platform()
    with operation_lock(lock_path=Path('/run/rdc-nextcloud-operation.lock')):
        settings=application.read_settings()
        config=prepare(bundle,settings,expected_fingerprint=expected_fingerprint,now=int(time.time()))
        verify_installed_runtime()
        records=json.loads(subprocess.run(['/usr/sbin/ip','-j','address','show'],check=True,capture_output=True,text=True,timeout=15).stdout)
        if not any(item['ifname'] not in ('lo','tailscale0') and any(value.get('local')==config['service_lan_address'] for value in item.get('addr_info',[])) for item in records):
            raise ValueError('Assign this file VM its declared dedicated private LAN address first')
        transition(config,settings,Runtime(settings))
    return {'state':'nextcloud-connector-configured','peers':config['peers'],'application_federation':'not-verified',
            'recovery':'Application restore suspends this connector until current partnerships are reviewed again.'}


def disable():
    from backup_operations import require_platform
    from service_certificates import operation_lock
    import nextcloud_runtime as application
    require_platform()
    with operation_lock(lock_path=Path('/run/rdc-nextcloud-operation.lock')):
        settings=application.read_settings();verify_installed_runtime()
        if connector.configured(settings) is None:return {'state':'connector-not-installed'}
        connector.write(connector.BASE/'disabled.json',json.dumps({'reason':'operator-disabled'}),mode=0o600)
        Runtime(settings).restart()
        (connector.BASE/'pending.json').unlink(missing_ok=True)
    return {'state':'connector-disabled','internal_service':'listeners-verified'}

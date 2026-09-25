"""One bounded read-only evidence worker. Never enroll, repair or refresh state."""
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parent))

BASES={'matrix':'etc/rdc-services','nextcloud':'etc/rdc-nextcloud','gateway':'etc/rdc-gateway'}


def present(path):return path.exists() or path.is_symlink()


def owned_json(path,*,require_root=True,private=False):
    from gateway_store import decode
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&(0o077 if private else 0o022) or info.st_size>65536:
        raise ValueError('Unsafe ownership record')
    return decode(path.read_bytes())


def discover(root=Path('/'),*,require_root=True):
    from backup_scope import include
    from service_contracts import network_manifest
    from profile_config import _identifier
    from validate_inventory import hostname
    root=Path(root);marker=root/'etc/server-connectivity-profile.json'
    directories=[(package,root/base) for package,base in BASES.items() if present(root/base)]
    if not present(marker):
        if directories:raise ValueError('Application exists without owned network')
        return None
    network=owned_json(marker,require_root=require_root)
    if not isinstance(network,dict):raise ValueError('Invalid network record')
    role=network.get('role')
    if role=='peer':network_manifest(network)
    elif role in ('controller','relay'):
        fields={'schema_version','deployment_mode','institution_id','role','controller_hostname'}
        managed=network.get('schema_version')==3
        if managed:fields|={'tls_mode','certificate_hostname'}
        if (set(network)!=fields or type(network.get('schema_version')) is not int or network['schema_version'] not in (2,3) or
            network['deployment_mode']!='independent' or not _identifier(network['institution_id']) or not hostname(network['controller_hostname']) or
            (managed and (network['tls_mode']!='managed-acme' or not hostname(network['certificate_hostname'])))):
            raise ValueError('Unsupported infrastructure ownership')
    else:raise ValueError('Unknown network role')
    if len(directories)>1:raise ValueError('Mixed application roles')
    application=None;package=None;owner=network
    if directories:
        package,base=directories[0];info=base.lstat()
        if role!='peer' or not stat.S_ISDIR(info.st_mode) or info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&0o022:
            raise ValueError('Unsafe application directory')
        if not present(base/'ownership.json'):raise ValueError('Incomplete application installation')
        application=owned_json(base/'ownership.json',require_root=require_root,private=package=='gateway')
        if application.get('packages')!=[package]:raise ValueError('Application directory differs from package')
        owner=include(network,application)
    return {'network':network,'owner':owner,'application':application,'package':package,'role':role}


def network_status(found):
    if found['role']=='peer':
        from service_contracts import network_manifest
        from local_enrollment import NativeRuntime,enrollment_action
        result=enrollment_action(network_manifest(found['network']),NativeRuntime(allow_sudo=False),start_requested=False)
        state={'enrolled':'enrolled','awaiting_enrollment':'awaiting-enrollment','client_not_running':'stopped'}.get(result['status'],'unknown')
        if state!='enrolled':return {'state':state}
        from diagnostic_probe import probe_controller
        checks=probe_controller(found['network']['controller_hostname'])
        reachable=any(c.code=='tls.verify' and c.outcome=='pass' for c in checks)
        return {'state':'enrolled' if reachable else 'enrolled-controller-unreachable','controller_reachable':reachable}
    unit='headscale' if found['role']=='controller' else 'sc-derp'
    result=subprocess.run(['/bin/systemctl','is-active',unit],capture_output=True,timeout=5)
    return {'state':'service-running' if result.returncode==0 else ('stopped' if result.returncode==3 else 'unknown')}


def applications(found):
    if found['application'] is None:return {'state':'not-applicable'}
    from backup_scope import application_runtime
    runtime=application_runtime(found['application']);settings=runtime.read_settings()
    for component in runtime.UNITS:
        item=runtime.inspect_container(component,settings)
        if item is None or not item.get('State',{}).get('Running'):return {'state':'stopped'}
        runtime.verify_image(component,settings)
        runtime.ready(component,settings,attempts=1)
    return {'state':'service-listeners-verified'}


def certificates(found):
    if found['application'] is None:return {'state':'not-applicable'} if found['role']=='peer' else infrastructure_certificate(found)
    import service_issuer
    if present(service_issuer.BASE):
        result=service_issuer.status()
        if result['state'] in ('renewal-failed','issuance-failed'):return dict(result,state='renewal-failed')
        verified=result.get('serving_verified',False)
        expiry=result.get('expires_at')
    elif found['package']=='gateway':
        from gateway_certificates import status
        from gateway_store import Store
        from gateway_runtime import BASE
        result=status(Store(BASE))
        if result['state']=='gateway-certificate-pending':return {'state':'change-pending'}
        expiry=result['expires_at'];verified=result['serving_certificate_verified']
        result={'automatic_renewal':False}
    else:
        from backup_scope import application_runtime
        from cryptography import x509
        from certificate_lifecycle import validity
        runtime=application_runtime(found['application']);settings=runtime.read_settings()
        runtime.verify_https(settings);verified=True
        expiry=validity(x509.load_pem_x509_certificate((runtime.TLS/'tls.crt').read_bytes()),'after').isoformat()
        result={'automatic_renewal':False}
    if not expiry:return {'state':'unknown'}
    when=datetime.fromisoformat(expiry);now=datetime.now(timezone.utc)
    if when.tzinfo is None:raise ValueError('Unknown certificate time')
    state='certificate-invalid' if not verified or when<=now else ('certificate-expiring' if when<=now+timedelta(days=14) else 'certificate-valid')
    return {'state':state,'expires_at':expiry,'serving_verified':verified,'automatic_renewal':result.get('automatic_renewal',False)}


def infrastructure_certificate(found):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    import certificate_lifecycle as lifecycle
    import hashlib,socket,ssl
    owner=found['network'];automatic=False;failed=False
    if owner['schema_version']==3:
        data=lifecycle.configuration();name=data['hostname']
        pointer=lifecycle.generation(lifecycle.BASE,'active')
        if pointer is None:return {'state':'certificate-invalid'}
        path=lifecycle.BASE/pointer/'tls.crt'
        if present(lifecycle.BASE/'status.json'):failed=lifecycle.root_file(lifecycle.BASE/'status.json').get('state')=='failed'
        timer=subprocess.run(['/bin/systemctl','is-active','rdc-certificate-renew.timer'],capture_output=True,timeout=5)
        if timer.returncode not in (0,3):raise ValueError('Unknown renewal timer state')
        automatic=timer.returncode==0
    elif found['role']=='controller':name=owner['controller_hostname'];path=Path('/etc/headscale/tls.crt')
    else:
        paths=list(Path('/etc/sc-derp').glob('*.crt'))
        if len(paths)!=1:raise ValueError('Ambiguous relay certificate')
        path=paths[0];name=path.stem
        from validate_inventory import hostname
        if not hostname(name):raise ValueError('Invalid relay certificate identity')
    certificate=x509.load_pem_x509_certificate(path.read_bytes());expiry=lifecycle.validity(certificate,'after');verified=False
    try:
        with socket.create_connection(('127.0.0.1',443),timeout=3) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=name) as secure:
                verified=hashlib.sha256(secure.getpeercert(binary_form=True)).digest()==certificate.fingerprint(hashes.SHA256())
    except (OSError,ValueError):pass
    now=datetime.now(timezone.utc)
    state='renewal-failed' if failed else ('certificate-invalid' if not verified or expiry<=now else ('certificate-expiring' if expiry<=now+timedelta(days=14) else 'certificate-valid'))
    return {'state':state,'expires_at':expiry.isoformat(),'serving_verified':verified,'automatic_renewal':automatic}


def backup(found):
    from backup_operations import BASE,configured,status_summary
    from backup_schedule import read_private,owned_schedule,overdue
    if not present(BASE):return {'state':'not-configured'}
    data,transport=configured()
    if data['ownership']!=found['owner']:return {'state':'backup-scope-missing'}
    result={}
    if present(BASE/'last-attempt.json'):
        attempts=read_private(BASE/'last-attempt.json')
        result['last_attempt']=attempts.get('last_attempt',{}).get('outcome')
        if attempts.get('last_success'):result['last_success_at']=attempts['last_success'].get('finished_at')
    try:summary=status_summary(transport.snapshots(timeout=10))
    except (OSError,ValueError,subprocess.SubprocessError):return dict(result,state='backup-unreachable')
    if summary['state']=='no-backup':return dict(result,state='no-backup')
    result.update(captured_at=summary['captured_at'],backup_age_seconds=summary['backup_age_seconds'])
    # Without a saved schedule use a disclosed daily freshness threshold.
    frequency=owned_schedule()['frequency'] if present(BASE/'schedule.json') else 'daily'
    state='backup-overdue' if overdue(frequency,summary['backup_age_seconds']) else 'backup-current'
    if result.get('last_attempt')=='failed':state='backup-failed'
    return dict(result,state=state)


def partners(found):
    if found['application'] is None:return {'state':'not-applicable'}
    if found['package']=='gateway':
        from gateway_operations import status
        result=status()
        if result['state']=='gateway-recovery-review-required':return {'state':'partner-review-required'}
        if result['state']=='gateway-change-pending':return {'state':'change-pending'}
        if not all(result[k] for k in ('time_checkpoint_recent','guard_timer_active','network_identity_verified','proxy_running')):return {'state':'unknown'}
        count=len(result['approved_peers'])
        # Running transport is not a verified partner exchange.
        return {'state':'partner-review-required' if count else 'partners-disabled','approved_peers':count}
    from backup_scope import application_runtime
    if found['package']=='matrix':import service_regional as regional
    else:import nextcloud_regional as regional
    settings=application_runtime(found['application']).read_settings()
    if present(regional.RESTORE):return {'state':'partner-review-required'}
    if present(regional.BASE/'pending.json'):return {'state':'change-pending'}
    if not regional.configured(settings):return {'state':'partners-disabled'}
    return {'state':'partner-review-required' if regional.active(settings) else 'partners-suspended'}


def probe(name):
    if name not in ('network','applications','certificates','backup','recovery','partners'):raise ValueError('Unknown dimension')
    if present(Path('/etc/rdc-upgrade-pending.json')):return {'state':'upgrade-pending'}
    if present(Path('/etc/rdc-restore-pending.json')):return {'state':'restore-pending'}
    found=discover()
    if found is None:return {'state':'not-configured'}
    if name=='recovery':
        from restore_evidence import latest
        return latest(Path('/'),found['owner'])
    return {'network':network_status,'applications':applications,'certificates':certificates,'backup':backup,'partners':partners}[name](found)


if __name__=='__main__':
    from product_status import DIMENSIONS,sanitize
    if len(sys.argv)!=2 or sys.argv[1] not in DIMENSIONS:raise SystemExit(2)
    try:result=probe(sys.argv[1])
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):result={'state':'unknown'}
    print(json.dumps(sanitize(sys.argv[1],result)))

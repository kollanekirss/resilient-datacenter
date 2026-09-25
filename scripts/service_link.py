"""Install a reviewed Matrix LAN connector without changing its home identity."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import regional_agreements as agreements
import gateway_contracts
import service_regional as connector

FIELDS={'kind','schema_version','package','gateway_identity','gateway_lan_address','service_lan_address','lan_subnet','agreements'}


def prepare(bundle,settings,*,expected_fingerprint,now):
    if not isinstance(bundle,dict) or set(bundle)!=FIELDS or bundle['kind']!='regional-service-link' or type(bundle['schema_version']) is not int or bundle['schema_version']!=1 or bundle['package']!='matrix':raise ValueError('Use a supported public Matrix connector document')
    agreements.canonical(bundle);identity=bundle['gateway_identity'];own=agreements.verify_identity(identity)
    if agreements.fingerprint(identity)!=expected_fingerprint:raise ValueError('Confirm the full institution approval fingerprint independently')
    owner=settings['ownership']
    if owner.get('packages')!=['matrix'] or owner.get('institution_id')!=own['institution_id'] or owner.get('matrix_hostname')!=own['services'].get('matrix') or owner.get('network',{}).get('controller_hostname')==own['regional_controller']:
        raise ValueError('Connector must match this institution and Matrix domain while preserving a separate internal network')
    peers=gateway_contracts.peer_rules(identity,bundle['agreements'],[],now=now)
    config={'schema_version':1,'package':'matrix','application_owner':owner,'gateway_fingerprint':expected_fingerprint,
            **{k:bundle[k] for k in ('gateway_lan_address','service_lan_address','lan_subnet')},
            'peers':sorted([{'hostname':peer['domains']['matrix'],'expires_at':peer['expires_at']} for peer in peers if 'matrix' in peer['services']],key=lambda p:p['hostname'])}
    connector.validate(config,settings);return config


def export_gateway(store):
    if store.pending():raise ValueError('Complete the pending gateway policy change before preparing its service connector')
    state=store.state();profile=store.profile();identity=store.identity()
    if 'matrix' not in identity['payload']['services']:raise ValueError('This gateway has no Matrix service')
    approved={peer['agreement_id'] for peer in store.peers() if 'matrix' in peer['services']}
    return {'kind':'regional-service-link','schema_version':1,'package':'matrix','gateway_identity':identity,
            'gateway_lan_address':profile['lan_address'],'service_lan_address':profile['upstreams']['matrix'],'lan_subnet':profile['lan_subnet'],
            'agreements':[document for document in state['agreements'] if document['offer']['payload']['agreement_id'] in approved]}


def verify_installed_runtime():
    import service_runtime as runtime
    source=Path(__file__).resolve().parent
    for name in ('service_runtime.py','service_regional.py'):
        installed=runtime.INSTALLED/name;info=installed.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or installed.read_bytes()!=(source/name).read_bytes():
            raise ValueError('This application runtime needs a reviewed upgrade before adding its regional connector; no runtime was overwritten')


def restart(settings):
    import service_runtime as runtime
    import subprocess
    subprocess.run(['/bin/systemctl','restart','rdc-synapse.service','rdc-service-proxy.service'],check=True,capture_output=True,timeout=240)
    runtime.ready('synapse',settings);runtime.ready('proxy',settings)


def configure(bundle,*,expected_fingerprint):
    from backup_operations import require_platform
    import service_runtime as runtime
    from service_certificates import operation_lock
    import subprocess
    require_platform()
    with operation_lock():
        settings=runtime.read_settings();config=prepare(bundle,settings,expected_fingerprint=expected_fingerprint,now=int(time.time()))
        verify_installed_runtime()
        records=json.loads(subprocess.run(['/usr/sbin/ip','-j','address','show'],check=True,capture_output=True,text=True,timeout=15).stdout)
        if not any(item['ifname'] not in ('lo','tailscale0') and any(value.get('local')==config['service_lan_address'] for value in item.get('addr_info',[])) for item in records):raise ValueError('Assign this service VM its declared dedicated private LAN address first')
        existing=connector.configured(settings)
        if existing and existing['gateway_fingerprint']!=expected_fingerprint:raise ValueError('Changing the institution signing identity requires a reviewed migration')
        if not connector.BASE.exists():connector.BASE.mkdir(mode=0o750);os.chown(connector.BASE,0,991)
        pending=connector.BASE/'pending.json'
        if pending.exists() and json.loads(connector.read(pending))!=config:raise ValueError('Resume the same pending service connector or disable it before preparing another')
        connector.write(pending,json.dumps(config),mode=0o600)
        connector.write(connector.BASE/'disabled.json',json.dumps({'reason':'connector-configuration-in-progress'}),mode=0o600)
        try:
            subprocess.run(['/bin/systemctl','stop','rdc-service-proxy.service','rdc-synapse.service'],check=True,capture_output=True,timeout=120)
            connector.write(connector.BASE/'configuration.json',json.dumps(config))
            connector.write(connector.BASE/'synapse.json',connector.synapse(config,now=int(time.time())))
            connector.write(connector.BASE/'Caddyfile',connector.proxy((runtime.BASE/'Caddyfile').read_text(),config))
            # No shell snippets or arbitrary directives are accepted. Validate the
            # generated native proxy config before its listener can be started.
            # The pinned Caddy executable carries cap_net_bind_service=ep; Linux
            # refuses exec itself when that file capability is outside the bound.
            # Keep its one required capability even for offline validation.
            image=settings['components']['proxy']['image']
            subprocess.run(['/usr/bin/podman','--runtime=/usr/bin/runc','run','--rm','--network=none','--read-only','--cap-drop=ALL','--cap-add=NET_BIND_SERVICE','--security-opt=no-new-privileges',
                '--tmpfs','/config:rw,nosuid,nodev,size=16m','--tmpfs','/data:rw,nosuid,nodev,size=16m',
                '--volume',str(connector.BASE/'Caddyfile')+':/etc/caddy/Caddyfile:ro','--volume',str(runtime.TLS)+':/tls:ro',
                image,'caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'],check=True,capture_output=True,timeout=60)
            pending.unlink();(connector.BASE/'disabled.json').unlink()
            restart(settings)
        except BaseException:
            connector.write(pending,json.dumps(config),mode=0o600)
            connector.write(connector.BASE/'disabled.json',json.dumps({'reason':'connector-activation-failed'}),mode=0o600)
            try:restart(settings)
            except BaseException:pass
            raise
    return {'state':'matrix-connector-configured','peers':config['peers'],'application_federation':'not-verified',
            'recovery':'Application restore suspends this connector until current partnerships are reviewed again.'}


def disable():
    from backup_operations import require_platform
    from service_certificates import operation_lock
    import service_runtime as runtime
    require_platform()
    with operation_lock():
        settings=runtime.read_settings()
        if connector.configured(settings) is None:return {'state':'connector-not-installed'}
        connector.write(connector.BASE/'disabled.json',json.dumps({'reason':'operator-disabled'}),mode=0o600)
        restart(settings)
        pending=connector.BASE/'pending.json'
        if pending.exists():pending.unlink()
    return {'state':'connector-disabled','internal_service':'listeners-verified'}


def action(args):
    from backup_operations import require_platform
    from regional_operations import imported,interactive
    import service_runtime as runtime
    require_platform();settings=runtime.read_settings();command=args.regional_service_action
    if command=='status':
        current=connector.configured(settings)
        return {'state':'connector-not-installed' if current is None else ('connector-configured' if connector.active(settings) else 'connector-suspended'),
                'application_federation':'not-verified','configuration':current,
                'recovery':'Reapply a currently reviewed public service-link document after restoration.'}
    if command=='disable':return disable()
    if command!='attach':raise ValueError('Unsupported application connector action')
    interactive();bundle=imported(args.document)
    identity=bundle.get('gateway_identity')
    fingerprint=agreements.fingerprint(identity)
    current=connector.configured(settings)
    if current is not None:expected=current['gateway_fingerprint']
    else:
        print('This is your institution approval identity: '+fingerprint)
        expected=input('Enter the full fingerprint independently confirmed from your administrator workspace: ').strip()
    candidate=prepare(bundle,settings,expected_fingerprint=expected,now=int(time.time()))
    print(json.dumps(candidate,indent=2))
    print('This briefly restarts chat and its HTTPS proxy. Internal network identity and application data remain owned by this service. Regional exchange still needs a real test.')
    if input('Type ATTACH to configure this Matrix gateway connection: ').strip()!='ATTACH':return {'state':'cancelled'}
    return configure(bundle,expected_fingerprint=expected)

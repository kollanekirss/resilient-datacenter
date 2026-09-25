#!/usr/bin/python3
"""Root-managed Matrix container runtime. Fixed commands, paths and ownership checks."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time

BASE=Path('/etc/rdc-services')
STATE=Path('/var/lib/rdc-services')
TLS=Path('/etc/rdc-service-tls/active')
INSTALLED=Path('/usr/local/lib/rdc-services')
UNITS={'postgres':'rdc-postgres','synapse':'rdc-synapse','element':'rdc-element','proxy':'rdc-service-proxy'}
if __name__=='__main__':sys.path.insert(0,str(INSTALLED))


def root_json(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>65536: raise ValueError('Unsafe service administration file')
    return json.loads(path.read_text())


def read_settings():
    if os.geteuid()!=0 or sys.platform!='linux': raise ValueError('Service runtime requires its managed Linux server')
    data=root_json(BASE/'runtime.json');owner=root_json(BASE/'ownership.json')
    if set(data)!={'schema_version','ownership','bind_address','components'} or data['schema_version']!=1 or data['ownership']!=owner: raise ValueError('Service runtime ownership mismatch')
    if owner.get('role')!='services' or owner.get('packages')!=['matrix'] or owner.get('network')!=root_json(Path('/etc/server-connectivity-profile.json')): raise ValueError('Service/network installation identity changed')
    pins=root_json(INSTALLED/'service_images.json')
    if pins.get('schema_version')!=1 or data['components']!=pins.get('components') or set(data['components'])!=set(UNITS): raise ValueError('Service component catalogue changed')
    address=ipaddress.ip_address(data['bind_address'])
    if owner['network'].get('role')=='portable':
        from application_access import validate_binding
        validate_binding(owner['network'],data['bind_address'])
    elif address.version!=4 or address not in ipaddress.ip_network('100.64.0.0/10'): raise ValueError('Invalid service overlay address')
    for name in ('matrix_hostname','element_hostname'):
        if not isinstance(owner.get(name),str) or not re.fullmatch('[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]',owner[name]): raise ValueError('Invalid service hostname')
    return data


def owner_digest(settings):
    return hashlib.sha256(json.dumps(settings['ownership'],sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_container(record,name,settings):
    labels=record.get('Config',{}).get('Labels') or {}
    actual=str(record.get('Image','')).removeprefix('sha256:')
    if labels.get('org.rdc.owner')!=owner_digest(settings) or labels.get('org.rdc.component')!=name or actual!=settings['components'][name]['config_digest'].removeprefix('sha256:'):
        raise ValueError('Existing container is not owned by this exact service installation')


def podman(*args,timeout=30):
    result=subprocess.run(['/usr/bin/podman',*args],check=True,capture_output=True,text=True,timeout=timeout)
    if len(result.stdout)>2*1024*1024: raise ValueError('Container response is oversized')
    return result.stdout


def inspect_container(name,settings):
    if name not in UNITS: raise ValueError('Unsupported service component')
    result=subprocess.run(['/usr/bin/podman','container','exists',UNITS[name]],capture_output=True,timeout=15)
    if result.returncode==1:return None
    if result.returncode!=0: raise ValueError('Cannot inspect service container existence')
    try:records=json.loads(podman('container','inspect',UNITS[name]))
    except subprocess.CalledProcessError:
        # --rm cleanup can remove a stopped container between existence and
        # inspection. Only verified absence is benign; retain all other errors.
        remaining=subprocess.run(['/usr/bin/podman','container','exists',UNITS[name]],capture_output=True,timeout=15)
        if remaining.returncode==1:return None
        raise
    if not isinstance(records,list) or len(records)!=1: raise ValueError('Cannot identify one service container')
    validate_container(records[0],name,settings)
    return records[0]


def verify_image(name,settings):
    records=json.loads(podman('image','inspect',settings['components'][name]['image']))
    if len(records)!=1: raise ValueError('Cannot identify one pinned service image')
    image=records[0]
    if (image.get('Architecture')!='amd64' or image.get('Os')!='linux' or
        str(image.get('Id','')).removeprefix('sha256:')!=settings['components'][name]['config_digest'].removeprefix('sha256:')):
        raise ValueError('Installed container image differs from the reviewed component')


def container_command(name,settings):
    if name not in UNITS: raise ValueError('Unsupported service component')
    common=['/usr/bin/podman','--runtime=/usr/bin/runc','run','--name',UNITS[name],'--network=host','--pull=never','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=512',
            '--label','org.rdc.owner='+owner_digest(settings),'--label','org.rdc.component='+name,
            '--tmpfs','/tmp:rw,nosuid,nodev,size=64m,mode=1777']
    image=settings['components'][name]['image']
    import service_regional
    regional=service_regional.active(settings) if name in ('synapse','proxy') else None
    if name=='postgres':
        return common+['--user=999:999','--memory=512m','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777',
                       '--volume',str(STATE/'postgres')+':/var/lib/postgresql/data:rw',
                       '--volume',str(BASE/'database-password')+':/run/secrets/database-password:ro',
                       '--env','POSTGRES_USER=synapse','--env','POSTGRES_DB=synapse',
                       '--env','POSTGRES_PASSWORD_FILE=/run/secrets/database-password',
                       '--env','POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=C',image,
                       'postgres','-c','listen_addresses=127.0.0.1','-c','port=5433','-c','max_connections=50','-c','shared_buffers=128MB']
    if name=='synapse':
        extra=[]
        if regional:extra=['--volume',str(service_regional.BASE)+':/regional:ro','--volume','/etc/ssl/certs:/etc/ssl/certs:ro','--env','SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt']
        arguments=['run','--config-path','/config/homeserver.yaml','--config-path','/regional/synapse.json'] if regional else []
        return common+extra+['--user=991:991','--memory=2g','--volume',str(STATE/'synapse')+':/data:rw',
                       '--volume',str(BASE/'synapse')+':/config:ro','--env','SYNAPSE_CONFIG_PATH=/config/homeserver.yaml',
                       '--env','PYTHONDONTWRITEBYTECODE=1',image]+arguments
    if name=='element':
        return common+['--memory=256m','--entrypoint=nginx',
                       '--volume',str(BASE/'element.json')+':/app/config.json:ro',
                       '--volume',str(BASE/'element-nginx.conf')+':/etc/nginx/nginx.conf:ro',image,'-g','daemon off;']
    return common+['--memory=256m','--cap-add=NET_BIND_SERVICE','--tmpfs','/config:rw,nosuid,nodev,size=16m',
                   '--tmpfs','/data:rw,nosuid,nodev,size=16m','--volume',str((service_regional.BASE if regional else BASE)/'Caddyfile')+':/etc/caddy/Caddyfile:ro',
                   '--volume',str(TLS)+':/tls:ro',image]


def ingress_entries(address,*,network=None):
    import ipaddress
    ip=ipaddress.ip_address(address)
    portable=network is not None and network.get('role')=='portable'
    if portable:
        from application_access import validate_binding
        validate_binding(network,address)
    elif ip.version!=4 or ip not in ipaddress.ip_network('100.64.0.0/10'):raise ValueError('Invalid application ingress address')
    table='rdc_application'
    def match(left,right,op='=='):return {'match':{'op':op,'left':left,'right':right}}
    return [{'table':{'family':'inet','name':table,'comment':'rdc-application-ingress-v1'}},
            {'chain':{'family':'inet','table':table,'name':'input','type':'filter','hook':'input','prio':-150,'policy':'accept'}},
            {'rule':{'family':'inet','table':table,'chain':'input','expr':[
                match({'meta':{'key':'iifname'}},'lo','!='),
                (match({'payload':{'protocol':'ip','field':'saddr'}},network['access']['frontend_address'],'!=') if portable else match({'meta':{'key':'iifname'}},'tailscale0','!=')),
                match({'payload':{'protocol':'ip','field':'daddr'}},str(ip)),
                match({'payload':{'protocol':'tcp','field':'dport'}},443),{'drop':None}]}}]


def validate_ingress(data,address,*,network=None):
    def normalize(value):
        if isinstance(value,dict):return {k:normalize(v) for k,v in value.items() if k!='handle'}
        if isinstance(value,list):return [normalize(v) for v in value]
        return value
    if not isinstance(data,dict) or set(data)!={'nftables'} or not isinstance(data['nftables'],list):raise ValueError('Cannot verify application ingress')
    entries=[normalize(e) for e in data['nftables'] if not isinstance(e,dict) or 'metainfo' not in e]
    if entries!=ingress_entries(address,network=network):raise ValueError('Application ingress rules differ; administrator review required')


def ingress_nft(*args,input=None):
    result=subprocess.run(['/usr/sbin/nft',*args],input=input,capture_output=True,text=True,check=True,timeout=15)
    return json.loads(result.stdout) if result.stdout.strip() else None


def application_ingress(settings,*,create=False):
    address=settings['bind_address'];network=settings.get('ownership',{}).get('network');entries=ingress_entries(address,network=network)
    tables=ingress_nft('-j','list','tables')
    exists=any(e.get('table',{}).get('family')=='inet' and e['table'].get('name')=='rdc_application' for e in tables['nftables'])
    if not exists:
        if not create:raise ValueError('Application ingress protection is missing; restart the owned proxy')
        # Exclusive create and all rules in one atomic batch. Never flush an
        # existing table or override another firewall's drop decision.
        commands=[{'create':entries[0]},*({'add':entry} for entry in entries[1:])]
        ingress_nft('-j','-f','-',input=json.dumps({'nftables':commands}))
    validate_ingress(ingress_nft('-j','list','table','inet','rdc_application'),address,network=network)


def unit(name,*,network=None):
    if name not in UNITS: raise ValueError('Unsupported component')
    dependencies={'postgres':[],'synapse':['rdc-postgres.service'],'element':[],
                  'proxy':['rdc-synapse.service','rdc-element.service','tailscaled.service']}[name]
    if network is not None and network.get('role')=='portable':
        from application_access import validate_portable_owner
        validate_portable_owner(network)
        dependencies=[v for v in dependencies if v!='tailscaled.service']
    text='[Unit]\nDescription=RDC '+name+' service\nPartOf=rdc-services.target\nAfter=network-online.target'
    if dependencies:text+=' '+' '.join(dependencies)+'\nRequires='+' '.join(dependencies)
    text+='\n[Service]\nType=simple\n'
    for action,directive in [('run','ExecStart'),('ready','ExecStartPost'),('stop','ExecStop')]:
        text+=directive+'=/usr/bin/python3 -I -B /usr/local/lib/rdc-services/service_runtime.py '+action+' '+name+'\n'
    return text+'Restart=on-failure\nRestartSec=5\nTimeoutStartSec=180\nTimeoutStopSec=90\nUMask=0077\n[Install]\nWantedBy=rdc-services.target\n'


def http_json(path,*,port=8008):
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
    try:
        connection.request('GET',path);response=connection.getresponse();body=response.read(1024*1024)
        if response.status!=200: raise ValueError('Service HTTP readiness failed')
        return json.loads(body)
    finally:connection.close()


def verify_https(settings):
    # Verify system trust, hostname and the exact selected leaf certificate.
    cert=subprocess.run(['/usr/bin/openssl','x509','-in',str(TLS/'tls.crt'),'-outform','DER'],check=True,capture_output=True,timeout=10).stdout
    fingerprint=hashlib.sha256(cert).digest()
    for name in ('matrix_hostname','element_hostname'):
        with socket.create_connection((settings['bind_address'],443),timeout=3) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=settings['ownership'][name]) as connection:
                if hashlib.sha256(connection.getpeercert(binary_form=True)).digest()!=fingerprint: raise ValueError('Service is not serving its selected certificate')


def ready(name,settings,*,attempts=90):
    last=None
    for attempt in range(attempts):
        try:
            record=inspect_container(name,settings)
            if record is None or not record.get('State',{}).get('Running'): raise ValueError('Container is not running')
            if name=='postgres':podman('exec',UNITS[name],'pg_isready','-h','127.0.0.1','-p','5433','-U','synapse','-d','synapse',timeout=5)
            elif name=='synapse':
                data=http_json('/_synapse/admin/v1/server_version')
                if data.get('server_version')!=settings['components'][name]['version']: raise ValueError('Unexpected running Synapse version')
            elif name=='element':
                data=http_json('/config.json',port=8082)
                if data!=root_json(BASE/'element.json'): raise ValueError('Element is not serving its owned configuration')
            else:application_ingress(settings);verify_https(settings)
            return
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            last=error
            if attempt<attempts-1:time.sleep(1)
    raise ValueError('Service did not reach verified readiness') from last


def main():
    phase='arguments'
    try:
        if len(sys.argv)!=3 or sys.argv[1] not in ('run','ready','stop') or sys.argv[2] not in UNITS: raise ValueError('Unsupported runtime action')
        action,name=sys.argv[1:];phase='read-settings';settings=read_settings()
        if action=='ready':
            phase='readiness';ready(name,settings);return 0
        phase='inspect-container';existing=inspect_container(name,settings)
        if action=='stop':
            if existing is not None:
                phase='stop-container';podman('stop','--time','45',UNITS[name],timeout=60)
            return 0
        phase='verify-image';verify_image(name,settings)
        if name=='proxy':
            phase='private-ingress';application_ingress(settings,create=True)
        if existing is not None:
            if existing.get('State',{}).get('Running'):
                return subprocess.run(['/usr/bin/podman','attach',UNITS[name]]).returncode
            phase='remove-stopped-container';podman('rm',UNITS[name])  # Exact owned stopped container; persistent bind data stays.
        phase='prepare-regional-connector'
        if name in ('synapse','proxy'):
            import service_regional
            if service_regional.BASE.exists() or service_regional.BASE.is_symlink():
                service_regional.materialize(settings,(BASE/'Caddyfile').read_text())
        phase='launch-container'
        return subprocess.run(container_command(name,settings)).returncode
    except Exception as error:
        detail=' exit='+str(error.returncode) if isinstance(error,subprocess.CalledProcessError) else ''
        print('RDC runtime phase='+phase+' error='+type(error).__name__+detail,file=sys.stderr)
        print('RDC application service action failed. Inspect its local journal, ownership, image identity and configuration; no unowned container was replaced.',file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())

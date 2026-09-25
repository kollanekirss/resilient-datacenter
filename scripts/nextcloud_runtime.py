#!/usr/bin/python3
"""Fixed Nextcloud container lifecycle and private local maintenance entry points."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

if __name__=='__main__':sys.path.insert(0,'/usr/local/lib/rdc-nextcloud')
from service_runtime import root_json,owner_digest,validate_container,verify_image,podman

BASE=Path('/etc/rdc-nextcloud')
STATE=Path('/var/lib/rdc-nextcloud')
APP=Path('/opt/rdc-nextcloud-app')
TLS=Path('/etc/rdc-nextcloud-tls/active')
INSTALLED=Path('/usr/local/lib/rdc-nextcloud')
UNITS={'postgres':'rdc-nextcloud-postgres','nextcloud':'rdc-nextcloud','proxy':'rdc-nextcloud-proxy'}


def read_settings():
    if os.geteuid()!=0 or sys.platform!='linux':raise ValueError('Use the owned Linux file-service node')
    settings=root_json(BASE/'runtime.json');owner=root_json(BASE/'ownership.json')
    if set(settings)!={'schema_version','ownership','bind_address','components'} or settings['schema_version']!=1 or settings['ownership']!=owner:
        raise ValueError('File-service runtime ownership differs')
    if owner.get('role')!='services' or owner.get('packages')!=['nextcloud'] or owner.get('network')!=root_json(Path('/etc/server-connectivity-profile.json')):
        raise ValueError('File-service network/package identity differs')
    pins=root_json(INSTALLED/'nextcloud_images.json')
    if pins.get('schema_version')!=1 or settings['components']!=pins.get('components') or set(settings['components'])!=set(UNITS):raise ValueError('File-service component catalogue differs')
    if ipaddress.ip_address(settings['bind_address']) not in ipaddress.ip_network('100.64.0.0/10'):raise ValueError('Invalid file-service overlay address')
    return settings


def inspect_container(name,settings):
    if name not in UNITS:raise ValueError('Unknown file-service component')
    found=subprocess.run(['/usr/bin/podman','container','exists',UNITS[name]],capture_output=True,timeout=15)
    if found.returncode==1:return None
    if found.returncode!=0:raise ValueError('Cannot inspect file-service container')
    records=json.loads(podman('container','inspect',UNITS[name]))
    if not isinstance(records,list) or len(records)!=1:raise ValueError('Cannot identify file-service container')
    validate_container(records[0],name,settings)
    return records[0]


def common(settings):
    return ['/usr/bin/podman','--runtime=/usr/bin/runc','run','--network=host','--pull=never','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=512',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=128m,mode=1777']


def container_command(name,settings):
    if name not in UNITS:raise ValueError('Unknown file-service component')
    command=common(settings)+['--name',UNITS[name],'--label','org.rdc.owner='+owner_digest(settings),
                              '--label','org.rdc.component='+name]
    image=settings['components'][name]['image']
    if name=='postgres':
        return command+['--user=999:999','--memory=512m','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777',
                        '--volume',str(STATE/'postgres')+':/var/lib/postgresql/data:rw',
                        '--volume',str(BASE/'database-password')+':/run/secrets/database-password:ro',
                        '--env','POSTGRES_USER=nextcloud','--env','POSTGRES_DB=nextcloud',
                        '--env','POSTGRES_PASSWORD_FILE=/run/secrets/database-password',
                        '--env','POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=C',image,
                        'postgres','-c','listen_addresses=127.0.0.1','-c','port=5434','-c','max_connections=50','-c','shared_buffers=128MB']
    if name=='nextcloud':
        return command+['--user=33:33','--memory=2g','--entrypoint=apache2-foreground',
                        '--tmpfs','/var/run/apache2:rw,nosuid,nodev,size=16m,mode=1777',
                        '--tmpfs','/var/lock/apache2:rw,nosuid,nodev,size=16m,mode=1777',
                        '--volume',str(APP)+':/var/www/html:ro','--volume',str(BASE/'config')+':/var/www/html/config:ro',
                        '--volume',str(STATE/'files')+':/var/www/data:rw',
                        '--volume',str(BASE/'ports.conf')+':/etc/apache2/ports.conf:ro',
                        '--volume',str(BASE/'site.conf')+':/etc/apache2/sites-enabled/000-default.conf:ro',image]
    return command+['--memory=256m','--cap-add=NET_BIND_SERVICE','--tmpfs','/config:rw,nosuid,nodev,size=16m',
                    '--tmpfs','/data:rw,nosuid,nodev,size=16m','--volume',str(BASE/'Caddyfile')+':/etc/caddy/Caddyfile:ro',
                    '--volume',str(TLS)+':/tls:ro',image]


def maintenance_command(settings,action):
    # Secrets arrive over stdin and become PHP-local arguments, never OS argv.
    prefix='$d=json_decode(file_get_contents("php://stdin"),true,512,JSON_THROW_ON_ERROR);'
    if action=='install':
        code=prefix+'$argv=["occ","maintenance:install","--no-interaction","--database=pgsql","--database-host=127.0.0.1","--database-port=5434","--database-name=nextcloud","--database-user=nextcloud","--database-pass=".$d["database_password"],"--admin-user=".$d["admin_user"],"--admin-pass=".$d["admin_password"],"--data-dir=/var/www/data"];'
    elif action=='account':
        code=prefix+'putenv("OC_PASS=".$d["password"]);$argv=["occ","user:add","--password-from-env","--no-interaction",$d["username"]];'
    else:raise ValueError('Unsupported private file-service maintenance operation')
    code+='$_SERVER["argv"]=$argv;require "/var/www/html/occ";'
    if action=='account':return ['/usr/bin/podman','exec','--interactive','--user','33:33',UNITS['nextcloud'],'php','-r',code]
    return common(settings)+['--rm','--interactive','--user=33:33','--entrypoint=php',
                             '--volume',str(APP)+':/var/www/html:rw','--volume',str(STATE/'files')+':/var/www/data:rw',
                             settings['components']['nextcloud']['image'],'-r',code]


def unit(name):
    dependencies={'postgres':[],'nextcloud':['rdc-nextcloud-postgres.service'],'proxy':['rdc-nextcloud.service','tailscaled.service']}[name]
    text='[Unit]\nDescription=RDC file-service '+name+'\nPartOf=rdc-nextcloud.target\nAfter=network-online.target'
    if dependencies:text+=' '+' '.join(dependencies)+'\nRequires='+' '.join(dependencies)
    text+='\n[Service]\nType=simple\n'
    for action,directive in [('run','ExecStart'),('ready','ExecStartPost'),('stop','ExecStop')]:
        text+=directive+'=/usr/bin/python3 -I -B /usr/local/lib/rdc-nextcloud/nextcloud_runtime.py '+action+' '+name+'\n'
    return text+'Restart=on-failure\nRestartSec=5\nTimeoutStartSec=180\nTimeoutStopSec=90\nUMask=0077\n'


def verify_https(settings):
    expected=subprocess.run(['/usr/bin/openssl','x509','-in',str(TLS/'tls.crt'),'-outform','DER'],check=True,capture_output=True,timeout=10).stdout
    with socket.create_connection((settings['bind_address'],443),timeout=3) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=settings['ownership']['nextcloud_hostname']) as secured:
            if hashlib.sha256(secured.getpeercert(binary_form=True)).digest()!=hashlib.sha256(expected).digest():raise ValueError('File-service TLS fingerprint differs')


def ready(name,settings,*,attempts=90):
    for attempt in range(attempts):
        try:
            record=inspect_container(name,settings)
            if record is None or not record.get('State',{}).get('Running'):raise ValueError('File-service container is not running')
            if name=='postgres':podman('exec',UNITS[name],'pg_isready','-h','127.0.0.1','-p','5434','-U','nextcloud','-d','nextcloud',timeout=5)
            elif name=='nextcloud':
                connection=http.client.HTTPConnection('127.0.0.1',8083,timeout=3)
                try:
                    connection.request('GET','/status.php',headers={'Host':settings['ownership']['nextcloud_hostname']})
                    response=connection.getresponse();data=json.loads(response.read(65536))
                    if response.status!=200 or data.get('installed') is not True or data.get('maintenance') or data.get('needsDbUpgrade') or data.get('versionstring')!=settings['components'][name]['version']:
                        raise ValueError('Nextcloud application readiness failed')
                finally:connection.close()
            else:verify_https(settings)
            return
        except (OSError,ValueError,subprocess.SubprocessError):
            if attempt==attempts-1:raise ValueError('File service did not reach verified readiness') from None
            time.sleep(1)


def main():
    phase='arguments'
    try:
        if len(sys.argv)!=3 or sys.argv[1] not in ('run','ready','stop') or sys.argv[2] not in UNITS:raise ValueError('Unsupported file-service action')
        action,name=sys.argv[1:];phase='settings';settings=read_settings()
        if action=='ready':phase='readiness';ready(name,settings);return 0
        phase='inspect';existing=inspect_container(name,settings)
        if action=='stop':
            if existing is not None:podman('stop','--time','45',UNITS[name],timeout=60)
            return 0
        phase='image';verify_image(name,settings)
        if existing is not None:
            if existing.get('State',{}).get('Running'):return subprocess.run(['/usr/bin/podman','attach',UNITS[name]]).returncode
            phase='remove';podman('rm',UNITS[name])
        phase='launch';return subprocess.run(container_command(name,settings)).returncode
    except Exception as error:
        print('RDC file-service failure phase='+phase+' error='+type(error).__name__+'. Review local service state; no unowned resource was adopted.',file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())

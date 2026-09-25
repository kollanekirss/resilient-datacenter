"""Fixed file-service configuration; data values never become PHP source."""
import base64
import ipaddress
import json
import re
from nextcloud_contracts import validate

IDENTITY_FIELDS={'instanceid','passwordsalt','secret','version','dbpassword','dbuser','installed','data_fingerprint'}


def configuration_values(profile,identity):
    if validate(profile):raise ValueError('Invalid Nextcloud profile')
    if not isinstance(identity,dict) or set(identity)!=IDENTITY_FIELDS or identity['installed'] is not True:
        raise ValueError('Unexpected Nextcloud instance identity')
    if not isinstance(identity['data_fingerprint'],str) or not re.fullmatch('[a-f0-9]{32}',identity['data_fingerprint']):raise ValueError('Invalid client recovery fingerprint')
    if identity['dbuser']!='oc_admin':raise ValueError('Unexpected application database account')
    if not re.fullmatch(r'[a-zA-Z0-9]{8,32}',identity['instanceid']) or not re.fullmatch(r'35\.0\.[01]\.\d+',identity['version']):raise ValueError('Unsupported Nextcloud identity/version')
    for key in ('passwordsalt','secret','dbpassword'):
        if not isinstance(identity[key],str) or not 20<=len(identity[key])<=512 or any(ord(c)<32 for c in identity[key]):raise ValueError('Invalid Nextcloud secret shape')
    return dict({k:v for k,v in identity.items() if k!='data_fingerprint'},**{'data-fingerprint':identity['data_fingerprint']},dbtype='pgsql',dbname='nextcloud',dbhost='127.0.0.1:5434',dbtableprefix='oc_',
                datadirectory='/var/www/data',trusted_domains=[profile['nextcloud_hostname']],trusted_proxies=['127.0.0.1'],
                overwritehost=profile['nextcloud_hostname'],overwriteprotocol='https',**{'overwrite.cli.url':'https://'+profile['nextcloud_hostname']},
                config_is_read_only=True,appstoreenabled=False,upgrade_disable_web=True,updatechecker=False,has_internet_connection=False,
                log_type='file',logfile='/var/www/data/nextcloud.log',loglevel=2,maintenance=False,
                **{'memcache.local':'\\OC\\Memcache\\APCu','maintenance_window_start':2,
                   'sharing.enable_share_mail':False,'allow_local_remote_servers':False,
                   'apps_paths':[{'path':'/var/www/html/apps','url':'/apps','writable':False}],
                   'filelocking.enabled':True})


def application_config(profile,identity):
    encoded=base64.b64encode(json.dumps(configuration_values(profile,identity),sort_keys=True,separators=(',',':')).encode()).decode()
    return '<?php\n$CONFIG = json_decode(base64_decode("'+encoded+'"), true, 512, JSON_THROW_ON_ERROR);\n'


def apache_ports():return 'Listen 127.0.0.1:8083\n'


def apache_site():
    return '<VirtualHost 127.0.0.1:8083>\nDocumentRoot /var/www/html\nErrorLog /dev/stderr\nCustomLog /dev/null combined\n<Directory /var/www/html>\nRequire all granted\nAllowOverride All\nOptions FollowSymLinks\n</Directory>\n</VirtualHost>\n'


def proxy(profile,address):
    if validate(profile) or ipaddress.ip_address(address) not in ipaddress.ip_network('100.64.0.0/10'):raise ValueError('Invalid private file-service endpoint')
    return ('{\n admin off\n auto_https off\n servers {\n  protocols h1 h2\n }\n}\nhttps://'+profile['nextcloud_hostname']+' {\n bind '+address+'\n tls /tls/tls.crt /tls/tls.key\n'
            ' header Strict-Transport-Security "max-age=15552000"\n'
            ' redir /.well-known/carddav /remote.php/dav/ 301\n redir /.well-known/caldav /remote.php/dav/ 301\n'
            ' reverse_proxy 127.0.0.1:8083 {\n  header_up X-Real-IP {remote_host}\n }\n}\n')

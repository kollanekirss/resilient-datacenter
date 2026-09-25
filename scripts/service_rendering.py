"""Fixed Matrix package configuration; only validated identities and generated secrets vary."""
import ipaddress
import json
import re
import yaml
from service_contracts import validate


def checked(profile):
    if validate(profile): raise ValueError('Invalid Matrix service profile')


def synapse(profile,secrets):
    checked(profile)
    if set(secrets)!={'database_password','registration_secret','macaroon_secret','form_secret'} or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in secrets.values()):
        raise ValueError('Service secrets must be freshly generated private random values')
    config={'server_name':profile['matrix_hostname'],'public_baseurl':'https://'+profile['matrix_hostname']+'/',
            'pid_file':'/data/synapse.pid','report_stats':False,'enable_registration':False,'allow_guest_access':False,
            'federation_domain_whitelist':[],'trusted_key_servers':[],'url_preview_enabled':False,
            'registration_shared_secret':secrets['registration_secret'],'macaroon_secret_key':secrets['macaroon_secret'],
            'form_secret':secrets['form_secret'],'signing_key_path':'/data/server.signing.key',
            'media_store_path':'/data/media','max_upload_size':'20M','log_config':'/config/log.config',
            'listeners':[{'port':8008,'type':'http','tls':False,'bind_addresses':['127.0.0.1'],'x_forwarded':True,
                          'resources':[{'names':['client','federation'],'compress':False}]}],
            'database':{'name':'psycopg2','args':{'user':'synapse','password':secrets['database_password'],'database':'synapse',
                                              'host':'127.0.0.1','port':5433,'cp_min':5,'cp_max':10}}}
    return yaml.safe_dump(config,sort_keys=False)


def logging_config():
    return yaml.safe_dump({'version':1,'formatters':{'plain':{'format':'%(asctime)s %(levelname)s %(name)s %(message)s'}},
                           'handlers':{'console':{'class':'logging.StreamHandler','formatter':'plain'}},
                           'root':{'level':'WARNING','handlers':['console']},'disable_existing_loggers':False})


def element(profile):
    checked(profile)
    return json.dumps({'default_server_config':{'m.homeserver':{'base_url':'https://'+profile['matrix_hostname'],'server_name':profile['matrix_hostname']}},
                       'disable_custom_urls':True,'disable_guests':True,'brand':'Element',
                       'integrations_ui_url':'','integrations_rest_url':'','integrations_widgets_urls':[],
                       'show_labs_settings':False,'default_theme':'light'},indent=2)+'\n'


def element_nginx():
    # Bypass the image's templating entry point: its default listener is public
    # when host networking is used. Keep static assets on loopback only.
    return '''pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;
    server {
        listen 127.0.0.1:8082;
        root /app;
        location / { try_files $uri $uri/ /index.html; }
        location = /config.json { add_header Cache-Control "no-store"; }
    }
}
'''


def proxy(profile,address):
    checked(profile)
    ip=ipaddress.ip_address(address)
    if ip.version!=4 or ip not in ipaddress.ip_network('100.64.0.0/10'): raise ValueError('Service HTTPS must bind to the verified overlay IPv4')
    common='    bind '+str(ip)+'\n    tls /tls/tls.crt /tls/tls.key\n    header X-Content-Type-Options nosniff\n    header Referrer-Policy no-referrer\n'
    discovery=json.dumps({'m.homeserver':{'base_url':'https://'+profile['matrix_hostname']}},separators=(',',':'))
    return ('{\n    admin off\n    auto_https off\n    servers {\n        protocols h1 h2\n    }\n}\n'
            'https://'+profile['matrix_hostname']+' {\n'+common+
            '    handle /.well-known/matrix/client {\n        header Content-Type application/json\n        header Access-Control-Allow-Origin *\n        respond `'+discovery+'`\n    }\n'
            '    handle /_matrix/client/* {\n        reverse_proxy 127.0.0.1:8008\n    }\n'
            '    handle /_matrix/media/* {\n        reverse_proxy 127.0.0.1:8008\n    }\n'
            '    handle {\n        respond "Not exposed by this service package" 404\n    }\n}\n'
            'https://'+profile['element_hostname']+' {\n'+common+
            '    reverse_proxy 127.0.0.1:8082\n}\n')

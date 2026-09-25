"""Fixed NGINX and firewall rendering for one portable frontend VM."""
import copy
import hashlib
import ipaddress
import json
import re
from application_access import _private_address

FIELDS={'schema_version','site_sha256','settings_sha256','address','administrator_address','staff_cidr','dns_address','services','certificate_days'}
TLS='/etc/rdc-frontend/tls/active'


def validate(config):
    if type(config) is not dict or set(config)!=FIELDS:raise ValueError('Unsupported frontend configuration')
    if type(config['schema_version']) is not int or config['schema_version']!=1:raise ValueError('Unsupported frontend schema')
    for key in ('site_sha256','settings_sha256'):
        if type(config[key]) is not str or not re.fullmatch('[a-f0-9]{64}',config[key]):raise ValueError('Invalid frontend plan binding')
    for key in ('address','administrator_address','dns_address'):_private_address(config[key])
    net=ipaddress.ip_network(config['staff_cidr'],strict=True)
    if net.version!=4 or not 16<=net.prefixlen<=28:raise ValueError('Invalid staff subnet')
    _private_address(str(net.network_address));_private_address(str(net.broadcast_address))
    if len({config[k] for k in ('address','administrator_address','dns_address')})!=3:raise ValueError('Frontend addresses must be distinct')
    if any(ipaddress.ip_address(config[k]) in net for k in ('address','administrator_address','dns_address')):raise ValueError('Staff and service addresses overlap')
    if type(config['certificate_days']) is not int or not 2<=config['certificate_days']<=4015:raise ValueError('Invalid certificate coverage')
    services=config['services'];names=set()
    if type(services) is not dict or set(services)!={'chat','element','files'}:raise ValueError('Unexpected frontend services')
    for item in services.values():
        if type(item) is not dict or set(item)!={'hostname','address'}:raise ValueError('Invalid frontend backend')
        _private_address(item['address'])
        if item['address'] in (config['address'],config['administrator_address'],config['dns_address']) or ipaddress.ip_address(item['address']) in net:raise ValueError('Invalid backend placement')
        name=item['hostname']
        if (type(name) is not str or len(name)>253 or '.' not in name or name.replace('.','').isdigit()
            or not all(re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in name.split('.'))):raise ValueError('Invalid frontend hostname')
        if name in names:raise ValueError('Frontend names must be distinct')
        names.add(name)
    if services['chat']['address']!=services['element']['address'] or services['chat']['address']==services['files']['address']:raise ValueError('Use separate chat and files VMs')
    return copy.deepcopy(config)


def configuration(plan,settings):
    from portable_network import derive
    policy=derive(plan,settings)
    return validate({'schema_version':1,'site_sha256':policy['site_sha256'],'settings_sha256':policy['settings_sha256'],
        'address':plan['vms']['nginx']['address'],'administrator_address':settings['administrator_address'],
        'staff_cidr':plan['networks']['staff']['cidr'],'dns_address':plan['vms']['dns']['address'],
        'certificate_days':plan['offline_days']+plan['certificate_margin_days'],
        'services':{role:{'hostname':host,'address':plan['vms']['chat' if role=='element' else role]['address']} for role,host in plan['domains'].items()}})


def nginx(config):
    c=validate(config);address=c['address']
    text='''user www-data;
worker_processes auto;
pid /run/rdc-frontend/nginx.pid;
error_log stderr warn;
events { worker_connections 1024; }
http {
    access_log off;
    server_tokens off;
    client_body_temp_path /var/lib/rdc-frontend/body;
    proxy_temp_path /var/lib/rdc-frontend/proxy;
    ssl_protocols TLSv1.2 TLSv1.3;
    proxy_http_version 1.1;
    proxy_connect_timeout 5s;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 4;
    proxy_ssl_server_name on;
    proxy_ssl_trusted_certificate /etc/rdc-frontend/tls/active/backend-ca.crt;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Forwarded "";
    proxy_set_header X-Forwarded-Host "";
    proxy_set_header Connection "";
'''
    text+='    proxy_bind '+address+';\n    server {\n        listen '+address+':443 ssl default_server;\n        ssl_reject_handshake on;\n        return 444;\n    }\n'
    for role,item in c['services'].items():
        host=item['hostname']
        text+='    server {\n        listen '+address+':443 ssl;\n        server_name '+host+';\n'
        text+='        if ($ssl_server_name != $host) { return 421; }\n'
        text+='        ssl_certificate '+TLS+'/'+role+'.crt;\n        ssl_certificate_key '+TLS+'/'+role+'.key;\n'
        text+='        client_max_body_size '+('512m' if role=='files' else '20m')+';\n'
        text+='        proxy_ssl_name '+host+';\n        proxy_set_header Host '+host+';\n'
        # Repeat headers here: nginx inherits proxy_set_header only when none
        # are declared at the current level.
        text+='        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_set_header Forwarded "";\n        proxy_set_header X-Forwarded-Host "";\n        proxy_set_header Connection "";\n'
        text+='        location / { proxy_pass https://'+item['address']+'; }\n    }\n'
    return text+'}\n'


def firewall(config):
    c=validate(config);table='rdc_frontend'
    digest=hashlib.sha256(json.dumps(c,sort_keys=True).encode()).hexdigest()
    entries=[{'table':{'family':'inet','name':table,'comment':'rdc-frontend:'+digest}}]
    for name in ('input','output','forward'):
        entries.append({'chain':{'family':'inet','table':table,'name':name,'type':'filter','hook':name,'prio':-160,'policy':'drop'}})
    def match(left,right):return {'match':{'op':'==','left':left,'right':right}}
    def payload(protocol,field):return {'payload':{'protocol':protocol,'field':field}}
    def rule(chain,*expressions):entries.append({'rule':{'family':'inet','table':table,'chain':chain,'expr':[*expressions,{'accept':None}]}})
    for chain,iface in (('input','iifname'),('output','oifname')):
        rule(chain,match({'meta':{'key':iface}},'lo'))
        rule(chain,match({'ct':{'key':'state'}},{'set':['established','related']}))
    subnet=ipaddress.ip_network(c['staff_cidr'])
    for source,ports in (({'prefix':{'addr':str(subnet.network_address),'len':subnet.prefixlen}},[443]),(c['administrator_address'],[22,443])):
        rule('input',match(payload('ip','saddr'),source),match(payload('tcp','dport'),(ports[0] if len(ports)==1 else {'set':ports})))
    # ICMP errors (including path MTU) are covered by related; permit local
    # diagnostic echo only from the administrator.
    rule('input',match(payload('ip','saddr'),c['administrator_address']),match(payload('icmp','type'),'echo-request'))
    for address in sorted({s['address'] for s in c['services'].values()}):
        rule('output',match(payload('ip','daddr'),address),match(payload('tcp','dport'),443))
    for protocol,ports in (('udp',[53,123]),('tcp',[53])):
        rule('output',match(payload('ip','daddr'),c['dns_address']),match(payload(protocol,'dport'),(ports[0] if len(ports)==1 else {'set':ports})))
    return entries

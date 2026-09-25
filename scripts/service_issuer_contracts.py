"""Non-executable DNS-01 certificate request; credentials are always separate."""
import re
from profile_config import _identifier,_safe_values
from validate_inventory import hostname

BASE='/etc/rdc-service-acme'
FIELDS={'kind','schema_version','provider','institution_id','node_name','matrix_hostname','element_hostname','acme_email','acme_agree_terms'}


def validate(data):
    if not isinstance(data,dict) or set(data)!=FIELDS or not _safe_values(data):return ['Use only the documented certificate request fields; credentials and commands are forbidden.']
    errors=[]
    if data['kind']!='service-certificates' or type(data['schema_version']) is not int or data['schema_version']!=1 or data['provider']!='cloudflare':errors.append('Unsupported certificate provider contract.')
    if not all(_identifier(data[k]) for k in ('institution_id','node_name')):errors.append('Invalid node identity.')
    if not all(hostname(data[k]) for k in ('matrix_hostname','element_hostname')) or data['matrix_hostname']==data['element_hostname']:errors.append('Provide distinct Matrix and Element DNS names.')
    if not isinstance(data['acme_email'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+%-]{0,126}@[A-Za-z0-9][A-Za-z0-9.-]{0,251}\.[A-Za-z]{2,63}',data['acme_email']):errors.append('Provide a valid certificate account email.')
    if data['acme_agree_terms'] is not True:errors.append('Explicit acceptance of the certificate issuer terms is required.')
    return errors


def credential_text(token):
    if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{20,512}',token):raise ValueError('Provide the restricted Cloudflare API token without whitespace or configuration text')
    return 'dns_cloudflare_api_token = '+token+'\n'


def common_command():
    return ['/usr/bin/certbot','--config',BASE+'/cli.ini','--config-dir',BASE+'/certbot',
            '--work-dir',BASE+'/work','--logs-dir',BASE+'/logs','--non-interactive','--no-directory-hooks',
            '--server','https://acme-v02.api.letsencrypt.org/directory','--cert-name','rdc-services']


def issue_command(profile):
    if validate(profile):raise ValueError('Invalid service certificate request')
    return common_command()+['certonly','--dns-cloudflare','--dns-cloudflare-credentials',BASE+'/cloudflare.ini',
                             '--dns-cloudflare-propagation-seconds','60','--email',profile['acme_email'],'--agree-tos',
                             '-d',profile['matrix_hostname'],'-d',profile['element_hostname']]


def renew_command():return common_command()+['renew']


def validate_renewal(text):
    import configparser
    parser=configparser.RawConfigParser(strict=True)
    try:parser.read_string('[lineage]\n'+text)
    except configparser.Error:raise ValueError('Invalid certificate renewal configuration') from None
    if 'renewalparams' not in parser:raise ValueError('Missing certificate renewal parameters')
    params=parser['renewalparams']
    if params.get('authenticator')!='dns-cloudflare' or params.get('server')!='https://acme-v02.api.letsencrypt.org/directory' or params.get('dns_cloudflare_credentials')!=BASE+'/cloudflare.ini':
        raise ValueError('Certificate renewal provider identity changed')
    for name in ('cert','privkey','chain','fullchain'):
        if parser['lineage'].get(name)!=BASE+'/certbot/live/rdc-services/'+name+'.pem':raise ValueError('Certificate renewal path changed')
    if parser['lineage'].get('archive_dir',BASE+'/certbot/archive/rdc-services')!=BASE+'/certbot/archive/rdc-services':raise ValueError('Certificate archive changed')
    for name,suffix in (('config_dir','certbot'),('work_dir','work'),('logs_dir','logs')):
        if params.get(name,BASE+'/'+suffix)!=BASE+'/'+suffix:raise ValueError('Certificate renewal workspace changed')
    for section in parser.values():
        for name,value in section.items():
            if (name.endswith('_hook') or name=='installer') and value.lower() not in ('','none'):raise ValueError('Unreviewed certificate renewal hooks or installer')
            if name in ('no_verify_ssl','break_my_certs','staging','dry_run') and value.lower() not in ('false','none','0',''):raise ValueError('Certificate renewal validation was weakened')

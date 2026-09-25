import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def profile():
    return {'kind':'service-certificates','schema_version':1,'provider':'cloudflare','institution_id':'south','node_name':'home-services',
            'matrix_hostname':'matrix.pilot.test','element_hostname':'chat.pilot.test','acme_email':'owner@pilot.test','acme_agree_terms':True}


def test_issuer_profile_requires_provider_consent_and_fixed_names():
    m=importlib.import_module('service_issuer_contracts');assert m.validate(profile())==[]
    for change in ({'acme_agree_terms':False},{'provider':'shell'},{'token':'secret'},
                   {'element_hostname':'matrix.pilot.test'},{'acme_email':'--config=/tmp/other'},{'acme_server':'https://other.test'}):
        assert m.validate(dict(profile(),**change))


def test_issuer_commands_use_fixed_acme_and_private_token_file():
    m=importlib.import_module('service_issuer_contracts')
    command=m.issue_command(profile())
    assert command[0]=='/usr/bin/certbot' and 'certonly' in command
    assert '--dns-cloudflare' in command and '--standalone' not in command
    assert command[command.index('--server')+1]=='https://acme-v02.api.letsencrypt.org/directory'
    assert command[command.index('--dns-cloudflare-credentials')+1]=='/etc/rdc-service-acme/cloudflare.ini'
    assert command.count('-d')==2 and '--no-directory-hooks' in command
    assert '--config-dir' in command and '--work-dir' in command and '--logs-dir' in command
    assert not any('token=' in part for part in command)


@pytest.mark.parametrize('token',['','a\nother=value','a'*1025,';curl example.org'])
def test_token_rejects_ini_injection(token):
    m=importlib.import_module('service_issuer_contracts')
    with pytest.raises(ValueError):m.credential_text(token)


def renewal():
    base='/etc/rdc-service-acme/certbot'
    return ''.join(name+' = '+base+'/live/rdc-services/'+name+'.pem\n' for name in ('cert','privkey','chain','fullchain'))+'[renewalparams]\nauthenticator = dns-cloudflare\nserver = https://acme-v02.api.letsencrypt.org/directory\ndns_cloudflare_credentials = /etc/rdc-service-acme/cloudflare.ini\n'


def test_renewal_rejects_hooks_changed_provider_and_external_paths():
    m=importlib.import_module('service_issuer_contracts');m.validate_renewal(renewal())
    for bad in (renewal()+'deploy_hook = shell-command\n',renewal().replace('authenticator = dns-cloudflare','authenticator = manual'),
                renewal().replace('/live/rdc-services/cert.pem','/live/other/cert.pem'),renewal().replace('https://acme-v02.api.letsencrypt.org/directory','https://other.test')):
        with pytest.raises(ValueError):m.validate_renewal(bad)

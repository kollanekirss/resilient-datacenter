import importlib
import json
import yaml
from test_service_contracts import profile


def api():return importlib.import_module('service_rendering')
SECRETS={'database_password':'a'*64,'registration_secret':'b'*64,'macaroon_secret':'c'*64,'form_secret':'d'*64}


def test_synapse_is_local_only_and_denies_unapproved_accounts_and_federation():
    config=yaml.safe_load(api().synapse(profile(),SECRETS))
    assert config['server_name']=='matrix.south.test'
    assert config['enable_registration'] is False and config['allow_guest_access'] is False
    assert config['federation_domain_whitelist']==[] and config['trusted_key_servers']==[]
    assert config['database']['name']=='psycopg2' and config['database']['args']['host']=='127.0.0.1'
    assert all(l['bind_addresses']==['127.0.0.1'] for l in config['listeners'])
    assert config['signing_key_path']=='/data/server.signing.key'


def test_element_uses_only_this_homeserver_without_external_integrations():
    config=json.loads(api().element(profile()))
    assert config['default_server_config']['m.homeserver']['base_url']=='https://matrix.south.test'
    assert config['disable_custom_urls'] is True and config['disable_guests'] is True
    assert config['integrations_ui_url']=='' and config['integrations_widgets_urls']==[]


def test_proxy_binds_only_overlay_and_excludes_admin_and_federation_routes():
    text=api().proxy(profile(),'100.64.0.22')
    assert 'bind 100.64.0.22' in text and 'admin off' in text
    assert '/_matrix/client/*' in text and '/_matrix/media/*' in text
    assert '/_synapse' not in text and '/_matrix/federation' not in text
    assert '0.0.0.0' not in text
    import pytest
    with pytest.raises(ValueError):api().proxy(profile(),'0.0.0.0')


def test_internal_element_listener_is_loopback_even_with_host_networking():
    text=api().element_nginx()
    assert 'listen 127.0.0.1:8082;' in text
    assert 'listen 80;' not in text

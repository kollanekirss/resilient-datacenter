import importlib
import json
import base64
import re
import pytest
from test_nextcloud_runtime import settings


def configuration():
    return {'schema_version':1,'package':'nextcloud','application_owner':settings()['ownership'],
            'gateway_fingerprint':'a'*64,'gateway_lan_address':'10.203.1.1','service_lan_address':'10.203.1.20','lan_subnet':'10.203.1.0/24',
            'peers':[{'hostname':'files.partner.test','expires_at':1800003600}]}


def test_file_connector_keeps_identity_and_routes_all_outbound_http_through_fixed_gateway():
    m=importlib.import_module('nextcloud_regional');config=configuration();m.validate(config,settings())
    def values(text):return json.loads(base64.b64decode(re.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)',text)[1]))
    active=values(m.php_overlay(config));closed=values(m.php_overlay(None))
    assert active['proxy']=='http://10.203.1.1:3128' and active['proxyexclude']==[]
    assert active['sharing.federation.allowSelfSignedCertificates'] is False
    assert active['allow_local_remote_servers'] is False
    # Pinned Nextcloud otherwise resolves/rejects private partner addresses
    # before the exact-destination proxy ever receives a CONNECT request.
    assert active['dns_pinning'] is False
    assert closed['dns_pinning'] is True
    assert closed['proxy']=='http://127.0.0.1:9' and closed['proxyexclude']==[]
    assert not {'instanceid','secret','dbpassword','trusted_domains'} & active.keys()
    for change in ({'gateway_lan_address':'169.254.169.254'},{'package':'matrix'},{'peers':[{'hostname':'https://outside.test/path','expires_at':1800003600}]}):
        with pytest.raises(ValueError):m.validate(dict(config,**change),settings())


def test_file_connector_route_catalogue_excludes_general_dav_login_and_admin():
    m=importlib.import_module('nextcloud_regional');config=configuration()
    text=m.proxy('original internal configuration\n',config)
    assert text.startswith('original internal configuration\n') and 'bind 10.203.1.20' in text
    assert 'remote_ip 10.203.1.1' in text and '/public' in text
    assert '/remote.php/dav' not in text and '/login' not in text and '/settings' not in text
    from regional_http import nextcloud_allowed
    for method,path in [('GET','/.well-known/ocm'),('POST','/index.php/ocm/shares'),('POST','/index.php/apps/cloud_federation_api/api/v1/access-token'),('PROPFIND','/public.php/webdav/folder')]:
        assert nextcloud_allowed(method,path)
    for method,path in [('GET','/remote.php/dav/files/admin'),('GET','/index.php/login'),('POST','/ocs/v2.php/cloud/users'),('DELETE','/.well-known/ocm'),('GET','/public.php/webdav-bypass'),('GET','/public.php/webdav/../settings')]:
        assert not nextcloud_allowed(method,path)


def test_restore_or_missing_connector_uses_closed_outbound_policy(tmp_path,monkeypatch):
    m=importlib.import_module('nextcloud_regional');base=tmp_path/'regional';base.mkdir(mode=0o750)
    monkeypatch.setattr(m,'BASE',base);pending=tmp_path/'restore';monkeypatch.setattr(m,'RESTORE',pending)
    m.materialize(settings(),'internal config',b'original private identity')
    assert '127.0.0.1:9' in base64.b64decode(re.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)',(base/'runtime-config/zz-regional.config.php').read_text())[1]).decode()
    assert (base/'runtime-config/config.php').read_bytes()==b'original private identity'
    assert (base/'runtime-config/config.php').stat().st_mode & 0o777 == 0o400
    m.write(base/'configuration.json',json.dumps(configuration()))
    pending.write_text('{}');m.materialize(settings(),'internal config')
    pending.unlink();assert m.active(settings()) is None
    assert (base/'disabled.json').exists()
    assert (base/'Caddyfile').read_text()=='internal config'


def test_file_runtime_always_mounts_generated_proxy_policy_and_synchronizes_share_controls(tmp_path,monkeypatch):
    runtime=importlib.import_module('nextcloud_runtime');m=importlib.import_module('nextcloud_regional')
    monkeypatch.setattr(m,'BASE',tmp_path/'connector')
    command=runtime.container_command('nextcloud',settings())
    assert str(m.BASE/'runtime-config')+':/var/www/html/config:ro' in command
    assert '/etc/ssl/certs:/etc/ssl/certs:ro' in command
    controls=m.controls(None)
    assert controls['incoming_server2server_share_enabled']=='no'
    assert controls['outgoing_server2server_share_enabled']=='no'
    enabled=m.controls(configuration())
    assert enabled['incoming_server2server_share_enabled']=='yes'
    assert enabled['outgoing_server2server_share_enabled']=='yes'
    assert enabled['incoming_server2server_group_share_enabled']=='no'
    assert enabled['federatedTrustedShareAutoAccept']=='no'
    command=runtime.regional_controls_command(settings(),None)
    assert '--network=host' in command and '--user=33:33' in command
    assert '--entrypoint=php' in command and '--interactive' in command
    assert 'php://stdin' in command[-1]


def test_private_runtime_umask_does_not_hide_configuration_from_application_group(tmp_path,monkeypatch):
    import os
    import stat
    m=importlib.import_module('nextcloud_regional')
    monkeypatch.setattr(m,'BASE',tmp_path/'connector');monkeypatch.setattr(m,'RESTORE',tmp_path/'absent')
    monkeypatch.setattr(m.os,'chown',lambda *args:None)
    previous=os.umask(0o077)
    try:m.materialize(settings(),'original',b'private identity')
    finally:os.umask(previous)
    assert stat.S_IMODE(m.BASE.stat().st_mode)==0o750
    assert stat.S_IMODE((m.BASE/'runtime-config').stat().st_mode)==0o750

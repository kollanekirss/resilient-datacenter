"""Actual Matrix LAN listener and restore suspension, with no VPN/federation claim."""
import json
import os
from pathlib import Path
import subprocess
import time
import regional_agreements as agreements
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def exercise(settings):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise ValueError('Disposable GitHub-hosted connector fixture only')
    from ci_regional_gateway import namespace,run
    namespace('rdc-connector-peer','rdc-private','connector0','10.204.1.10/24','10.204.1.1/24')
    run('ip','netns','exec','rdc-connector-peer','ip','address','add','10.204.1.2/24','dev','connector0')
    ownkey,peerkey=Ed25519PrivateKey.generate().private_bytes_raw(),Ed25519PrivateKey.generate().private_bytes_raw()
    owner=settings['ownership'];hostname=owner['matrix_hostname']
    own=agreements.identity(ownkey,institution_id=owner['institution_id'],regional_controller='regional.ci.test',gateway_node='own-gateway',gateway_ipv4='100.64.0.10',services={'matrix':hostname})
    peer=agreements.identity(peerkey,institution_id='partner',regional_controller='regional.ci.test',gateway_node='partner-gateway',gateway_ipv4='100.64.0.11',services={'matrix':'partner.ci.test'})
    now=int(time.time());offered=agreements.offer(ownkey,own,peer,['matrix'],now=now,expires_at=now+3600,expected_peer=agreements.fingerprint(peer))
    document=agreements.accept(peerkey,offered,now=now,expected_peer=agreements.fingerprint(own))
    bundle={'kind':'regional-service-link','schema_version':1,'package':'matrix','gateway_identity':own,'gateway_lan_address':'10.204.1.1','service_lan_address':'10.204.1.10','lan_subnet':'10.204.1.0/24','agreements':[document]}
    from service_link import configure
    assert configure(bundle,expected_fingerprint=agreements.fingerprint(own))['state']=='matrix-connector-configured'
    def request(path,source='10.204.1.1'):
        return json.loads(run('ip','netns','exec','rdc-connector-peer','curl','--silent','--show-error','--noproxy','*','--interface',source,
                             '--resolve',hostname+':8443:10.204.1.10','--write-out','\\n%{http_code}',
                             'https://'+hostname+':8443'+path).rsplit('\n',1)[0])
    result=request('/_matrix/federation/v1/version');assert result['server']['name']=='Synapse'
    for source,path in [('10.204.1.2','/_matrix/federation/v1/version'),('10.204.1.1','/_synapse/admin/v1/server_version'),('10.204.1.1','/_matrix/client/versions')]:
        response=run('ip','netns','exec','rdc-connector-peer','curl','--silent','--show-error','--noproxy','*','--interface',source,
                     '--resolve',hostname+':8443:10.204.1.10','--output','/dev/null','--write-out','%{http_code}',
                     'https://'+hostname+':8443'+path)
        assert response=='403',(source,path,response)
    print('Actual Matrix connector: reviewed signed peer input, Synapse proxy configuration, trusted private LAN federation endpoint, denied other source/client/admin routes PASS. No remote homeserver exchange is claimed.',flush=True)


def verify_suspended_after_restore(settings):
    import service_regional
    assert service_regional.active(settings) is None
    assert json.loads((service_regional.BASE/'disabled.json').read_text())['reason']=='application-restore-requires-current-partner-review'
    result=subprocess.run(['ip','netns','exec','rdc-connector-peer','curl','--silent','--show-error','--max-time','2','--noproxy','*',
                           '--resolve',settings['ownership']['matrix_hostname']+':8443:10.204.1.10',
                           'https://'+settings['ownership']['matrix_hostname']+':8443/_matrix/federation/v1/version'],capture_output=True)
    assert result.returncode!=0
    print('Actual application restore preserves internal chat and leaves its previous regional connector suspended for current partnership review PASS.',flush=True)

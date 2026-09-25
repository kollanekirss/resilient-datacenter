#!/usr/bin/env python3
"""Actual file-service acceptance on a fresh disposable Ubuntu runner only."""
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from setup_contracts import local_ownership
import nextcloud_runtime as runtime
from nextcloud_operations import install_or_resume,maintenance

HOST='files.ci.test'
ADDRESS='100.64.0.23'


def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():
        raise SystemExit('Use only a disposable GitHub-hosted Ubuntu 24.04 runner')
    if Path('/etc/server-connectivity-profile.json').exists():raise ValueError('File-service fixture requires a fresh runner')
    subprocess.run(['ip','address','add',ADDRESS+'/32','dev','lo'],check=True)
    with Path('/etc/hosts').open('a') as stream:stream.write('\n'+ADDRESS+' '+HOST+'\n')
    from ci_matrix_backup import prepare_network
    prepare_network()  # Explicit transport stub; no real VPN claim.
    network=local_ownership({'kind':'local-node','schema_version':1,'institution_id':'ci','node_name':'files','headscale_hostname':'control.ci.test','node_tag':'tag:files'})
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps(network))
    import ci_matrix_services as certificate_fixture
    certificate_fixture.MATRIX=HOST;certificate_fixture.ELEMENT='unused.ci.test'
    from ci_matrix_backup import prepare_backup,snapshot,restore
    network_snapshot=prepare_backup(network)
    cert,key=certificate_fixture.certificates()
    profile={'kind':'nextcloud-services','schema_version':1,'institution_id':'ci','node_name':'files','nextcloud_hostname':HOST,
             'tls_mode':'supplied','tls_certificate':str(cert),'tls_private_key':str(key)}
    alice_password=secrets.token_urlsafe(24);bob_password=secrets.token_urlsafe(24)
    assert install_or_resume(profile,network,ADDRESS,'cialice',alice_password)['state']=='file-service-listeners-verified'
    settings=runtime.read_settings()
    for component in runtime.UNITS:
        record=runtime.inspect_container(component,settings)
        confinement=(Path('/proc')/str(record['State']['Pid'])/'attr/current').read_text()
        assert 'containers-default-' in confinement and '(enforce)' in confinement
    maintenance(settings,'account',{'username':'cibob','password':bob_password})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def request(method,path,data=None,*,username='cialice',password=alice_password,form=False):
        headers={'Authorization':'Basic '+base64.b64encode((username+':'+password).encode()).decode()}
        if form:headers.update({'OCS-APIRequest':'true','Content-Type':'application/x-www-form-urlencoded'})
        if isinstance(data,dict):data=urllib.parse.urlencode(data).encode()
        with opener.open(urllib.request.Request('https://'+HOST+path,data=data,headers=headers,method=method),timeout=60) as response:
            return response.status,response.read(1024*1024)
    def denied(path,**kwargs):
        try:request('GET',path,**kwargs)
        except urllib.error.HTTPError as error:assert error.code in (401,403,404)
        else:raise AssertionError('Unapproved file access succeeded')
    content=b'Disposable resilient file proof '+os.urandom(128)
    path='/remote.php/dav/files/cialice/proof.txt'
    assert request('PUT',path,content)[0]==201
    assert request('GET',path)[1]==content
    denied(path,username='cibob',password=bob_password)
    share_path='/ocs/v2.php/apps/files_sharing/api/v1/shares'
    # These requests must fail locally before remote exchange or link creation.
    for forbidden in ({'shareType':'6','shareWith':'unapproved@partner.invalid'},{'shareType':'3'}):
        try:
            _,denial=request('POST',share_path+'?format=json',{'path':'/proof.txt','permissions':'1',**forbidden},form=True)
        except urllib.error.HTTPError as error:
            assert error.code in (400,403)
        else:
            assert json.loads(denial)['ocs']['meta']['status']=='failure'
    code,body=request('POST',share_path+'?format=json',{'path':'/proof.txt','shareType':'0','shareWith':'cibob','permissions':'1'},form=True)
    result=json.loads(body)['ocs'];assert result['meta']['status']=='ok'
    shared=result['data'];target=shared['file_target']
    assert request('GET','/remote.php/dav/files/cibob'+urllib.parse.quote(target),username='cibob',password=bob_password)[1]==content
    request('DELETE',share_path+'/'+str(shared['id'])+'?format=json',form=True)
    denied('/remote.php/dav/files/cibob'+urllib.parse.quote(target),username='cibob',password=bob_password)
    subprocess.run(['systemctl','start','rdc-nextcloud-cron.service'],check=True,timeout=300)
    assert install_or_resume(profile,network,ADDRESS,'unused','unused')['state']=='file-service-listeners-verified'
    assert request('GET',path)[1]==content
    apps=json.loads(runtime.podman('exec','--user','33:33',runtime.UNITS['nextcloud'],'php','occ','app:list','--output=json'))
    assert 'federation' not in apps['enabled']
    from nextcloud_operations import federation_status
    assert federation_status()=='disabled'
    print('Actual Nextcloud: trusted HTTPS, pinned confined containers, two accounts, exact file round trip, unauthorized access denial, approved share and revocation, background jobs and repeated installation PASS.',flush=True)
    identity_before=json.loads((runtime.BASE/'identity.json').read_text())
    selected=snapshot(network_snapshot)
    request('PUT',path,b'Later changes that must not replace the selected backup')
    request('PUT','/remote.php/dav/files/cialice/later.txt',b'Created after snapshot')
    restore(selected)
    assert request('GET',path)[1]==content
    denied('/remote.php/dav/files/cialice/later.txt')
    identity_after=json.loads((runtime.BASE/'identity.json').read_text())
    assert identity_before['data_fingerprint']!=identity_after['data_fingerprint']
    assert {k:v for k,v in identity_before.items() if k!='data_fingerprint'}=={k:v for k,v in identity_after.items() if k!='data_fingerprint'}
    assert request('PROPFIND','/remote.php/dav/files/cibob/',username='cibob',password=bob_password)[0]==207
    print('Actual encrypted scheduled Nextcloud snapshot and fenced restore preserve file bytes, application identity and accounts, remove later files and refresh the client recovery fingerprint PASS.',flush=True)

    from ci_element_browser import session
    from playwright.sync_api import expect
    with session() as page:
        page.goto('https://'+HOST+'/index.php/login')
        page.locator('input[name="user"]').fill('cialice')
        page.locator('input[name="password"]').fill(alice_password)
        page.get_by_role('button',name='Log in',exact=True).click()
        page.wait_for_url('**/apps/**')
        page.goto('https://'+HOST+'/index.php/apps/files/')
        expect(page.get_by_text('proof.txt',exact=True).first).to_be_visible()

    from certificate_lifecycle import activate,ActivationError
    from nextcloud_certificates import Runtime as CertificateRuntime,BASE as CERTBASE
    selected_certificate=(runtime.TLS/'tls.crt').read_bytes()
    class FailedActivation(CertificateRuntime):
        def __init__(self,settings):super().__init__(settings);self.first=True
        def verify(self,hostname,fingerprint):
            super().verify(hostname,fingerprint)
            if self.first:self.first=False;raise ValueError('Injected failure after new file-service HTTPS verification')
    replacement_cert,replacement_key=certificate_fixture.certificates()
    try:
        activate(CERTBASE,HOST,'nextcloud',replacement_cert.read_bytes(),replacement_key.read_bytes(),gid=0,runtime=FailedActivation(settings))
    except ActivationError as error:assert error.recovered
    else:raise AssertionError('Failed file-service TLS activation was reported as success')
    assert (runtime.TLS/'tls.crt').read_bytes()==selected_certificate
    runtime.verify_https(settings)
    print('Actual file-service TLS activation failure restored and verified the previous live certificate PASS.',flush=True)
    from ci_service_issuer import exercise as issuer_exercise
    issuer_exercise(certificate_fixture.certificates,package='nextcloud')
    print('Actual Nextcloud browser login and uploaded file visibility PASS. Real VPN/home NAT and physical offsite placement NOT RUN.',flush=True)

if __name__=='__main__':
    try:main()
    finally:
        from ci_nextcloud_diagnostics import report
        report(runtime.STATE/'files/nextcloud.log')

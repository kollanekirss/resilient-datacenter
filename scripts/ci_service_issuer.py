"""Frozen issuer timer acceptance; DNS/ACME boundary is explicitly simulated."""
import json
import os
from pathlib import Path
import subprocess
import service_issuer as issuer
from service_issuer_contracts import renew_command


def exercise(certificate_factory):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Issuer fixture requires a disposable GitHub-hosted runner')
    if issuer.BASE.exists() or issuer.RUNTIME.exists():raise ValueError('Issuer fixture requires fresh owned paths')
    profile={'kind':'service-certificates','schema_version':1,'provider':'cloudflare','institution_id':'ci','node_name':'services',
             'matrix_hostname':'matrix.ci.test','element_hostname':'chat.ci.test','acme_email':'ci@example.test','acme_agree_terms':True}
    issuer.directory(issuer.BASE)
    network=json.loads(Path('/etc/server-connectivity-profile.json').read_text())
    issuer.write(issuer.BASE/'configuration.json',json.dumps({'schema_version':1,'profile':profile,'network':network}))
    issuer.write(issuer.BASE/'cloudflare.ini','dns_cloudflare_api_token = '+'c'*40+'\n');issuer.write(issuer.BASE/'cli.ini','')
    for relative in ('certbot','certbot/archive','certbot/archive/rdc-services','certbot/live','certbot/live/rdc-services','certbot/renewal','work','logs','issued'):
        issuer.directory(issuer.BASE/relative)
    renewal=''.join(name+' = /etc/rdc-service-acme/certbot/live/rdc-services/'+name+'.pem\n' for name in ('cert','privkey','chain','fullchain'))
    renewal+='[renewalparams]\nauthenticator = dns-cloudflare\nserver = https://acme-v02.api.letsencrypt.org/directory\ndns_cloudflare_credentials = /etc/rdc-service-acme/cloudflare.ini\n'
    issuer.write(issuer.BASE/'certbot/renewal/rdc-services.conf',renewal)
    archive=issuer.BASE/'certbot/archive/rdc-services';live=issuer.BASE/'certbot/live/rdc-services'
    for source,name in [('tls.crt','fullchain1.pem'),('tls.key','privkey1.pem')]:
        issuer.write(archive/name,Path('/etc/rdc-service-tls/active',source).read_bytes())
    (live/'fullchain.pem').symlink_to('../../archive/rdc-services/fullchain1.pem')
    (live/'privkey.pem').symlink_to('../../archive/rdc-services/privkey1.pem')
    # Never contact a public CA or DNS API with CI fixtures. Only this disposable
    # runner replaces the external issuer executable. Production has no bypass.
    certbot=Path('/usr/bin/certbot');saved=Path('/root/rdc-ci-original-certbot')
    if saved.exists():raise ValueError('Unexpected retained CI issuer')
    if certbot.exists():certbot.rename(saved)
    failure=Path('/root/rdc-ci-issuer-failure');called=Path('/root/rdc-ci-issuer-command.json')
    certbot.write_text('#!/usr/bin/python3\nimport json,sys\nfrom pathlib import Path\nPath("/root/rdc-ci-issuer-command.json").write_text(json.dumps(sys.argv))\nsys.exit(1 if Path("/root/rdc-ci-issuer-failure").exists() else 0)\n');certbot.chmod(0o755)
    try:
        assert issuer.enable()['state']=='certificate-renewal-enabled'
        # A new trusted leaf is supplied at the controlled external boundary.
        cert,key=certificate_factory()
        issuer.write(archive/'fullchain1.pem',cert.read_bytes(),replace=True);issuer.write(archive/'privkey1.pem',key.read_bytes(),replace=True)
        subprocess.run(['systemctl','start','rdc-service-certificate.service'],check=True,timeout=240)
        assert json.loads(called.read_text())==renew_command()
        status=issuer.status()
        assert status['state']=='active' and status['automatic_renewal'] and status['serving_verified'] and not status['expires_within_14_days']
        selected=Path('/etc/rdc-service-tls/active/tls.crt').read_bytes()
        assert selected==cert.read_bytes()
        failure.write_text('simulate provider outage')
        result=subprocess.run(['systemctl','start','rdc-service-certificate.service'],capture_output=True,timeout=240)
        assert result.returncode!=0
        status=issuer.status();assert status['state']=='renewal-failed' and status['serving_verified']
        assert Path('/etc/rdc-service-tls/active/tls.crt').read_bytes()==selected
        print('Frozen private-service issuer timer: actual new HTTPS activation, independent expiry status and simulated provider failure retaining the current certificate PASS. Public DNS/ACME issuance NOT RUN.',flush=True)
    finally:
        subprocess.run(['systemctl','disable','--now','rdc-service-certificate.timer'],capture_output=True,timeout=30)
        certbot.unlink(missing_ok=True)
        if saved.exists():saved.rename(certbot)

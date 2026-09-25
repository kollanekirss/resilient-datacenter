#!/usr/bin/env python3
"""Destructive disposable-runner acceptance only; refuses ordinary workstations."""
from datetime import datetime,timedelta,timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from jinja2 import Environment,FileSystemLoader,StrictUndefined
import certificate_lifecycle as lifecycle

ROOT=Path(__file__).resolve().parents[1]
HOST='control.ci.test'


def run(argv,**kwargs): return subprocess.run(argv,check=True,timeout=120,**kwargs)


def download(url,path,digest):
    with urllib.request.urlopen(url,timeout=60) as source: content=source.read(150*1024*1024)
    if hashlib.sha256(content).hexdigest()!=digest: raise ValueError('Pinned binary checksum mismatch')
    path.write_bytes(content)


def main():
    if (os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
        or platform.system()!='Linux' or platform.machine()!='x86_64' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text()):
        raise SystemExit('This integration test is restricted to disposable GitHub-hosted Ubuntu 24.04 amd64 runners.')
    if len(sys.argv)!=2 or sys.argv[1] not in lifecycle.SERVICES: raise SystemExit('Select controller or relay')
    role=sys.argv[1]; service,group=lifecycle.SERVICES[role]
    for path in ('/etc/rdc-tls','/etc/server-connectivity-profile.json','/etc/headscale','/etc/sc-derp','/etc/letsencrypt/live/rdc-managed'):
        if Path(path).exists(): raise SystemExit('Test target is not fresh: '+path)
    run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',group])
    gid=grp.getgrnam(group).gr_gid
    rootkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable RDC CI CA')])
    now=datetime.now(timezone.utc)
    ca=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(rootkey.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
        .sign(rootkey,hashes.SHA256()))
    Path('/usr/local/share/ca-certificates/rdc-disposable-ci.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    run(['update-ca-certificates'],stdout=subprocess.DEVNULL)
    def issue():
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,HOST)]))
            .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=60))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(rootkey,hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM),key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    base=lifecycle.BASE; base.mkdir(mode=0o750); os.chown(base,0,gid)
    Path('/etc/server-connectivity-profile.json').write_text(json.dumps({'schema_version':3,'deployment_mode':'independent','institution_id':'ci','role':role,'controller_hostname':HOST,'tls_mode':'managed-acme','certificate_hostname':HOST}))
    (base/'config.json').write_text(json.dumps({'schema_version':1,'hostname':HOST,'role':role,'institution_id':'ci','controller_hostname':HOST}))
    cert,key=issue()
    info=lifecycle.activate(base,HOST,role,cert,key,gid=gid,initial=True)
    assert info['state']=='staged'
    environment=Environment(loader=FileSystemLoader(ROOT/'roles'),undefined=StrictUndefined)
    with tempfile.TemporaryDirectory(prefix='rdc-service-ci-') as directory:
        temporary=Path(directory)
        if role=='controller':
            package=temporary/'headscale.deb'
            download('https://github.com/juanfont/headscale/releases/download/v0.29.4/headscale_0.29.4_linux_amd64.deb',package,'1f65364716ae1fcc3845b1a65a47583469022e9c6f194dfdfeb25403f89f0841')
            run(['dpkg-deb','--extract',str(package),str(temporary/'package')])
            binary=Path('/usr/bin/headscale'); shutil.copyfile(temporary/'package/usr/bin/headscale',binary); binary.chmod(0o755)
            configuration=Path('/etc/headscale'); configuration.mkdir(mode=0o750); os.chown(configuration,0,gid)
            for name,content in {'config.yaml':environment.get_template('controller/templates/config.yaml.j2').render(headscale_hostname=HOST,tls_mode='managed-acme'),
                                 'policy.json':environment.get_template('controller/templates/policy.json.j2').render(profile_policy={'tagOwners':{'tag:ci-service':['lab-admin@']},'grants':[]}),
                                 'derp-map.yml':environment.get_template('controller/templates/derp-map.yml.j2').render(derp_hostname='relay.ci.test',hostvars={'relay-01':{'ansible_host':'192.0.2.2'}})}.items():
                p=configuration/name;p.write_text(content);p.chmod(0o640);os.chown(p,0,gid)
            state=Path('/var/lib/headscale'); state.mkdir(mode=0o700); shutil.chown(state,user=group,group=group)
            run(['runuser','-u',group,'--',str(binary),'configtest','--config','/etc/headscale/config.yaml'])
            unit=environment.get_template('controller/templates/headscale.service.j2').render().replace('/usr/bin/headscale',str(binary))
        else:
            binary=Path('/usr/local/bin/sc-derper')
            download('https://github.com/kollanekirss/resilient-datacenter/releases/download/v0.2.0-alpha.1/derper-linux-amd64',binary,'1ae593bc6e4d31c774538982cd6400f6503e053d6a15f9373f98aa5e141f85e5');binary.chmod(0o755)
            unit=environment.get_template('relay/templates/sc-derp.service.j2').render(derp_hostname=HOST,headscale_hostname=HOST,tls_mode='managed-acme')
        Path('/etc/systemd/system/'+service+'.service').write_text(unit)
        gate=Path('/usr/local/sbin/rdc-ci-startgate')
        gate.write_text('#!/bin/sh\nif test -f /run/rdc-ci-fail-once; then rm /run/rdc-ci-fail-once; exit 1; fi\n');gate.chmod(0o755)
        dropin=Path('/etc/systemd/system/'+service+'.service.d');dropin.mkdir()
        # The actual service remains under its normal user. + lets only this CI
        # gate remove the root-owned one-shot fault file.
        (dropin/'ci.conf').write_text('[Service]\nExecStartPre=+/usr/local/sbin/rdc-ci-startgate\nRestart=no\n')
        run(['systemctl','daemon-reload']);run(['systemctl','start',service])
        lifecycle.Runtime().verify(HOST,info['fingerprint'])
        cert2,key2=issue()
        successful=lifecycle.activate(base,HOST,role,cert2,key2,gid=gid)
        assert successful['state']=='active' and successful['fingerprint']!=info['fingerprint']
        Path('/run/rdc-ci-fail-once').touch()
        cert3,key3=issue()
        try: lifecycle.activate(base,HOST,role,cert3,key3,gid=gid)
        except lifecycle.ActivationError as error: assert error.recovered is True
        else: raise AssertionError('Injected service failure did not fail activation')
        lifecycle.Runtime().verify(HOST,successful['fingerprint'])
        assert (base/'active/tls.crt').read_bytes()==cert2
        from ci_restore_lifecycle import exercise
        exercise(role)
        run(['systemctl','stop',service])
    print(role+': actual service initial TLS, certificate replacement, failed restart and verified rollback PASS. Public ACME issuance NOT RUN.')

if __name__=='__main__': main()

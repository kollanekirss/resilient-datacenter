#!/usr/bin/env python3
"""Actual portable application + NGINX acceptance, disposable hosted Linux only.

Each job has one application VM equivalent, a separate NGINX network namespace,
a staff namespace and a same-bridge attacker. This is not Proxmox acceptance.
"""
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

ROOT=Path(__file__).resolve().parents[1]
BASE=Path('/root/rdc-portable-ci')


def run(argv,**kwargs):
    return subprocess.run([str(x) for x in argv],check=True,timeout=kwargs.pop('timeout',180),**kwargs)


def guard():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():
        raise ValueError('Use only disposable GitHub-hosted Ubuntu 24.04 runners')


def certificates(plan,role):
    import ci_matrix_services as fixture
    fixture.MATRIX=plan['domains']['chat'];fixture.ELEMENT=plan['domains']['element']
    fixture.certificates()
    ca=Path('/usr/local/share/ca-certificates/rdc-application-ci.crt').read_bytes()
    root=x509.load_pem_x509_certificate(ca)
    issuer=serialization.load_pem_private_key(Path('/root/rdc-application-ci/ca.key').read_bytes(),password=None)
    def pair(names,days=60):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
        leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,names[0])]))
              .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=days))
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
              .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(issuer,hashes.SHA256()))
        return (leaf.public_bytes(serialization.Encoding.PEM)+ca,
                key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    prepared=Path('/etc/rdc-prepared');prepared.mkdir(mode=0o700)
    names=[plan['domains'][role]]+([plan['domains']['element']] if role=='chat' else [])
    for suffix,raw in zip(('crt','key'),pair(names)):
        path=prepared/(role+'.'+suffix);path.write_bytes(raw);path.chmod(0o600)
    tls=BASE/'tls';tls.mkdir(mode=0o700)
    for name,hostname in plan['domains'].items():
        for suffix,raw in zip(('crt','key'),pair([hostname])):
            path=tls/(name+'.'+suffix);path.write_bytes(raw);path.chmod(0o600)
    (tls/'backend-ca.crt').write_bytes(ca)
    # Prove the production preparer rejects expired TLS before installation.
    from portable_application_install import coverage
    expired=pair([plan['domains'][role]],days=-1)
    try:coverage(*expired,plan['domains'][role],28)
    except ValueError:pass
    else:raise AssertionError('Expired frontend certificate was accepted')
    return tls


def network(plan,role):
    run(['ip','link','add','rdc-apps','type','bridge'])
    run(['ip','address','add',plan['vms'][role]['address']+'/24','dev','rdc-apps']);run(['ip','link','set','rdc-apps','up'])
    for name,root_ip,peer_ip,host_if in [('rdc-front','10.76.30.1/24','10.76.30.11/24','rdc-front-h'),('rdc-staff','10.76.20.1/24','10.76.20.100/24','rdc-staff-h')]:
        run(['ip','netns','add',name]);run(['ip','link','add',host_if,'type','veth','peer','name','eth0','netns',name])
        run(['ip','address','add',root_ip,'dev',host_if]);run(['ip','link','set',host_if,'up'])
        run(['ip','-n',name,'link','set','lo','up']);run(['ip','-n',name,'address','add',peer_ip,'dev','eth0']);run(['ip','-n',name,'link','set','eth0','up'])
        run(['ip','-n',name,'route','add','default','via',root_ip.split('/')[0]])
    run(['ip','netns','add','rdc-attacker']);run(['ip','link','add','rdc-attack-h','type','veth','peer','name','eth0','netns','rdc-attacker'])
    run(['ip','link','set','rdc-attack-h','master','rdc-apps']);run(['ip','link','set','rdc-attack-h','up'])
    run(['ip','-n','rdc-attacker','link','set','lo','up']);run(['ip','-n','rdc-attacker','address','add','10.76.40.200/24','dev','eth0']);run(['ip','-n','rdc-attacker','link','set','eth0','up'])
    run(['sysctl','-w','net.ipv4.ip_forward=1'],stdout=subprocess.DEVNULL)
    run(['iptables','-P','FORWARD','ACCEPT'])
    with Path('/etc/hosts').open('a') as stream:stream.write('\n10.76.30.11 '+' '.join(plan['domains'].values())+'\n')


def child_frontend():
    import portable_application_install as installer
    plan=json.loads((BASE/'site.json').read_text());settings=json.loads((BASE/'network.json').read_text())
    original=installer.frontend_unit
    # A namespace simulates the separate VM NIC. Product rendering is unchanged;
    # this CI-only systemd addition supplies the fixture's virtual network.
    installer.frontend_unit=lambda:original()+'\n[Service]\nNetworkNamespacePath=/run/netns/rdc-front\n'
    assert installer.frontend(plan,settings,BASE/'tls')['state']=='local-frontend-tls-verified'
    assert installer.frontend(plan,settings,BASE/'tls')['state']=='local-frontend-tls-verified'


def client(role,phase,namespace='rdc-staff'):
    run(['ip','netns','exec',namespace,sys.executable,ROOT/'scripts/ci_portable_client.py',role,phase],timeout=120)


def offline():
    # This brief firewall also disconnects the runner agent; its existing job
    # process continues locally and reconnects when finally removes this table.
    rules='''create table inet rdc_ci_offline
add chain inet rdc_ci_offline output { type filter hook output priority -250; policy accept; }
add chain inet rdc_ci_offline forward { type filter hook forward priority -250; policy accept; }
add rule inet rdc_ci_offline output ip daddr { 127.0.0.0/8, 10.76.0.0/16 } accept
add rule inet rdc_ci_offline output counter drop
add rule inet rdc_ci_offline forward ip daddr 10.76.0.0/16 accept
add rule inet rdc_ci_offline forward counter drop
'''
    run(['nft','-f','-'],input=rules,text=True)


def main(role):
    guard()
    if role=='frontend':child_frontend();return
    assert role in ('chat','files') and not Path('/etc/server-connectivity-profile.json').exists()
    BASE.mkdir(mode=0o700)
    plan=json.loads((ROOT/'examples/portable-site.json').read_text());plan['site']='ci';plan['recovery_site']='ci-recovery'
    plan['domains']={'chat':'matrix.ci.test','element':'element.ci.test','files':'files.ci.test'}
    settings=json.loads((ROOT/'examples/portable-network.json').read_text())
    for name,value in [('site.json',plan),('network.json',settings)]:
        (BASE/name).write_text(json.dumps(value));(BASE/name).chmod(0o600)
    network(plan,role);certificates(plan,role)
    password=secrets.token_urlsafe(24)
    (BASE/'client.json').write_text(json.dumps({'host':plan['domains'][role],'backend':plan['vms'][role]['address'],'password':password}));(BASE/'client.json').chmod(0o600)
    from portable_application_install import backend
    if role=='chat':
        backend(plan,role)
        import service_runtime as runtime
        from service_accounts import create
        create('cialice',password,admin=True)
    else:
        import builtins,getpass
        saved_input,saved_getpass=builtins.input,getpass.getpass
        builtins.input=lambda *args:'cialice';getpass.getpass=lambda *args:password
        try:backend(plan,role)
        finally:builtins.input=saved_input;getpass.getpass=saved_getpass
        import nextcloud_runtime as runtime
        # Test Nextcloud's real request-address interpretation, not an echo proxy.
        (runtime.APP/'rdc-ci-ip.php').write_text('<?php require_once __DIR__."/lib/base.php"; header("Content-Type: application/json"); echo json_encode(["client"=>\\OC::$server->getRequest()->getRemoteAddress()]);')
    run(['ip','netns','exec','rdc-front',sys.executable,__file__,'frontend'],timeout=360)
    assert not Path('/etc/systemd/system/tailscaled.service').exists()
    assert subprocess.run(['ip','link','show','tailscale0'],capture_output=True).returncode!=0
    client(role,'create');client(role,'negative');client(role,'direct','rdc-attacker')
    if role=='chat':
        # Synapse persists client addresses periodically. The forged header must
        # not win at either of the actual proxy hops.
        for attempt in range(30):
            values=runtime.podman('exec','--user','999:999',runtime.UNITS['postgres'],'psql','-At','-U','synapse','-d','synapse','-p','5433','-c',"SELECT ip FROM user_ips WHERE user_id='@cialice:matrix.ci.test'")
            if values.strip():break
            time.sleep(2)
        assert set(values.split())=={'10.76.20.100'},values
    else:(runtime.APP/'rdc-ci-ip.php').unlink()
    # Replace only the fixture's backend CA, keeping frontend trust unchanged.
    trust=Path('/etc/rdc-frontend/tls/active/backend-ca.crt');saved=trust.read_bytes()
    try:
        trust.write_bytes(Path('/etc/ssl/certs/ISRG_Root_X1.pem').read_bytes())
        run(['systemctl','restart','rdc-frontend.service'])
        client(role,'backend-untrusted')
    finally:
        trust.write_bytes(saved);run(['systemctl','restart','rdc-frontend.service'])
    print('Actual NGINX/backend TLS, source restrictions, forwarding headers, unknown host and expired-certificate rejection PASS.',flush=True)
    target='rdc-services.target' if role=='chat' else 'rdc-nextcloud.target'
    # No downloads or external sign-in are possible from this point.
    offline()
    try:
        run(['systemctl','stop','rdc-frontend.service',target])
        run(['nft','delete','table','inet','rdc_application'])
        run(['ip','netns','exec','rdc-front','nft','delete','table','inet','rdc_frontend'])
        run(['systemctl','start',target],timeout=240)
        run(['systemctl','start','rdc-frontend.service'])
        client(role,'cold');client(role,'negative');client(role,'direct','rdc-attacker')
        from backup_scope import include
        from backup_snapshot import capture
        from backup_operations import validate_restore
        from restore_runtime import install_guards
        from restore_transaction import apply
        app=runtime.read_settings()['ownership'];owner=include(app['network'],app)
        install_guards(owner)
        stage=BASE/'snapshot';capture(Path('/'),stage,owner)
        validate_restore(stage,owner)
        client(role,'mutate')
        result=apply(stage,owner)
        assert result['state']=='restored-service-verified'
        client(role,'restored')
        print('WAN-blocked cold restart, actual message/file operation and native fenced application snapshot restore PASS. No Tailscale daemon or stub was installed.',flush=True)
    finally:subprocess.run(['nft','delete','table','inet','rdc_ci_offline'],check=False)


if __name__=='__main__':main(sys.argv[1])

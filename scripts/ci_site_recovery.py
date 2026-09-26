#!/usr/bin/env python3
"""Combined disconnected Linux service recovery, with an explicit routing surrogate."""
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
import ci_home_vm as virtual
from ci_site_network import Network,run,ns
from ci_site_recovery_contract import ROLES,guest_command,require_fenced,evidence
from offline_bundle_build import build
from private_recovery_package import seal,inspect

SOURCE=Path(__file__).resolve().parents[1]
ROOT=Path('/var/lib/rdc-site-recovery-ci')
GUEST_ROOT=Path('/root/rs-guest')


def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    path.write_bytes(raw);path.chmod(0o600)


def inputs():
    material=ROOT/'material';material.mkdir(mode=0o700)
    for category in ('configuration','edge','trust','tls','backup-access','application-backups','operator'):(material/category).mkdir(mode=0o700)
    plan=json.loads((SOURCE/'examples/portable-site.json').read_text());plan['site']='ci';plan['recovery_site']='ci-recovery'
    plan['domains']={'chat':'matrix.ci.test','element':'element.ci.test','files':'files.ci.test'}
    settings=json.loads((SOURCE/'examples/portable-network.json').read_text())
    for name,value in [('site',plan),('network',settings)]:write(material/('configuration/'+name+'.json'),json.dumps(value).encode())
    write(material/'edge/router-fixture.json',b'{"kind":"linux-routing-fixture","opnsense":"not-tested"}')
    write(material/'operator/runbook.txt',b'Fence originals before restoring. Synthetic Linux exercise only.')
    write(material/'backup-access/client.json',json.dumps({r:secrets.token_urlsafe(24) for r in ROLES}).encode())
    issuer=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable site recovery root')])
    root=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(issuer.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=120))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()),False).sign(issuer,hashes.SHA256()))
    ca=root.public_bytes(serialization.Encoding.PEM);write(material/'trust/ca.crt',ca)
    for label,names in [(r,[h]) for r,h in plan['domains'].items()]+[(r+'-backend',[plan['domains'][r]]+([plan['domains']['element']] if r=='chat' else [])) for r in ROLES]:
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,names[0])]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=60))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(issuer,hashes.SHA256()))
        folder=material/'tls'/('backend' if label.endswith('-backend') else 'frontend');stem=label.removesuffix('-backend')
        write(folder/(stem+'.crt'),leaf.public_bytes(serialization.Encoding.PEM)+ca)
        write(folder/(stem+'.key'),key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    write(material/'tls/frontend/backend-ca.crt',ca)
    return material,plan,settings


def trust(material):
    Path('/usr/local/share/ca-certificates/rs-fixture.crt').write_bytes((material/'trust/ca.crt').read_bytes())
    run('update-ca-certificates',stdout=subprocess.DEVNULL)


def wait_probe(material,state):
    deadline=time.monotonic()+45
    while True:
        try:client(material,state,'probe');return
        except subprocess.CalledProcessError:
            if time.monotonic()>=deadline:raise
            time.sleep(1)


def client(material,state,phase):
    ns('rs-staff',sys.executable,SOURCE/'scripts/ci_site_client.py',material,state,phase,timeout=180)


def start_frontend(material):
    ns('rs-front',sys.executable,SOURCE/'scripts/ci_site_network.py',material,timeout=180)


def remove_frontend():
    # These exact resources were created earlier on this guarded disposable host.
    run('systemctl','disable','--now','rdc-frontend.service')
    for path in ('/etc/rdc-frontend','/usr/local/lib/rdc-frontend','/var/lib/rdc-frontend'):shutil.rmtree(path)
    Path('/etc/systemd/system/rdc-frontend.service').unlink();run('systemctl','daemon-reload')


def guest(role,generation,material,software_hash):
    folder=ROOT/(generation+'-'+role)
    original=virtual.qemu_command
    virtual.qemu_command=lambda directory,port,**kw:guest_command(directory,port,role)
    try:vm=virtual.VM(folder,ROOT/'ubuntu.img',port=ROLES[role][2],ca='',controller_address='127.0.0.1',controller_hostname='unused.ci.test',offline=True)
    finally:virtual.qemu_command=original
    try:
        links=json.loads(vm.ssh(['ip','-j','link']))
        interface=next(item['ifname'] for item in links if item.get('address')==ROLES[role][1])
        plan=json.loads((material/'configuration/site.json').read_text())
        vm.ssh(['ip','address','add',plan['vms'][role]['address']+'/24','dev',interface]);vm.ssh(['ip','link','set',interface,'up'])
        vm.ssh(['ip','route','add','10.76.0.0/16','via','10.76.40.1','dev',interface])
        vm.ssh(['resolvectl','dns',interface,'10.76.30.10']);vm.ssh(['resolvectl','domain',interface,'~.'])
        vm.ssh(['python3','-c',"import socket; s=socket.socket(); s.settimeout(2); r=s.connect_ex(('1.1.1.1',443)); s.close(); assert r!=0"])
        vm.put(ROOT/'software.tar','/root/software.tar',timeout=900)
        vm.ssh(['tar','-xf','/root/software.tar','-C','/root'],timeout=300);vm.ssh(['rm','/root/software.tar'])
        result=json.loads(vm.ssh(['python3','/root/software/source/scripts/offline_bundle.py','bootstrap','/root/software',
                                 '--manifest-sha256',software_hash,'--confirm-fresh-guest'],timeout=1500))
        assert result['state']=='role-software-prepared'
        vm.ssh(['systemctl','disable','--now','nginx.service'])
        vm.ssh(['mkdir','-m','700',GUEST_ROOT])
        for source,target in [('configuration/site.json','site.json'),('trust/ca.crt','ca.crt'),('tls/backend/'+role+'.crt','role.crt'),('tls/backend/'+role+'.key','role.key')]:vm.put(material/source,str(GUEST_ROOT/target))
        password=json.loads((material/'backup-access/client.json').read_text())[role]
        temp=ROOT/'guest-password';write(temp,password.encode())
        try:vm.put(temp,str(GUEST_ROOT/'password'))
        finally:temp.unlink()
        vm.source=Path(result['source']);vm.python=vm.source/'.venv/bin/python'
        action(vm,role,'install')
        return vm
    except BaseException:vm.stop();raise


def action(vm,role,phase):
    try:
        output=vm.ssh(['env','GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted',vm.python,vm.source/'scripts/ci_site_guest.py',role,phase],timeout=900)
        # Print only the explicit safe completion line, never command output that
        # might contain application account material.
        for line in output.decode().splitlines():
            if line.startswith('Guest '):print(line,flush=True)
    except subprocess.CalledProcessError as error:
        # Paths and stack locations are useful without publishing exception
        # messages or subprocess arguments that might contain credentials.
        for line in (error.stderr or b'').decode(errors='replace').splitlines():
            if line.startswith('  File '):print(line,flush=True)
        print('Guest action failed: '+role+' '+phase,flush=True)
        raise ValueError('Guest action failed; inspect bounded synthetic diagnostics') from None


def snapshot(vm,role,material):
    action(vm,role,'snapshot')
    target=material/'application-backups'/(role+'.tar')
    # Stream via the pinned private management channel rather than retaining a
    # complete application archive in controller memory.
    vm.ssh(['cp',GUEST_ROOT/'snapshot.tar','/home/ciadmin/snapshot.tar']);vm.ssh(['chown','ciadmin:ciadmin','/home/ciadmin/snapshot.tar'])
    run('scp',*vm.ssh_options(),'-P',ROLES[role][2],'ciadmin@127.0.0.1:/home/ciadmin/snapshot.tar',target,timeout=900);target.chmod(0o600)
    metadata=json.loads(vm.get(str(GUEST_ROOT/'snapshot/snapshot.json')))
    write(material/'application-backups'/(role+'.json'),json.dumps(metadata).encode())
    return datetime.fromisoformat(metadata['captured_at'])


def main():
    virtual.guard()
    if ROOT.exists() or Path('/etc/rdc-frontend').exists():raise ValueError('Use a fresh disposable host')
    if os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')<12*1024**3:raise ValueError('Combined fixture requires at least 12 GiB runner RAM')
    ROOT.mkdir(mode=0o700);network=None;guests={};originals={}
    try:
        result=build(ROOT/'software');software_hash=result['manifest_sha256'];virtual.image(ROOT/'ubuntu.img')
        with tarfile.open(ROOT/'software.tar','w') as archive:archive.add(ROOT/'software',arcname='software')
        material,plan,settings=inputs();trust(material)
        state=material/'operator/client-state';state.mkdir(mode=0o700)
        network=Network(ROOT,plan,settings);wait_probe(material,state)
        for role in ROLES:guests[role]=guest(role,'original',material,software_hash)
        start_frontend(material);client(material,state,'create')
        captures={role:snapshot(vm,role,material) for role,vm in guests.items()}
        client(material,state,'mutate')
        password=ROOT/'package-password';write(password,secrets.token_hex(32).encode())
        artifact=ROOT/'software/tools/restic.bz2'
        sealed=seal(material,ROOT/'private-repository',password,artifact)
        print('Both applications, local routing/DNS/time/frontend and encrypted recovery inputs prepared.',flush=True)
        # Gateway outage must block local staff access without removing the
        # independent pinned management consoles used for repair.
        started=time.monotonic();failed_at=datetime.now(timezone.utc)
        ns('rs-edge','sysctl','-w','net.ipv4.ip_forward=0',stdout=subprocess.DEVNULL)
        try:client(material,state,'probe')
        except subprocess.CalledProcessError:pass
        else:raise AssertionError('Staff still crossed the disabled routing fixture')
        for vm in guests.values():vm.ssh(['true'])
        originals=guests;guests={}
        for vm in originals.values():vm.stop()
        require_fenced(originals)
        for vm in originals.values():shutil.rmtree(vm.folder)
        network.stop();network=None;remove_frontend();shutil.rmtree(material)
        opened=ROOT/'recovered-material'
        inspect(ROOT/'private-repository',password,artifact,sealed['snapshot_id'],sealed['manifest_sha256'],output=opened)
        plan=json.loads((opened/'configuration/site.json').read_text());settings=json.loads((opened/'configuration/network.json').read_text());trust(opened)
        state=opened/'operator/client-state'
        network=Network(ROOT,plan,settings);wait_probe(opened,state)
        for role in ROLES:
            require_fenced(originals)
            vm=guest(role,'replacement',opened,software_hash);guests[role]=vm
            vm.put(opened/'application-backups'/(role+'.tar'),str(GUEST_ROOT/'snapshot.tar'),timeout=900)
            action(vm,role,'restore')
        start_frontend(opened);client(opened,state,'restored')
        result=evidence(time.monotonic()-started,{r:round((failed_at-t).total_seconds(),2) for r,t in captures.items()})
        (ROOT/'evidence.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)
    finally:
        for vm in [*guests.values(),*originals.values()]:vm.stop()
        if network:network.stop()


if __name__=='__main__':main()

"""Acquire public role software on a connected disposable Ubuntu preparation host."""
import ast
from datetime import datetime,timezone
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
from offline_bundle import TARGET,require,digest,file_names,verify

ROOT=Path(__file__).resolve().parents[1]
PACKAGES=('python3','python3-venv','python3-pip','podman','runc','skopeo','nftables',
          'nginx','unbound','chrony','openssh-server','openssh-client','openssl','ca-certificates','iproute2','iptables','bzip2')
TOP={'requirements.txt','ansible.cfg','rdc','project-version.json','LICENSE','README.md','THIRD_PARTY_NOTICES.md'}


def run(argv,**kwargs):
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
         'PIP_CONFIG_FILE':'/dev/null','PYTHONNOUSERSITE':'1','DEBIAN_FRONTEND':'noninteractive'}
    argv=[str(x) for x in argv]
    if argv[0]=='/usr/bin/git':argv[1:1]=['-c','safe.directory='+str(ROOT)]
    try:
        return subprocess.run(argv,check=True,capture_output=True,text=True,timeout=kwargs.pop('timeout',1800),env=env,**kwargs).stdout
    except subprocess.CalledProcessError as error:
        raise ValueError('Public acquisition command failed: '+argv[0]+'; '+(error.stderr or '')[-4000:]) from error


def require_builder():
    require(platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()==0,'Build only on a disposable Ubuntu 24.04 amd64 preparation host as root')
    release=platform.freedesktop_os_release()
    require(release.get('ID')=='ubuntu' and release.get('VERSION_ID')=='24.04' and sys.version_info[:2]==(3,12),'Build requires Ubuntu 24.04 with Python 3.12')
    require(all(Path(p).is_file() for p in ('/usr/bin/apt-get','/usr/bin/skopeo','/usr/bin/git')),'Prepare apt-get, skopeo and git on the disposable build host')


def source_allowed(name):
    return name in TOP or name.split('/')[0] in {'scripts','roles','playbooks','portable','docs','templates','examples'} or name.startswith('inventories/examples/') or name=='inventories/example/hosts.yml'


def image_catalogue():
    images={}
    for name in ('service_images.json','nextcloud_images.json'):
        data=json.loads((ROOT/'scripts'/name).read_text())
        for pin in data['components'].values():
            key=pin['image'].split('@sha256:')[1]
            item={'reference':pin['image'],'config_digest':pin['config_digest'],'path':'images/'+key}
            require(key not in images or images[key]==item,'Conflicting pinned image identities')
            images[key]=item
    return images


def restic_identity():
    values={}
    for node in ast.parse((ROOT/'scripts/backup_contracts.py').read_text()).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and target.id in ('RESTIC_VERSION','RESTIC_SHA256'):
                    values[target.id]=ast.literal_eval(node.value)
    require(set(values)=={'RESTIC_VERSION','RESTIC_SHA256'},'Missing reviewed Restic identity')
    return values


def apt_options(work):
    return ['-o','Dir::Etc::main=-','-o','Dir::Etc::parts=-',
            '-o','Dir::Etc::sourcelist='+str(work/'sources.list'),'-o','Dir::Etc::sourceparts=-',
            '-o','Dir::State='+str(work/'state'),'-o','Dir::State::status=/dev/null',
            '-o','Dir::State::lists='+str(work/'lists'),'-o','Dir::Cache='+str(work/'cache'),
            '-o','Dir::Cache::archives='+str(work/'archives'),'-o','APT::Sandbox::User=root',
            '-o','APT::Install-Recommends=false','-o','APT::Get::AllowUnauthenticated=false',
            '-o','Acquire::AllowInsecureRepositories=false','-o','APT::Architecture=amd64']


def acquire_packages(out,work):
    for name in ('state','lists/partial','archives/partial','cache'):(work/name).mkdir(parents=True,exist_ok=True)
    sources=''.join('deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://'+host+'/ubuntu '+suite+' main universe\n'
        for host,suite in [('archive.ubuntu.com','noble'),('archive.ubuntu.com','noble-updates'),('security.ubuntu.com','noble-security')])
    (work/'sources.list').write_text(sources)
    args=['/usr/bin/apt-get',*apt_options(work)]
    run([*args,'update'])
    run([*args,'--download-only','--yes','install',*PACKAGES])
    target=out/'packages';target.mkdir()
    debs=sorted((work/'archives').glob('*.deb'));require(debs,'APT produced no package closure')
    for path in debs:shutil.copyfile(path,target/path.name)
    evidence=out/'provenance/apt';evidence.mkdir(parents=True)
    (evidence/'sources.list').write_text(sources)
    for path in (work/'lists').iterdir():
        if path.is_file() and path.name!='lock':shutil.copyfile(path,evidence/path.name)
    shutil.copyfile('/usr/share/keyrings/ubuntu-archive-keyring.gpg',evidence/'ubuntu-archive-keyring.gpg')
    (evidence/'requested.json').write_text(json.dumps(PACKAGES))


def acquire_images(out,work):
    images=image_catalogue();auth=work/'empty-auth.json';auth.write_text('{"auths":{}}');auth.chmod(0o600)
    for key,pin in images.items():
        target=out/pin['path'];target.parent.mkdir(exist_ok=True)
        run(['/usr/bin/skopeo','copy','--preserve-digests','--src-authfile',auth,
             '--src-tls-verify=true','--override-os','linux','--override-arch','amd64',
             'docker://'+pin['reference'],'dir:'+str(target)],timeout=1800)
        require(digest(target,'manifest.json')['sha256']==key,'Container manifest differs from its reviewed pin')
        manifest=json.loads((target/'manifest.json').read_text())
        require(manifest.get('config',{}).get('digest')==pin['config_digest'],'Container configuration differs from its reviewed pin')
        config=pin['config_digest'].split(':')[1]
        require(digest(target,config)['sha256']==config,'Container configuration checksum differs')
    return images


def acquire_python(out):
    wheels=out/'wheels';wheels.mkdir()
    run([sys.executable,'-m','pip','--isolated','download','--index-url','https://pypi.org/simple',
         '--only-binary=:all:','--no-cache-dir','--dest',wheels,'-r',out/'source/requirements.txt'])
    require(any(wheels.glob('*.whl')),'No target wheels were collected')
    # The manifest anchors every exact wheel byte. No index or source build is
    # consulted when the replacement installs this closed wheel directory.


def acquire_restic(out):
    pin=restic_identity();folder=out/'tools';folder.mkdir()
    url='https://github.com/restic/restic/releases/download/v'+pin['RESTIC_VERSION']+'/restic_'+pin['RESTIC_VERSION']+'_linux_amd64.bz2'
    with urllib.request.urlopen(url,timeout=120) as stream:raw=stream.read(64*1024**2+1)
    require(len(raw)<=64*1024**2 and hashlib.sha256(raw).hexdigest()==pin['RESTIC_SHA256'],'Restic distribution failed pinned verification')
    (folder/'restic.bz2').write_bytes(raw)
    (out/'provenance/restic.json').write_text(json.dumps({'version':pin['RESTIC_VERSION'],'sha256':pin['RESTIC_SHA256'],'url':url}))


def export_source(out,commit):
    entries=run(['/usr/bin/git','ls-tree','-rz',commit],cwd=ROOT).split('\0')
    for entry in entries:
        if not entry:continue
        metadata,name=entry.split('\t',1);mode,kind,blob=metadata.split()
        if not source_allowed(name):continue
        require(mode in ('100644','100755') and kind=='blob','Public source cannot contain linked or special entries')
        target=out/'source'/name;target.parent.mkdir(parents=True,exist_ok=True)
        raw=subprocess.run(['/usr/bin/git','-c','safe.directory='+str(ROOT),'cat-file','blob',blob],cwd=ROOT,check=True,capture_output=True,timeout=30).stdout
        target.write_bytes(raw);target.chmod(0o755 if mode=='100755' else 0o644)


def build(target):
    require_builder();target=Path(target).absolute()
    require(not target.exists() and not target.is_symlink(),'Choose a new bundle directory')
    require(not run(['/usr/bin/git','status','--porcelain','--untracked-files=no'],cwd=ROOT).strip(),'Build from a clean committed source revision')
    commit=run(['/usr/bin/git','rev-parse','HEAD'],cwd=ROOT).strip()
    require(target.parent.is_dir() and not target.parent.is_symlink(),'Use an existing real parent directory')
    with tempfile.TemporaryDirectory(prefix='.rdc-bundle-',dir=target.parent) as staging:
        staging=Path(staging);out=staging/'bundle';out.mkdir(mode=0o700);work=staging/'work';work.mkdir(mode=0o700)
        export_source(out,commit);acquire_packages(out,work)
        images=acquire_images(out,work);acquire_python(out);acquire_restic(out)
        (out/'OFFLINE-RECOVERY.txt').write_text('Public Ubuntu role software only. Keep the manifest SHA256 independently.\n'
            'Private plans, trust, TLS keys, accounts and encrypted backups are NOT in this bundle.\n'
            'Guest/hypervisor installation media and full private site reconstruction are separate prerequisites.\n'
            'Read source/docs/offline-software-bundle.md before bootstrap.\n'
            'Third-party licences/notices remain in upstream packages, wheels and image layers.\n'
            'No public combined-distribution licence approval is claimed.\n')
        data={'schema_version':1,'kind':'portable-software','source_commit':commit,'target':TARGET,'scope':'role-software',
              'images':images,'files':{name:digest(out,name) for name in sorted(file_names(out))},'created_at':datetime.now(timezone.utc).isoformat()}
        raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode();(out/'manifest.json').write_bytes(raw)
        trusted=hashlib.sha256(raw).hexdigest();verify(out,trusted)
        require(not target.exists() and not target.is_symlink(),'Bundle destination appeared during preparation')
        os.rename(out,target)
    return {'state':'role-software-bundle-prepared','directory':str(target),'manifest_sha256':trusted,'source_commit':commit,
            'whole_site_recovery':'not-tested','notice':'Record this hash through your independent trusted handover; it is not a publisher signature.'}

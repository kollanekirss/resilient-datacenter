"""Explicit fresh Ubuntu dependency bootstrap from a verified local software kit."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile
from offline_bundle import require,verify,open_file,digest

BASE=Path('/var/lib/rdc-offline-bootstrap')
INSTALL=Path('/opt/rdc-offline')
POLICY=b'#!/bin/sh\n# RDC offline bootstrap: suppress package service autostart\nexit 101\n'


def run(argv,**kwargs):
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
         'DEBIAN_FRONTEND':'noninteractive','PIP_CONFIG_FILE':'/dev/null','PYTHONNOUSERSITE':'1'}
    return subprocess.run([str(x) for x in argv],check=True,capture_output=True,text=True,
                          timeout=kwargs.pop('timeout',1800),env=env,**kwargs).stdout


def supported():
    require(platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()==0,'Bootstrap requires root on a fresh Ubuntu 24.04 amd64 guest')
    release=platform.freedesktop_os_release()
    require(release.get('ID')=='ubuntu' and release.get('VERSION_ID')=='24.04' and Path('/run/systemd/system').is_dir(),'Bootstrap requires Ubuntu 24.04 with systemd')


def private(path):
    path.mkdir(mode=0o700,exist_ok=True)
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o077,'Bootstrap directories must be owned and private')


def write(path,data):
    with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as stream:
        temporary=Path(stream.name);stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


def closure(data):
    names=set(data['files'])
    required={'source/rdc','source/requirements.txt','source/scripts/offline_bundle.py','source/scripts/rdc.py',
              'source/scripts/service_images.json','source/scripts/nextcloud_images.json',
              'tools/restic.bz2','provenance/restic.json','provenance/apt/requested.json'}
    require(required<=names and any(n.startswith('packages/') and n.endswith('.deb') for n in names)
            and any(n.startswith('wheels/') and n.endswith('.whl') for n in names) and len(data['images'])==5,
            'Bundle lacks the complete supported role-software layout')
    for key,pin in data['images'].items():
        name=pin['path']+'/manifest.json';config=pin['config_digest'].split(':')[1]
        require(name in names and data['files'][name]['sha256']==key and
                pin['path']+'/'+config in names and data['files'][pin['path']+'/'+config]['sha256']==config,
                'Image manifest/configuration identity is absent or inconsistent')


def stage(root,data,trusted):
    target=BASE/trusted
    if target.exists() or target.is_symlink():verify(target,trusted);return target
    with tempfile.TemporaryDirectory(prefix='.copy-',dir=BASE) as temporary:
        destination=Path(temporary)/'bundle';destination.mkdir(mode=0o700)
        for name in [*data['files'],'manifest.json']:
            path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
            with open_file(root,name) as source,path.open('xb') as output:
                shutil.copyfileobj(source,output,1024**2);output.flush();os.fsync(output.fileno())
        verify(destination,trusted);os.rename(destination,target)
    return target


@contextmanager
def no_autostart(path=Path('/usr/sbin/policy-rc.d')):
    if path.exists() or path.is_symlink():
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022
                and path.read_bytes()==POLICY,'Existing service-start policy requires independent review; it was not replaced')
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
        with os.fdopen(fd,'wb') as stream:stream.write(POLICY);stream.flush();os.fsync(stream.fileno())
    try:yield
    finally:
        require(not path.is_symlink() and path.read_bytes()==POLICY,'Service-start policy changed during bootstrap; inspect it manually')
        path.unlink()


def package_command(folder,debs):
    return ['/usr/bin/unshare','--net','--','/usr/bin/apt-get','-o','Dir::Etc::main=-','-o','Dir::Etc::parts=-',
            '-o','Dir::Etc::sourcelist=/dev/null','-o','Dir::Etc::sourceparts=-',
            '-o','Dir::State::lists='+str(folder/'empty-lists'),'-o','APT::Install-Recommends=false',
            '-o','Dpkg::Options::=--force-confold','--no-download','--no-remove','--yes','install',*map(str,debs)]


def import_images(folder,images):
    for pin in images.values():
        run(['/usr/bin/skopeo','copy','--preserve-digests','dir:'+str(folder/pin['path']),
             'containers-storage:'+pin['reference']])
    verify_images(images)


def verify_images(images):
    for pin in images.values():
        records=json.loads(run(['/usr/bin/podman','--remote=false','image','inspect',pin['reference']]))
        require(isinstance(records,list) and len(records)==1 and records[0].get('Id','').removeprefix('sha256:')==pin['config_digest'].removeprefix('sha256:')
                and records[0].get('Architecture')=='amd64' and records[0].get('Os')=='linux','Imported image differs from its reviewed identity')


def source_copy(folder,data,*,verify_only=False):
    private(INSTALL)
    for name,item in data['files'].items():
        if not name.startswith('source/'):continue
        destination=INSTALL/name
        if not verify_only:destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists() or destination.is_symlink():
            require(digest(INSTALL,name,item['size'])==item,'Installed bootstrap source changed; review before resuming')
        else:
            require(not verify_only,'Prepared source is missing; review the installation')
            temporary=None
            try:
                with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as output:
                    temporary=Path(output.name)
                    with open_file(folder,name) as stream:shutil.copyfileobj(stream,output)
                    output.flush();os.fsync(output.fileno())
                require(digest(temporary.parent,temporary.name,item['size'])==item,'Source changed during bootstrap copy')
                temporary.chmod(0o755 if name=='source/rdc' else 0o644)
                os.link(temporary,destination,follow_symlinks=False)
            finally:
                if temporary is not None:temporary.unlink(missing_ok=True)


def verify_prepared(data):
    for path in ('/usr/bin/podman','/usr/bin/skopeo','/usr/bin/runc','/usr/sbin/nft',
                 '/usr/sbin/nginx','/usr/sbin/unbound','/usr/sbin/chronyd',str(INSTALL/'source/.venv/bin/python')):
        require(Path(path).is_file() and os.access(path,os.X_OK),'Prepared software is missing; review before repair')
    verify_images(data['images'])


def outcome(data,frozen):
    return {'state':'role-software-prepared','source':str(INSTALL/'source'),'restic_artifact':str(frozen/'tools/restic.bz2'),
            'source_commit':data['source_commit'],'applications':'not-installed','whole_site_recovery':'not-tested'}


def bootstrap(root,trusted):
    supported();root=Path(root).absolute();data=verify(root,trusted);closure(data)
    private(BASE)
    lockfd=os.open(BASE/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(lockfd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        marker=BASE/'installation.json';identity={'manifest_sha256':trusted,'source_commit':data['source_commit']}
        prior=None
        if marker.exists() or marker.is_symlink():
            require(not marker.is_symlink(),'Unsafe bootstrap identity')
            prior=json.loads(marker.read_text())
            require(prior.get('identity')==identity and prior.get('state') in ('incomplete','prepared'),'Bootstrap belongs to another bundle')
        else:
            require(not INSTALL.exists() and not INSTALL.is_symlink(),'Unowned offline installation directory exists')
            for name in ('/etc/server-connectivity-profile.json','/etc/rdc-services','/etc/rdc-nextcloud','/etc/rdc-frontend','/etc/rdc-portable-dns'):
                require(not Path(name).exists() and not Path(name).is_symlink(),'Use a fresh guest; existing role installation was not changed')
            write(marker,json.dumps({'identity':identity,'state':'incomplete'}).encode())
        frozen=stage(root,data,trusted)
        if prior is not None and prior['state']=='prepared':
            source_copy(frozen,data,verify_only=True);verify_prepared(data)
            return outcome(data,frozen)
        source_copy(frozen,data)
        # Validate the expected closure against the source catalogue before any
        # root package execution. The independently trusted manifest binds both.
        from offline_bundle_build import PACKAGES
        require(json.loads((frozen/'provenance/apt/requested.json').read_text())==list(PACKAGES),'Unreviewed package request set')
        (BASE/'empty-lists').mkdir(exist_ok=True)
        with no_autostart():run(package_command(BASE,sorted((frozen/'packages').glob('*.deb'))))
        source=INSTALL/'source';venv=source/'.venv'
        run(['/usr/bin/python3','-m','venv',venv])
        run([venv/'bin/python','-m','pip','--isolated','install','--no-index','--only-binary=:all:',
             '--no-cache-dir','--find-links',frozen/'wheels','-r',source/'requirements.txt'])
        import_images(frozen,data['images'])
        write(marker,json.dumps({'identity':identity,'state':'prepared'}).encode())
    return outcome(data,frozen)

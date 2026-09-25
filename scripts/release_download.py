"""Fetch fixed-project experimental releases; never execute or extract downloads."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

REPOSITORY='kollanekirss/resilient-datacenter'
WORKFLOW=REPOSITORY+'/.github/workflows/release.yml'
FILES={'derper-linux-amd64','source.tar.gz','notices.tar.gz','derper-build.json'}
MANIFEST='release-manifest.json'
VERSION=re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}-(?:alpha|beta|rc)\.[0-9]{1,4}')
COMMIT=re.compile(r'[a-f0-9]{40}')
MAX_FILE=256*1024*1024


def identity(version,commit):
    if not isinstance(version,str) or not VERSION.fullmatch(version):
        raise ValueError('Choose an explicit experimental release version, for example 0.2.0-alpha.1.')
    if not isinstance(commit,str) or not COMMIT.fullmatch(commit):
        raise ValueError('Supply the full 40-character expected source commit from the reviewed release.')


class GitHub:
    def _run(self,args):
        # Never use an inherited alternate API host or repository. Authentication is
        # supplied by the operator's normal GitHub CLI configuration.
        env={k:v for k,v in os.environ.items() if k not in ('GH_HOST','GH_REPO','GH_DEBUG')}
        env['GH_HOST']='github.com'
        result=subprocess.run(['gh',*args],env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
        if result.returncode: raise ValueError('GitHub download or provenance verification failed; no release was published locally.')

    def download(self,tag,destination):
        args=['release','download',tag,'--repo',REPOSITORY,'--dir',str(destination)]
        for name in sorted(FILES|{MANIFEST}): args.extend(['--pattern',name])
        self._run(args)

    def verify(self,path,tag,commit):
        self._run(['attestation','verify',str(path),'--repo',REPOSITORY,
                   '--signer-workflow',WORKFLOW,'--signer-digest',commit,
                   '--source-ref','refs/tags/'+tag,'--source-digest',commit,
                   '--deny-self-hosted-runners'])


def validate_manifest(data,version,commit):
    if (not isinstance(data,dict) or set(data)!={'schema_version','repository','version','commit','target','files'} or
        type(data['schema_version']) is not int or data['schema_version']!=1 or
        data['repository']!=REPOSITORY or data['version']!=version or data['commit']!=commit or
        data['target']!='linux/amd64' or not isinstance(data['files'],dict) or set(data['files'])!=FILES or
        any(not isinstance(d,str) or not re.fullmatch('[a-f0-9]{64}',d) for d in data['files'].values())):
        raise ValueError('Release manifest does not match the requested project, source or supported target.')
    return data


def check_destination(destination):
    destination=Path(os.path.abspath(destination))
    if destination.exists() or destination.is_symlink(): raise ValueError('Output already exists; select a new directory.')
    for parent in (destination.parent,*destination.parent.parents):
        if parent.is_symlink(): raise ValueError('Symlink output parents are not supported.')
    info=destination.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o022:
        raise ValueError('Output parent must be an existing directory owned by you, without group/other write access.')
    return destination


def fetch(version,commit,destination,*,transport=None):
    identity(version,commit)
    destination=check_destination(destination)
    transport=transport or GitHub()
    with tempfile.TemporaryDirectory(prefix='.rdc-release-',dir=destination.parent) as temporary:
        stage=Path(temporary)/'payload'; stage.mkdir(mode=0o700)
        transport.download('v'+version,stage)
        if set(p.name for p in stage.iterdir())!=FILES|{MANIFEST}: raise ValueError('Release files are incomplete or unexpected.')
        for name in FILES|{MANIFEST}:
            path=stage/name
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_FILE or info.st_nlink!=1:
                raise ValueError('Release contains an unsafe or oversized file.')
            path.chmod(0o600)
        if (stage/MANIFEST).stat().st_size>16384: raise ValueError('Release manifest is oversized.')
        transport.verify(stage/MANIFEST,'v'+version,commit)
        manifest=validate_manifest(json.loads((stage/MANIFEST).read_text()),version,commit)
        for name,digest in sorted(manifest['files'].items()):
            with (stage/name).open('rb') as source: actual=hashlib.file_digest(source,'sha256').hexdigest()
            if actual!=digest: raise ValueError('Release checksum mismatch; no release was published locally.')
            transport.verify(stage/name,'v'+version,commit)
        # Reserve exclusively AFTER verification. Copy only verified bytes. A
        # failed copy removes the new directory; an existing path is never used.
        destination.mkdir(mode=0o700)
        try:
            for name in sorted(FILES|{MANIFEST}): os.replace(stage/name,destination/name)
        except BaseException:
            shutil.rmtree(destination)
            raise
    return manifest

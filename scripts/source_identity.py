"""Read project identity without inferring provenance from a version label."""
import json
import os
from pathlib import Path
import re
import subprocess
from profile_config import load_profile

VERSION=re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-(?:dev|alpha|beta|rc)(?:\.[0-9]{1,4})?)?')
COMMIT=re.compile(r'[a-f0-9]{40}(?:[a-f0-9]{24})?')


def safe_version(value):
    return value if isinstance(value,str) and VERSION.fullmatch(value) else 'unknown/unreleased'


def source_identity(root: Path) -> dict:
    result={'version':'unknown/unreleased','channel':'unknown','commit':None,'dirty':None,
            'provenance':'unverified','components':{}}
    try:
        data=json.loads((root/'project-version.json').read_text())
        if (isinstance(data,dict) and set(data)=={'schema_version','version','channel'} and
            type(data['schema_version']) is int and data['schema_version']==1 and
            data['channel'] in ('development','prerelease','release') and safe_version(data['version'])!='unknown/unreleased'):
            result.update(version=data['version'],channel=data['channel'])
    except (OSError,ValueError,TypeError): pass
    try:
        pins=load_profile(str(root/'versions.yml'))
        if isinstance(pins,dict):
            result['components']={name:safe_version(pins.get(name+'_version')) for name in ('headscale','tailscale')}
    except (OSError,ValueError): pass
    env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    def git(*args):
        return subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),*args],env=env,
                              capture_output=True,text=True,check=True,timeout=3).stdout.strip()
    try:
        if Path(git('rev-parse','--show-toplevel')).resolve()!=root.resolve(): return result
        commit=git('rev-parse','HEAD')
        if not COMMIT.fullmatch(commit): return result
        dirty=bool(git('status','--porcelain','--untracked-files=no'))
        result.update(commit=commit,dirty=dirty)
    except (OSError,ValueError,subprocess.SubprocessError): pass
    return result

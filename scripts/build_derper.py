#!/usr/bin/env python3
"""Cross-build the pinned Linux/amd64 DERP executable into local artifacts/."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil

ROOT=Path(__file__).resolve().parents[1]
VERSION='v1.102.4'
TOOLCHAIN='go1.26.6'

def build_environment():
    cache=ROOT/'.cache'; cache.mkdir(exist_ok=True)
    env={k:v for k,v in os.environ.items() if not k.startswith(('GO','CGO_'))}
    env.update(GOTOOLCHAIN=TOOLCHAIN,GOPATH=str(cache/'go'),GOMODCACHE=str(cache/'gomod'),GOCACHE=str(cache/'gobuild'),GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOSUMDB='sum.golang.org',GOPROXY='https://proxy.golang.org',GOENV='off',GOWORK='off')
    return env

def main():
    build=ROOT/'.work/derper-build'; build.mkdir(parents=True,exist_ok=True)
    cache=ROOT/'.cache'; cache.mkdir(exist_ok=True)
    out=ROOT/'artifacts/derper-linux-amd64'; out.parent.mkdir(exist_ok=True)
    for name in ('go.mod','go.sum'): shutil.copyfile(ROOT/'build/derper'/name,build/name)
    env=build_environment()
    subprocess.run(['go','mod','download','tailscale.com'],cwd=build,env=env,check=True)
    subprocess.run(['go','build','-mod=readonly','-buildvcs=false','-trimpath','-o',str(out),'tailscale.com/cmd/derper'],cwd=build,env=env,check=True)
    if (build/'go.sum').read_bytes()!=(ROOT/'build/derper/go.sum').read_bytes():
        raise ValueError('Build dependency checksums changed; review and update the lock before release.')
    digest=hashlib.sha256(out.read_bytes()).hexdigest()
    metadata={'module':'tailscale.com/cmd/derper','version':VERSION,'toolchain':TOOLCHAIN,'target':'linux/amd64','sha256':digest}
    (out.parent/'derper-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
    (out.parent/'derper-go.sum').write_bytes((build/'go.sum').read_bytes())
    print(json.dumps(metadata,indent=2))
    print('Set derper_artifact to '+str(out)+' and derper_sha256 to the value above.')

if __name__=='__main__': main()

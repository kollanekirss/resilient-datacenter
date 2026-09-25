#!/usr/bin/env python3
"""Cross-build the pinned Linux/amd64 DERP executable into local artifacts/."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
VERSION='v1.102.4'
TOOLCHAIN='go1.26.6'

def main():
    build=ROOT/'.work/derper-build'; build.mkdir(parents=True,exist_ok=True)
    cache=ROOT/'.cache'; cache.mkdir(exist_ok=True)
    out=ROOT/'artifacts/derper-linux-amd64'; out.parent.mkdir(exist_ok=True)
    (build/'go.mod').write_text('module institutional-pilot-derper\n\ngo 1.26.6\n\nrequire tailscale.com '+VERSION+'\n')
    (build/'main.go').write_text('// Build dependency anchor; never executed.\npackage main\nimport _ "tailscale.com/cmd/derper"\n')
    env=dict(os.environ,GOTOOLCHAIN=TOOLCHAIN,GOPATH=str(cache/'go'),GOMODCACHE=str(cache/'gomod'),GOCACHE=str(cache/'gobuild'),GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOSUMDB='sum.golang.org',GOPROXY='https://proxy.golang.org')
    subprocess.run(['go','mod','download','tailscale.com'],cwd=build,env=env,check=True)
    subprocess.run(['go','build','-mod=mod','-trimpath','-o',str(out),'tailscale.com/cmd/derper'],cwd=build,env=env,check=True)
    digest=hashlib.sha256(out.read_bytes()).hexdigest()
    metadata={'module':'tailscale.com/cmd/derper','version':VERSION,'toolchain':TOOLCHAIN,'target':'linux/amd64','sha256':digest}
    (out.parent/'derper-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
    (out.parent/'derper-go.sum').write_bytes((build/'go.sum').read_bytes())
    print(json.dumps(metadata,indent=2))
    print('Set derper_artifact to '+str(out)+' and derper_sha256 to the value above.')

if __name__=='__main__': main()

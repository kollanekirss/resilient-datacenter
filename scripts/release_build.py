#!/usr/bin/env python3
"""Create experimental release assets from a clean, exact tagged checkout."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from build_derper import ROOT, VERSION, TOOLCHAIN, build_environment, main as build_derper
from release_download import FILES, REPOSITORY, identity

LICENSE_TOOL='github.com/google/go-licenses/v2@v2.0.1'
ALLOWED_LICENSES={'MIT','BSD-2-Clause','BSD-3-Clause','Apache-2.0','ISC'}


def validate_licenses(text):
    rows=list(csv.reader(io.StringIO(text)))
    if (not rows or any(len(row)!=3 or not row[0] or not row[1] or row[2] not in ALLOWED_LICENSES for row in rows)
        or len({row[0] for row in rows})!=len(rows)):
        raise ValueError('Unknown, unreviewed or malformed dependency license report; publication blocked.')
    return rows


def write_manifest(out,version,commit):
    identity(version,commit)
    if any(not (out/name).is_file() or (out/name).is_symlink() for name in FILES):
        raise ValueError('Missing or unsafe release asset.')
    hashes={}
    for name in sorted(FILES):
        with (out/name).open('rb') as stream: hashes[name]=hashlib.file_digest(stream,'sha256').hexdigest()
    result={'schema_version':1,'repository':REPOSITORY,'version':version,'commit':commit,'target':'linux/amd64','files':hashes}
    (out/'release-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def run(args,**kwargs):
    return subprocess.run(args,check=True,text=True,**kwargs)


def collect_notices(build,notices,env):
    tools=ROOT/'.work/release-tools'; tools.mkdir(parents=True,exist_ok=True)
    native=dict(env,GOBIN=str(tools))
    native.pop('GOOS',None); native.pop('GOARCH',None)
    run(['go','install',LICENSE_TOOL],env=native)
    license_tool=str(tools/'go-licenses')
    report=run([license_tool,'report','tailscale.com/cmd/derper'],cwd=build,env=env,capture_output=True)
    rows=validate_licenses(report.stdout)
    run([license_tool,'save','tailscale.com/cmd/derper','--save_path',str(notices/'dependencies')],cwd=build,env=env)
    (notices/'licenses.csv').write_text(report.stdout)
    (notices/'scanner-warnings.txt').write_text(report.stderr)
    # go-licenses omits Go's runtime. Retain Go and bundled vendor notices too.
    goroot=Path(run(['go','env','GOROOT'],env=env,capture_output=True).stdout.strip())
    for path in goroot.rglob('*'):
        if path.is_file() and path.name.upper().startswith(('LICENSE','NOTICE','COPYING','PATENTS','COPYRIGHT')):
            target=notices/'go'/path.relative_to(goroot); target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
    for row in rows:
        if not (notices/'dependencies'/row[0]).is_dir():
            raise ValueError('A reported dependency has no saved license material.')
    shutil.copyfile(build/'go.sum',notices/'go.sum')
    shutil.copyfile(build/'go.mod',notices/'go.mod')
    shutil.copyfile(ROOT/'LICENSE',notices/'PROJECT-LICENSE')
    (notices/'README.txt').write_text('DERP is unmodified Tailscale source '+VERSION+'.\n'
        'Dependency license texts and copyright notices are retained under dependencies/.\n'
        'Go runtime/toolchain notices are under go/. Keep this archive with redistributed binaries.\n'
        'Scanner non-Go/assembly warnings are retained; no external C libraries are linked (CGO_ENABLED=0).\n'
        'No upstream endorsement is implied.\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True); args=parser.parse_args()
    commit=run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True).stdout.strip()
    identity(args.version,commit)
    if run(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,capture_output=True).stdout.strip():
        raise ValueError('Release build requires a clean checkout including untracked source files.')
    tag=run(['git','rev-parse','refs/tags/v'+args.version+'^{commit}'],cwd=ROOT,capture_output=True).stdout.strip()
    if tag!=commit: raise ValueError('Release tag does not match the current source commit.')
    version=json.loads((ROOT/'project-version.json').read_text())
    if version['version']!=args.version or version['channel']!='prerelease':
        raise ValueError('Project version/channel does not match the requested prerelease.')
    out=ROOT/'artifacts/release'; out.mkdir(parents=True,exist_ok=False)
    build_derper()
    env=build_environment(); build=ROOT/'.work/derper-build'
    notices=ROOT/'.work/release-notices'; notices.mkdir(parents=True,exist_ok=False)
    collect_notices(build,notices,env)
    for name in ('derper-linux-amd64','derper-build.json'): shutil.copyfile(ROOT/'artifacts'/name,out/name)
    metadata=json.loads((out/'derper-build.json').read_text())
    metadata.update(repository=REPOSITORY,commit=commit,release=args.version,license_tool=LICENSE_TOOL)
    (out/'derper-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
    run(['git','archive','--format=tar.gz','--prefix=resilient-datacenter/','--output='+str(out/'source.tar.gz'),commit],cwd=ROOT)
    with tarfile.open(out/'notices.tar.gz','w:gz') as archive: archive.add(notices,arcname='notices')
    write_manifest(out,args.version,commit)
    print('Release assets prepared. Publication and provenance signing are separate workflow steps.')

if __name__=='__main__': main()

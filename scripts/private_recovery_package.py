#!/usr/bin/env python3
"""Seal or verify private recovery material; never activate restored services."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from private_recovery_contract import private,local_path,inventory,make_manifest,write_manifest,verify,CATEGORIES,unreadable
from offline_bundle import open_file,digest,require


def supported():
    require(os.geteuid()==0,'Private package operations require root for consistent recovery ownership')
    require(platform.system()=='Linux' and platform.machine()=='x86_64','Private package operations require Ubuntu 24.04 amd64; no workstation execution')
    info=platform.freedesktop_os_release()
    require(info.get('ID')=='ubuntu' and info.get('VERSION_ID')=='24.04','Private package operations require Ubuntu 24.04')


def within(path,parent):return path==parent or parent in path.parents


def credentials(path,excluded):
    path=private(path)
    require(16<=path.stat().st_size<=4096 and not any(within(path,p) for p in excluded),
            'Keep a strong independent package password outside captured material and destinations')
    return path


def destination(value,excluded):
    path=local_path(value);private(path.parent,directory=True)
    require(not path.exists() and not path.is_symlink() and not any(within(path,p) or within(p,path) for p in excluded),
            'Use a new separate destination under a private owned parent')
    return path


def repository(path):
    path=private(path,directory=True)
    require({'config','data','index','keys','snapshots'}<=set(p.name for p in path.iterdir()) and
            set(p.name for p in path.iterdir())<={'config','data','index','keys','snapshots','locks'},'Unsupported local recovery repository layout')
    count=0
    for current,dirs,files in os.walk(path,followlinks=False,onerror=unreadable):
        for name in dirs:private(Path(current)/name,directory=True)
        for name in files:
            private(Path(current)/name);count+=1
            require(count<=100000,'Recovery repository exceeds supported file count')
    return path


def execute(binary,repo,password,args,*,cwd=None):
    # Absolute filesystem repository plus a minimal environment: no network
    # backend, shell, ambient repository, password or credential configuration.
    command=[str(binary),'--repo',str(repo),'--password-file',str(password),'--no-cache',*args]
    with tempfile.TemporaryFile(dir=Path(binary).parent) as output:
        result=subprocess.run(command,cwd=cwd,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'},
                              stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,timeout=3600)
        require(result.returncode==0,'Private recovery operation failed; no successful package or restore is claimed')
        output.seek(0);raw=output.read(2*1024**2+1)
        require(len(raw)<=2*1024**2,'Private recovery response exceeds supported size')
    return raw.decode('utf-8')


def tool(work,artifact):
    from backup_operations import restic_bytes
    raw=restic_bytes(local_path(artifact))
    path=work/'restic'
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o700)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    return path


def copy_material(source,target,data):
    target.mkdir(mode=0o700)
    for category in CATEGORIES:(target/category).mkdir(mode=0o700)
    for name,item in data['files'].items():
        path=target/name;path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        # mkdir(parents=True) intermediate modes follow umask, so set each
        # created directory private before putting material inside it.
        for parent in path.parents:
            if parent==target:break
            parent.chmod(0o700)
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output,open_file(source,name) as stream:
            shutil.copyfileobj(stream,output,1024**2);output.flush();os.fsync(output.fileno())
        require(digest(target,name,item['size'])==item,'Recovery input changed during capture')
    require(inventory(source)==data['files'] and inventory(target)==data['files'],'Recovery input changed during capture')


def restore_verified(binary,repo,password,snapshot,trusted,target):
    require(isinstance(snapshot,str) and re.fullmatch('[a-f0-9]{64}',snapshot),'Use the full saved snapshot ID, never latest')
    require(isinstance(trusted,str) and re.fullmatch('[a-f0-9]{64}',trusted),'Supply the independently retained manifest SHA256')
    target.mkdir(mode=0o700)
    execute(binary,repo,password,['restore',snapshot,'--target',str(target),'--verify'])
    return verify(target,trusted)


def seal(source,output,password,artifact):
    supported();source=private(source,directory=True);private(source.parent,directory=True)
    output=destination(output,[source]);password=credentials(password,[source,output])
    data=make_manifest(source)
    with tempfile.TemporaryDirectory(prefix='.rdc-private-',dir=output.parent) as folder:
        work=Path(folder);binary=tool(work,artifact);stage=work/'material';repo=work/'repository'
        copy_material(source,stage,data);trusted=write_manifest(stage,data)
        execute(binary,repo,password,['init','--repository-version','2'])
        records=execute(binary,repo,password,['backup','--json','--host','private-kit','--tag','rdc-private-v1','.'],cwd=stage)
        summaries=[r for r in (json.loads(line) for line in records.splitlines() if line) if r.get('message_type')=='summary']
        require(len(summaries)==1,'No unique completed private snapshot')
        snapshot=summaries[0].get('snapshot_id')
        repository(repo);execute(binary,repo,password,['check','--read-data'])
        restore_verified(binary,repo,password,snapshot,trusted,work/'proof')
        require(not output.exists() and not output.is_symlink(),'Destination appeared during private package preparation')
        os.rename(repo,output)
    return {'state':'private-package-sealed','snapshot_id':snapshot,'manifest_sha256':trusted,
            'restored_bytes':'verified','whole_site_recovery':'not-tested','readiness':'not-assessed'}


def inspect(repo,password,artifact,snapshot,trusted,*,output=None):
    supported();repo=repository(repo);private(repo.parent,directory=True)
    target=destination(output,[repo]) if output is not None else None
    password=credentials(password,[repo]+([target] if target else []))
    parent=target.parent if target else repo.parent
    with tempfile.TemporaryDirectory(prefix='.rdc-private-',dir=parent) as folder:
        work=Path(folder);binary=tool(work,artifact)
        execute(binary,repo,password,['check','--read-data'])
        data=restore_verified(binary,repo,password,snapshot,trusted,work/'material')
        if target:
            require(not target.exists() and not target.is_symlink(),'Restore destination appeared during verification')
            os.rename(work/'material',target)
    return {'state':'private-material-staged' if target else 'private-package-verified','files':len(data['files']),
            'restored_bytes':'verified','whole_site_recovery':'not-tested','readiness':'not-assessed','services':'not-started'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('seal','check','open'))
    parser.add_argument('source',type=Path)
    parser.add_argument('--output-dir',type=Path)
    parser.add_argument('--password-file',type=Path,required=True)
    parser.add_argument('--restic-artifact',type=Path,required=True)
    parser.add_argument('--snapshot')
    parser.add_argument('--manifest-sha256')
    args=parser.parse_args(argv)
    try:
        require((args.output_dir is not None)==(args.action!='check'),'Seal/open require a new output directory; check takes none')
        if args.action=='seal':result=seal(args.source,args.output_dir,args.password_file,args.restic_artifact)
        else:result=inspect(args.source,args.password_file,args.restic_artifact,args.snapshot,args.manifest_sha256,
                            output=args.output_dir if args.action=='open' else None)
        print(json.dumps(result,indent=2));return 0
    except (ValueError,OSError,subprocess.SubprocessError,KeyError,TypeError):
        # Raw exceptions may include institution paths or captured material.
        print('Private recovery package needs attention. Check input layout, private permissions, trusted identities and local artifact; no recovery success is claimed.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())

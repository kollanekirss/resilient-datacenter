#!/usr/bin/env python3
"""Standard-library offline bundle verification and explicit bootstrap entry point."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

# The verifier/bootstrap may itself reside on read-only transport media. Never
# write bytecode into that source tree before exact bundle membership is checked.
sys.dont_write_bytecode=True

MAX_FILE=64*1024**3
MAX_TOTAL=128*1024**3
MAX_MANIFEST=4*1024**2
TARGET='ubuntu-24.04-amd64-python3.12'


def require(condition,message):
    if not condition:raise ValueError(message)


def safe_path(name):
    require(isinstance(name,str) and 0<len(name)<=1024 and '\\' not in name and '\x00' not in name,'Invalid bundle path')
    p=PurePosixPath(name)
    require(not p.is_absolute() and all(v not in ('','.','..') for v in name.split('/')) and str(p)==name,'Unsafe bundle path')
    return name


def open_file(root,name):
    """Open every component relative to a no-follow directory descriptor."""
    safe_path(name)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parts=name.split('/')
        for part in parts[:-1]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=new
        result=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result);raise ValueError('Bundle entries must be regular files')
        return os.fdopen(result,'rb')
    finally:os.close(fd)


def digest(root,name,maximum=MAX_FILE):
    hashed=hashlib.sha256();size=0
    with open_file(root,name) as stream:
        require(os.fstat(stream.fileno()).st_size<=maximum,'Oversized bundle artifact')
        while chunk:=stream.read(1024**2):
            size+=len(chunk);require(size<=maximum,'Oversized bundle artifact');hashed.update(chunk)
    return {'size':size,'sha256':hashed.hexdigest()}


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate manifest field');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)


def validate(data):
    fields={'schema_version','kind','source_commit','target','scope','images','files','created_at'}
    require(isinstance(data,dict) and set(data)==fields,'Unknown bundle manifest schema')
    require(type(data['schema_version']) is int and data['schema_version']==1 and data['kind']=='portable-software','Unknown bundle manifest version')
    require(isinstance(data['source_commit'],str) and re.fullmatch('[a-f0-9]{40}',data['source_commit']),'Invalid source commit')
    require(data['target']==TARGET and data['scope']=='role-software','Unsupported bundle target or scope')
    require(isinstance(data['created_at'],str),'Invalid bundle time')
    try:stamp=datetime.fromisoformat(data['created_at'])
    except ValueError:raise ValueError('Invalid bundle time') from None
    require(stamp.tzinfo is not None,'Bundle time needs a timezone')
    require(isinstance(data['files'],dict) and 0<len(data['files'])<=30000,'Invalid bundle file count')
    total=0
    for name,item in data['files'].items():
        safe_path(name);require(name!='manifest.json','Manifest cannot include itself')
        require(isinstance(item,dict) and set(item)=={'size','sha256'},'Invalid artifact fields')
        require(type(item['size']) is int and 0<=item['size']<=MAX_FILE,'Invalid artifact size')
        require(isinstance(item['sha256'],str) and re.fullmatch('[a-f0-9]{64}',item['sha256']),'Invalid artifact digest')
        total+=item['size']
    require(total<=MAX_TOTAL,'Bundle exceeds supported size')
    require(isinstance(data['images'],dict) and len(data['images'])<=20,'Invalid image catalogue')
    for key,pin in data['images'].items():
        require(re.fullmatch('[a-f0-9]{64}',key) is not None,'Invalid image ID')
        require(isinstance(pin,dict) and set(pin)=={'reference','config_digest','path'},'Invalid image fields')
        require(isinstance(pin['reference'],str) and re.fullmatch(r'[a-z0-9./_-]+@sha256:'+key,pin['reference']),'Invalid image reference')
        require(isinstance(pin['config_digest'],str) and re.fullmatch('sha256:[a-f0-9]{64}',pin['config_digest']),'Invalid image configuration digest')
        require(pin['path']=='images/'+key,'Invalid image path')
    return data


def file_names(root):
    require(root.is_dir() and not root.is_symlink(),'Use a real bundle directory')
    result=set()
    for current,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:
            require(not (Path(current)/name).is_symlink(),'Linked bundle directory')
        for name in files:
            path=Path(current)/name
            require(stat.S_ISREG(path.lstat().st_mode),'Bundle entries must be regular files')
            result.add(path.relative_to(root).as_posix())
            require(len(result)<=30001,'Too many bundle artifacts')
    return result


def verify(root,expected_sha256):
    root=Path(root)
    require(isinstance(expected_sha256,str) and re.fullmatch('[a-f0-9]{64}',expected_sha256),'Supply the independently recorded manifest SHA256')
    try:
        require(root.is_dir() and not root.is_symlink(),'Use a real bundle directory')
        with open_file(root,'manifest.json') as stream:raw=stream.read(MAX_MANIFEST+1)
        require(len(raw)<=MAX_MANIFEST and hashlib.sha256(raw).hexdigest()==expected_sha256,'Bundle manifest differs from the trusted SHA256')
        data=validate(decode(raw))
        require(file_names(root)==set(data['files'])|{'manifest.json'},'Missing or unexpected bundle artifacts')
        for name,item in data['files'].items():require(digest(root,name,item['size'])==item,'Bundle artifact differs: '+name)
        return data
    except (OSError,UnicodeError,TypeError) as exc:
        raise ValueError('Cannot safely read the complete bundle') from exc


def report(root,expected_sha256):
    data=verify(root,expected_sha256)
    return {'state':'bundle-integrity-verified','source_commit':data['source_commit'],'files':len(data['files']),
            'scope':data['scope'],'private_recovery_material':'not-assessed','whole_site_recovery':'not-tested',
            'notice':'This verifies bytes against your trusted manifest hash, not publisher identity or successful recovery.'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('build','verify','bootstrap'))
    parser.add_argument('directory',type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--confirm-fresh-guest',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.action=='build':
            from offline_bundle_build import build
            result=build(args.directory)
        elif args.action=='verify':result=report(args.directory,args.manifest_sha256)
        else:
            require(args.confirm_fresh_guest,'Bootstrap installs role dependencies on this fresh guest; pass --confirm-fresh-guest after reviewing the target.')
            verify(args.directory,args.manifest_sha256)
            from offline_bundle_install import bootstrap
            result=bootstrap(args.directory,args.manifest_sha256)
        print(json.dumps(result,indent=2));return 0
    except (ValueError,OSError) as error:
        print('Offline bundle needs attention: '+str(error));return 1


if __name__=='__main__':raise SystemExit(main())

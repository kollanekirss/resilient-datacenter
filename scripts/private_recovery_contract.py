"""Private recovery inventory; content verification is distinct from readiness."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from offline_bundle import decode,digest,open_file,safe_path,require
from portable_plan import validate
from portable_network import derive

CATEGORIES={'configuration','edge','trust','tls','backup-access','application-backups','operator'}
MAX_FILES=30000
MAX_BYTES=128*1024**3


def local_path(value):
    path=Path(value)
    require(path.is_absolute() and '..' not in path.parts and path.resolve()==path,
            'Use an absolute local path without linked or parent components')
    return path


def private(path,*,directory=False):
    path=local_path(path);info=path.lstat()
    expected=stat.S_ISDIR if directory else stat.S_ISREG
    require(expected(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o077,
            'Recovery material must be private and owned by the current operator')
    if not directory:require(info.st_nlink==1,'Linked recovery files are not supported')
    return path


def small_json(root,name):
    with open_file(root,name) as stream:raw=stream.read(65537)
    require(len(raw)<=65536,'Recovery configuration is oversized')
    return decode(raw)


def unreadable(error):
    raise ValueError('Cannot read every recovery directory; no complete inventory is claimed') from None


def inventory(root,*,manifest=False):
    root=private(root,directory=True);result={};total=0
    require(set(p.name for p in root.iterdir())==CATEGORIES|({'manifest.json'} if manifest else set()),
            'Recovery input requires exactly the documented categories')
    for current,dirs,files in os.walk(root,followlinks=False,onerror=unreadable):
        for name in dirs:private(Path(current)/name,directory=True)
        for name in files:
            path=private(Path(current)/name)
            relative=path.relative_to(root).as_posix();safe_path(relative)
            if relative=='manifest.json':continue
            require(relative.split('/')[0] in CATEGORIES,'Unknown recovery category')
            before=path.stat();item=digest(root,relative)
            after=path.stat()
            require((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                    (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Recovery material changed during inspection')
            result[relative]=item;total+=item['size']
            require(len(result)<=MAX_FILES and total<=MAX_BYTES,'Recovery package exceeds supported size')
    require(all(any(n.startswith(category+'/') for n in result) for category in CATEGORIES),'Recovery category is empty')
    require({'configuration/site.json','configuration/network.json'}<=set(result),'Site and network settings are required')
    try:derive(validate(small_json(root,'configuration/site.json')),small_json(root,'configuration/network.json'))
    except (ValueError,TypeError,KeyError):raise ValueError('Recovery site and network settings are invalid') from None
    return result


def make_manifest(root):
    return {'schema_version':1,'kind':'private-recovery-material','captured_at':datetime.now(timezone.utc).isoformat(),
            'files':inventory(root)}


def write_manifest(root,data):
    raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
    require(len(raw)<=8*1024**2,'Recovery manifest is oversized')
    fd=os.open(Path(root)/'manifest.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def verify(root,trusted):
    require(isinstance(trusted,str) and re.fullmatch('[a-f0-9]{64}',trusted),'Provide the independently retained private manifest SHA256')
    root=private(root,directory=True)
    with open_file(root,'manifest.json') as stream:raw=stream.read(8*1024**2+1)
    require(len(raw)<=8*1024**2 and hashlib.sha256(raw).hexdigest()==trusted,'Private manifest differs from the trusted identity')
    data=decode(raw)
    require(isinstance(data,dict) and set(data)=={'schema_version','kind','captured_at','files'} and
            type(data['schema_version']) is int and data['schema_version']==1 and data['kind']=='private-recovery-material',
            'Unsupported private recovery manifest')
    require(isinstance(data['captured_at'],str) and datetime.fromisoformat(data['captured_at']).tzinfo is not None,
            'Invalid recovery capture time')
    require(data['files']==inventory(root,manifest=True),'Restored recovery material differs from the manifest')
    return data

"""Download pinned vendor media as data; never execute it on the preparation host."""
import bz2
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request
from portable_plan import require
from portable_state import directory, regular, write, lock
from proxmox_api import NoRedirect

CHUNK=4*1024*1024


def catalogue():
    return json.loads(Path(__file__).with_suffix('.json').read_text())


def fetch(url):
    require(url.startswith('https://'),'Media requires HTTPS.')
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(url,timeout=60)


def digest(stream,maximum,out=None):
    h=hashlib.sha256();total=0
    while True:
        data=stream.read(CHUNK)
        if not data:break
        total+=len(data);require(total<=maximum,'Media exceeds the pinned size or expansion limit.')
        h.update(data)
        if out:out.write(data)
    return h.hexdigest(),total


def identity(kind,cache):
    items=catalogue();require(kind in items,'Select ubuntu or opnsense media.')
    item=items[kind];raw=cache/(kind+'.download')
    with regular(raw) as stream:
        hashed,size=digest(stream,item['download_bytes'])
        require(hashed==item['sha256'] and size==item['download_bytes'],'Downloaded media does not match the pinned catalogue.')
        stream.seek(0)
        if item['compression']=='bz2':
            with bz2.BZ2File(stream,'rb') as decompressed:iso_hash,iso_size=digest(decompressed,item['iso_max_bytes'])
        else:iso_hash,iso_size=hashed,size
    return {'kind':kind,'version':item['version'],'source_sha256':item['sha256'],
            'sha256':iso_hash,'size':iso_size,'filename':kind+'.iso'}


def verify(cache,kind):
    cache=directory(cache)
    try:
        record=identity(kind,cache)
        with regular(cache/record['filename']) as stream:hashed,size=digest(stream,record['size'])
        require((hashed,size)==(record['sha256'],record['size']),'Prepared ISO differs from the verified source.')
        return record
    except (OSError,EOFError):raise ValueError('Media is incomplete or cannot be decompressed.') from None


def publish_stream(cache,target,reader,maximum,expected=None):
    fd,tmp=tempfile.mkstemp(prefix='.media-',dir=cache)
    try:
        with os.fdopen(fd,'wb') as out:
            hashed,size=digest(reader,maximum,out);out.flush();os.fsync(out.fileno())
        if expected:require((hashed,size)==expected,'Downloaded media does not match the pinned catalogue.')
        os.link(tmp,target)  # refuse overwrite, including a racing symlink
    except OSError:raise ValueError('Cannot publish media; inspect existing files and available disk space.') from None
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def prepare(kind,cache,*,open_url=fetch):
    items=catalogue();require(kind in items,'Select ubuntu or opnsense media.')
    item=items[kind]
    with lock(cache) as cache:
        raw=cache/(kind+'.download')
        try:
            if not raw.exists():
                with open_url(item['url']) as response:
                    publish_stream(cache,raw,response,item['download_bytes'],(item['sha256'],item['download_bytes']))
            record=identity(kind,cache);iso=cache/record['filename']
            if not iso.exists():
                if item['compression']=='none':os.link(raw,iso)
                else:
                    with regular(raw) as stream,bz2.BZ2File(stream,'rb') as decompressed:
                        publish_stream(cache,iso,decompressed,item['iso_max_bytes'],(record['sha256'],record['size']))
            result=verify(cache,kind);write(cache/(kind+'.json'),result)
            return result
        except (OSError,EOFError):raise ValueError('Media preparation failed; no unverified ISO is approved. Check connectivity, disk space and cached files.') from None

"""Allowlisted support reports and exclusive private-file publication."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
from operation_results import Check, check, message, CATALOGUE, OUTCOMES
from source_identity import safe_version, COMMIT


def make_report(checks: tuple[Check,...], identity: dict, platform_info: dict, *, generated_at: str) -> dict:
    source={'version':safe_version(identity.get('version')),'commit':None,'dirty':None,
            'provenance':'unverified','components':{}}
    commit=identity.get('commit')
    if isinstance(commit,str) and COMMIT.fullmatch(commit): source['commit']=commit
    if type(identity.get('dirty')) is bool: source['dirty']=identity['dirty']
    components=identity.get('components')
    if isinstance(components,dict):
        source['components']={k:safe_version(components.get(k)) for k in ('headscale','tailscale')}
    platform={}
    for key,allowed in {'system':('Linux','Darwin','Windows'),
                        'architecture':('x86_64','amd64','AMD64','arm64','aarch64')}.items():
        value=platform_info.get(key)
        platform[key]=value if isinstance(value,str) and value in allowed else 'unknown'
    try:
        timestamp=datetime.fromisoformat(generated_at)
        if timestamp.tzinfo is None: raise ValueError('Timezone required')
        timestamp=timestamp.astimezone(timezone.utc).isoformat()
    except (ValueError,TypeError,OverflowError): timestamp='unknown'
    records=[]
    for item in checks:
        if (isinstance(item,Check) and isinstance(item.code,str) and item.code in CATALOGUE and
            isinstance(item.outcome,str) and item.outcome in OUTCOMES and
            item.next_step==CATALOGUE[item.code][1]):
            safe=check(item.code,item.outcome)
        else: safe=check('check.unknown','unknown')
        records.append({'code':safe.code,'outcome':safe.outcome,'explanation':message(safe),'next_step':safe.next_step})
    return {'schema_version':1,'generated_at_utc':timestamp,'source':source,'platform':platform,'checks':records}


def write_report(path: Path, report: dict) -> None:
    path=Path(path).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('Unsafe report path')
    directory=path.parent
    info=directory.stat()  # Parent must already exist.
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o022:
        raise ValueError('Report directory must be private and owned by you')
    if path.exists(): raise FileExistsError('Report already exists')
    content=json.dumps(report,indent=2)+'\n'
    fd,temp=tempfile.mkstemp(prefix='.rdc-report-',dir=directory)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.link(temp,path)  # Exclusive publication, including competing writers/symlinks.
    finally:
        os.unlink(temp)

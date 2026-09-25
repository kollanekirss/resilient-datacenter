"""Bounded application diagnostics for disposable fixtures only; no request data."""
import json
import os
import re
from pathlib import Path


def safe_message(value):
    text=str(value)
    if any(term in text.lower() for term in ('password','secret','authorization','bearer','token=')):
        return '[sensitive diagnostic omitted]'
    text=re.sub(r'https?://[^\s<>"\']+', '[endpoint]', text)
    text=re.sub(r'[A-Za-z0-9_+/=-]{24,}', '[long value]', text)
    return text[:600]


def report(path):
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Diagnostics require a disposable GitHub-hosted fixture')
    path=Path(path)
    if not path.is_file():return
    with path.open('rb') as stream:
        stream.seek(max(0,path.stat().st_size-65536));raw=stream.read(65536)
    for line in raw.decode(errors='replace').splitlines()[-20:]:
        try:item=json.loads(line)
        except ValueError:continue
        record={'message':safe_message(item.get('message',''))}
        error=item.get('exception',{})
        if isinstance(error,dict):
            record['exception']={key:safe_message(error[key]) for key in ('Exception','Message','Code','File','Line') if key in error}
            record['frames']=[{key:frame[key] for key in ('file','line','class','function') if key in frame}
                              for frame in error.get('Trace',[])[:8] if isinstance(frame,dict)]
        print('Disposable file application diagnostic '+json.dumps(record),flush=True)

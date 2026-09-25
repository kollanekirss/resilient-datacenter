"""Pinned gateway identity and durable, monotonically revoked partner state.

The gateway receives public signed documents only. It never stores an
institution's approval signing key. Call mutations while holding lock().
"""
import json
import os
import time
from regional_workspace import Workspace,private_read,private_write
import regional_agreements as agreements
import gateway_contracts as contracts


def decode(raw):
    def unique(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate gateway state field')
            result[key]=value
        return result
    try:return json.loads(raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError):raise ValueError('Invalid gateway state JSON') from None


class Store(Workspace):
    def initialize(self,profile,identity):
        errors=contracts.validate(profile,identity)
        if errors:raise ValueError('; '.join(errors))
        created=False
        if not (self.base.exists() or self.base.is_symlink()):self.base.mkdir(mode=0o700);created=True
        with self.lock(wait_seconds=10):
            intent=self.base/'initialization.json'
            if not created and not intent.exists():raise ValueError('Existing directory is not an owned gateway')
            private_write(intent,agreements.canonical({'profile':profile,'identity':identity}))
            private_write(self.base/'identity.json',agreements.canonical(identity))
            private_write(self.base/'profile.json',agreements.canonical(profile))
            if not (self.base/'state.json').exists():
                if (self.base/'initialized.json').exists() or (self.base/'initialized.json').is_symlink():raise ValueError('Initialized gateway state is missing; do not recreate or discard its revocation history')
                self._write('state.json',{'schema_version':1,'generation':0,'agreements':[],'revoked_ids':[]})
            self.state()
            private_write(self.base/'initialized.json',b'{"schema_version":1}')

    def profile(self):
        self.check();profile=agreements.decode(private_read(self.base/'profile.json'))
        if contracts.validate(profile,self.identity()):raise ValueError('Stored gateway profile differs from its pinned identity')
        return profile

    def validate_state(self,state):
        if not isinstance(state,dict) or set(state)!={'schema_version','generation','agreements','revoked_ids'} or type(state['schema_version']) is not int or state['schema_version']!=1 or type(state['generation']) is not int or not 0<=state['generation']<2**53:raise ValueError('Unknown gateway state version')
        revoked=state['revoked_ids']
        if not isinstance(revoked,list) or len(revoked)>4096 or any(not agreements._hex(value,32) for value in revoked) or revoked!=sorted(set(revoked)):raise ValueError('Invalid gateway revocation catalogue')
        contracts.peer_rules(self.identity(),state['agreements'],revoked,now=0)
        return state

    def state(self):
        self.check();return self.validate_state(decode(private_read(self.base/'state.json')))

    def peers(self,state=None,*,now=None):
        state=self.state() if state is None else self.validate_state(state)
        return contracts.peer_rules(self.identity(),state['agreements'],state['revoked_ids'],now=int(time.time()) if now is None else now)

    def pending(self):
        self.check();path=self.base/'pending.json'
        if not (path.exists() or path.is_symlink()):return None
        candidate=self.validate_state(decode(private_read(path)));previous=self.state()
        if candidate['generation'] not in (previous['generation'],previous['generation']+1) or not set(previous['revoked_ids'])<=set(candidate['revoked_ids']):raise ValueError('Gateway transition history changed; keep regional access isolated')
        if candidate['generation']==previous['generation'] and candidate!=previous:raise ValueError('Committed gateway transition differs')
        return candidate

    def candidate(self,documents,revoked_ids,*,now):
        if self.pending():raise ValueError('Resume the pending gateway change before preparing another')
        previous=self.state()
        if not isinstance(revoked_ids,list) or any(not agreements._hex(value,32) for value in revoked_ids):raise ValueError('Use signed agreement identifiers for revocation')
        result={'schema_version':1,'generation':previous['generation']+1,'agreements':documents,'revoked_ids':sorted(set(previous['revoked_ids'])|set(revoked_ids))}
        self.validate_state(result);self.peers(result,now=now)
        return result

    def _write(self,name,state):private_write(self.base/name,json.dumps(state,sort_keys=True,separators=(',',':')).encode(),replace=True)

    def begin(self,candidate):
        self.validate_state(candidate);previous=self.state();pending=self.pending()
        if pending:
            if pending!=candidate:raise ValueError('Resume the exact pending gateway transition')
            return
        if candidate['generation']!=previous['generation']+1 or not set(previous['revoked_ids'])<=set(candidate['revoked_ids']):raise ValueError('Stale gateway transition or attempted revocation removal')
        self._write('pending.json',candidate)

    def commit(self,candidate):
        if self.pending()!=candidate:raise ValueError('Gateway state has no matching durable intent')
        self._write('state.json',candidate)

    def finish(self):
        if self.pending()!=self.state():raise ValueError('Gateway transition was not committed')
        (self.base/'pending.json').unlink()
        descriptor=os.open(self.base,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)

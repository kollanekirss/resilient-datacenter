"""Private operator approval workspace. It installs no gateway and grants no traffic."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import regional_agreements as contracts

PROFILE_FIELDS={'institution_id','regional_controller','gateway_node','gateway_ipv4','services'}


def private_read(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>512*1024:raise ValueError('Approval files must be regular, privately owned files')
    return path.read_bytes()


def private_write(path,raw,*,replace=False):
    if len(raw)>512*1024:raise ValueError('Approval workspace has reached its supported document limit')
    if path.exists() or path.is_symlink():
        previous=private_read(path)
        if not replace:
            if previous!=raw:raise ValueError('Existing approval resource differs; no identity was replaced')
            return
    descriptor,temporary=tempfile.mkstemp(prefix='.rdc-approval-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        descriptor=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def passphrase_bytes(passphrase):
    if not isinstance(passphrase,str) or not 12<=len(passphrase)<=256 or '\x00' in passphrase:raise ValueError('Use a signing-key passphrase of 12–256 characters')
    return passphrase.encode('utf-8')


class Workspace:
    def __init__(self,base):self.base=Path(base)

    def check(self):
        info=self.base.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Use a private approval directory owned by the current operator')

    @contextmanager
    def lock(self,*,wait_seconds=0):
        self.check()
        descriptor=os.open(self.base/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'a') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe approval workspace lock')
            if type(wait_seconds) not in (int,float) or not 0<=wait_seconds<=30:raise ValueError('Invalid bounded lock wait')
            deadline=time.monotonic()+wait_seconds
            while True:
                try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise BlockingIOError('Another administration operation is running; retry after it completes') from None
                    time.sleep(min(.05,max(0,deadline-time.monotonic())))
            yield

    def initialize(self,profile,passphrase):
        contracts._fields(profile,PROFILE_FIELDS,'regional-identity-request')
        password=passphrase_bytes(passphrase)
        # Validate public inputs before touching the workspace or generating its key.
        contracts.identity(b'\x01'*32,**{k:profile[k] for k in PROFILE_FIELDS})
        created=False
        if not (self.base.exists() or self.base.is_symlink()):
            self.base.mkdir(mode=0o700);created=True
        with self.lock():
            intent=self.base/'initialization.json'
            if not created and not intent.exists():raise ValueError('Existing directory has no owned initialization record')
            private_write(intent,contracts.canonical(profile))
            keypath=self.base/'signing-key.pem'
            if keypath.exists() or keypath.is_symlink():seed=self.private_seed(passphrase,check_identity=False)
            else:
                key=Ed25519PrivateKey.generate();seed=key.private_bytes_raw()
                encrypted=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password))
                private_write(keypath,encrypted)
            document=contracts.identity(seed,**{k:profile[k] for k in PROFILE_FIELDS})
            private_write(self.base/'identity.json',contracts.canonical(document))
            if not (self.base/'state.json').exists():self._save({'schema_version':1,'approved_peers':{},'agreements':{},'revoked_ids':[]})
            self._state()
        return {'state':'identity-prepared','fingerprint':contracts.fingerprint(document),'transport':'not-installed-or-verified'}

    def identity(self):
        self.check();document=contracts.decode(private_read(self.base/'identity.json'));contracts.verify_identity(document);return document

    def private_seed(self,passphrase,*,check_identity=True):
        self.check()
        try:key=serialization.load_pem_private_key(private_read(self.base/'signing-key.pem'),password=passphrase_bytes(passphrase))
        except (ValueError,TypeError):raise ValueError('Cannot unlock this signing key with the supplied passphrase') from None
        if not isinstance(key,Ed25519PrivateKey):raise ValueError('Unsupported signing key type')
        seed=key.private_bytes_raw()
        if check_identity and contracts.public_key(seed)!=self.identity()['payload']['public_key']:raise ValueError('Signing key differs from the public institution identity')
        return seed

    def _state(self):
        def unique(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError('Duplicate approval state key')
                result[key]=value
            return result
        try:data=json.loads(private_read(self.base/'state.json'),object_pairs_hook=unique)
        except (json.JSONDecodeError,UnicodeError,RecursionError):raise ValueError('Invalid approval workspace state') from None
        if not isinstance(data,dict) or set(data)!={'schema_version','approved_peers','agreements','revoked_ids'} or type(data['schema_version']) is not int or data['schema_version']!=1:raise ValueError('Unknown approval workspace state')
        if not isinstance(data['approved_peers'],dict) or len(data['approved_peers'])>128 or not isinstance(data['agreements'],dict) or len(data['agreements'])>256:raise ValueError('Approval workspace capacity exceeded')
        revoked=data['revoked_ids']
        if not isinstance(revoked,list) or len(revoked)>4096 or any(not contracts._hex(value,32) for value in revoked) or len(set(revoked))!=len(revoked):raise ValueError('Invalid durable revocation list')
        own=contracts.fingerprint(self.identity())
        for fingerprint,document in data['approved_peers'].items():
            if contracts.fingerprint(document)!=fingerprint or fingerprint==own:raise ValueError('Invalid approved peer identity')
        for identifier,document in data['agreements'].items():
            offered=contracts.verify_agreement(document)
            if identifier!=offered['agreement_id'] or own not in [contracts.fingerprint(offered[k]) for k in ('initiator','recipient')]:raise ValueError('Invalid stored agreement identity')
        return data

    def _save(self,state):private_write(self.base/'state.json',json.dumps(state,sort_keys=True,separators=(',',':')).encode(),replace=True)

    def export_identity(self):return contracts.canonical(self.identity())+b'\n'

    def approve(self,document,*,confirmed_fingerprint):
        fingerprint=contracts.fingerprint(document)
        if fingerprint!=confirmed_fingerprint or fingerprint==contracts.fingerprint(self.identity()):raise ValueError('Confirm the full independent peer fingerprint')
        if document['payload']['regional_controller']!=self.identity()['payload']['regional_controller']:raise ValueError('Peer belongs to another regional network')
        with self.lock():
            state=self._state()
            if fingerprint not in state['approved_peers'] and len(state['approved_peers'])>=128:raise ValueError('Peer capacity reached')
            state['approved_peers'][fingerprint]=document;self._save(state)
        return {'state':'peer-approved','peer_fingerprint':fingerprint,'transport':'not-installed-or-verified'}

    def offer(self,peer,services,*,passphrase,now,expires_at):
        with self.lock():
            state=self._state()
            if peer not in state['approved_peers']:raise ValueError('Independently approve the peer identity first')
            return contracts.offer(self.private_seed(passphrase),self.identity(),state['approved_peers'][peer],services,
                                   now=now,expires_at=expires_at,expected_peer=peer)

    def _parties(self,offered,state):
        own=self.identity();fingerprint=contracts.fingerprint(own)
        parties=[offered[k] for k in ('initiator','recipient')]
        local=[item for item in parties if contracts.fingerprint(item)==fingerprint]
        if local!=[own]:raise ValueError('Agreement does not match this exact local gateway/application identity')
        peer=next(item for item in parties if item!=own);peerprint=contracts.fingerprint(peer)
        if state['approved_peers'].get(peerprint)!=peer:raise ValueError('Independently approve this exact peer gateway/application identity first')
        return peerprint

    def accept(self,document,*,passphrase,now):
        offered=contracts.verify_offer(document)
        with self.lock():
            state=self._state();peer=self._parties(offered,state)
            if offered['agreement_id'] in state['revoked_ids']:raise ValueError('This agreement was locally revoked')
            accepted=contracts.accept(self.private_seed(passphrase),document,now=now,expected_peer=peer)
            self._store_agreement(accepted,state)
            return accepted

    def _store_agreement(self,document,state):
        offered=contracts.verify_agreement(document);identifier=offered['agreement_id']
        self._parties(offered,state)
        if identifier in state['revoked_ids']:raise ValueError('This agreement was locally revoked')
        if identifier not in state['agreements'] and len(state['agreements'])>=256:raise ValueError('Agreement capacity reached')
        if identifier in state['agreements'] and state['agreements'][identifier]!=document:raise ValueError('Existing agreement bytes differ')
        state['agreements'][identifier]=document;self._save(state)

    def import_agreement(self,document):
        with self.lock():self._store_agreement(document,self._state())
        return {'state':'agreement-recorded','transport':'not-installed-or-verified'}

    def revoke(self,identifier):
        with self.lock():
            state=self._state()
            if identifier not in state['agreements']:raise ValueError('Select an existing local agreement identifier')
            if identifier not in state['revoked_ids']:
                if len(state['revoked_ids'])>=4096:raise ValueError('Revocation capacity reached; reviewed archival is required')
                state['revoked_ids'].append(identifier);self._save(state)
        return {'state':'approval-revoked','agreement_id':identifier,'transport':'not-installed-or-verified'}

    def status(self,*,now):
        state=self._state();own=contracts.fingerprint(self.identity());summaries=[]
        for document in state['agreements'].values():
            result=contracts.evaluate(document,local_fingerprint=own,approved_peers=list(state['approved_peers']),revoked_ids=state['revoked_ids'],now=now)
            try:self._parties(document['offer']['payload'],state)
            except ValueError:
                if result['state']=='mutually-approved':result['state']='identity-review-required'
            summaries.append(result)
        return {'state':'approval-workspace','fingerprint':own,'approved_peers':len(state['approved_peers']),
                'agreements':summaries,'transport':'not-installed-or-verified'}

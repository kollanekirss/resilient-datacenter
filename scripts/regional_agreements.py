"""Strict, offline bilateral consent. Signatures never imply local trust or VPN access."""
import hashlib
import ipaddress
import json
import re
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from profile_config import _identifier
from validate_inventory import hostname

MAX_BYTES=32768
MAX_LIFETIME=90*86400
MAX_EPOCH=253402300799
SERVICES={'matrix','nextcloud'}


def _plain(value,depth=0):
    if depth>12:raise ValueError('Regional document is too deeply nested')
    if isinstance(value,dict):
        if len(value)>32 or any(not isinstance(k,str) or len(k)>64 for k in value):raise ValueError('Unsupported regional object')
        for item in value.values():_plain(item,depth+1)
    elif isinstance(value,list):
        if len(value)>32:raise ValueError('Oversized regional list')
        for item in value:_plain(item,depth+1)
    elif isinstance(value,str):
        if len(value)>8192 or any(ord(c)<32 or ord(c)>126 for c in value):raise ValueError('Regional documents require printable ASCII values')
    elif type(value) is int:
        if not 0<=value<=2**53-1:raise ValueError('Unsupported regional integer')
    else:raise ValueError('Regional documents do not support null, booleans or floating-point values')


def canonical(document):
    _plain(document)
    raw=json.dumps(document,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    if len(raw)>MAX_BYTES:raise ValueError('Regional document is oversized')
    return raw


def decode(raw):
    if not isinstance(raw,bytes) or len(raw)>MAX_BYTES:raise ValueError('Use a bounded UTF-8 regional document')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate regional document key')
            result[key]=value
        return result
    try:document=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs)
    except (UnicodeError,json.JSONDecodeError,RecursionError):raise ValueError('Invalid regional JSON document') from None
    if not isinstance(document,dict):raise ValueError('Regional document must be an object')
    canonical(document)
    return document


def _fields(data,fields,kind):
    if not isinstance(data,dict) or set(data)!=fields|{'kind','schema_version'} or data.get('kind')!=kind or type(data.get('schema_version')) is not int or data['schema_version']!=1:
        raise ValueError('Unsupported '+kind+' document')
    canonical(data)


def _hex(value,size):return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(size)+'}',value) is not None


def _private(seed):
    if not isinstance(seed,bytes) or len(seed)!=32:raise ValueError('Use a private Ed25519 seed')
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key(seed):return _private(seed).public_key().public_bytes_raw().hex()


def _message(payload):return b'RDC REGIONAL V1\x00'+payload['kind'].encode('ascii')+b'\x00'+canonical(payload)


def _sign(seed,payload):return {'payload':payload,'signature':_private(seed).sign(_message(payload)).hex()}


def _verify(document,key,kind):
    if not isinstance(document,dict) or set(document)!={'payload','signature'} or not _hex(document['signature'],128) or not _hex(key,64):raise ValueError('Invalid regional signature envelope')
    canonical(document)
    payload=document['payload']
    if not isinstance(payload,dict) or payload.get('kind')!=kind:raise ValueError('Regional signature domain differs')
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(document['signature']),_message(payload))
    except (InvalidSignature,ValueError):raise ValueError('Regional signature verification failed') from None
    return payload


def verify_identity(document):
    if not isinstance(document,dict) or not isinstance(document.get('payload'),dict):raise ValueError('Invalid institution identity')
    data=document['payload']
    _fields(data,{'institution_id','regional_controller','gateway_node','gateway_ipv4','services','public_key'},'regional-identity')
    if not _identifier(data['institution_id']) or not _identifier(data['gateway_node']) or not hostname(data['regional_controller']):raise ValueError('Invalid institution or regional controller name')
    address=data['gateway_ipv4']
    try:
        if not isinstance(address,str) or ipaddress.ip_address(address) not in ipaddress.ip_network('100.64.0.0/10') or address=='100.100.100.100':raise ValueError()
    except ValueError:raise ValueError('Gateway requires its enrolled regional overlay IPv4') from None
    services=data['services']
    if not isinstance(services,dict) or not services or not set(services)<=SERVICES or not all(hostname(v) for v in services.values()) or len(set(services.values()))!=len(services):raise ValueError('Declare distinct supported application domains')
    return _verify(document,data['public_key'],'regional-identity')


def fingerprint(document):return hashlib.sha256(bytes.fromhex(verify_identity(document)['public_key'])).hexdigest()


def identity(seed,*,institution_id,regional_controller,gateway_node,gateway_ipv4,services):
    payload={'kind':'regional-identity','schema_version':1,'institution_id':institution_id,'regional_controller':regional_controller,
             'gateway_node':gateway_node,'gateway_ipv4':gateway_ipv4,'services':dict(services),'public_key':public_key(seed)}
    document=_sign(seed,payload);verify_identity(document);return document


def verify_offer(document):
    if not isinstance(document,dict) or not isinstance(document.get('payload'),dict):raise ValueError('Invalid regional offer')
    data=document['payload']
    _fields(data,{'agreement_id','issued_at','expires_at','initiator','recipient','services'},'regional-offer')
    if not _hex(data['agreement_id'],32):raise ValueError('Invalid agreement identifier')
    if type(data['issued_at']) is not int or type(data['expires_at']) is not int or not 0<data['expires_at']-data['issued_at']<=MAX_LIFETIME:raise ValueError('Agreement must expire within 90 days of issue')
    _time(data['issued_at']);_time(data['expires_at'])
    left=verify_identity(data['initiator']);right=verify_identity(data['recipient'])
    if left['regional_controller']!=right['regional_controller']:raise ValueError('Parties belong to different regional controllers')
    if any(left[k]==right[k] for k in ('institution_id','gateway_ipv4','public_key')):raise ValueError('Agreement needs two distinct institutions and gateways')
    if set(left['services'].values())&set(right['services'].values()):raise ValueError('Institutions cannot claim the same application domain')
    scope=data['services']
    if not isinstance(scope,list) or not scope or any(not isinstance(v,str) for v in scope) or scope!=sorted(set(scope)) or not set(scope)<=set(left['services'])&set(right['services']):raise ValueError('Agreement scope must be a distinct supported set available at both parties')
    return _verify(document,left['public_key'],'regional-offer')


def offer(seed,initiator,recipient,services,*,now,expires_at,expected_peer):
    left=verify_identity(initiator)
    if left['public_key']!=public_key(seed):raise ValueError('Offer signing key differs from its institution identity')
    if fingerprint(recipient)!=expected_peer:raise ValueError('Recipient fingerprint was not independently confirmed')
    if not isinstance(services,list) or any(not isinstance(v,str) for v in services):raise ValueError('Use supported service names')
    payload={'kind':'regional-offer','schema_version':1,'agreement_id':uuid.uuid4().hex,'issued_at':now,'expires_at':expires_at,
             'initiator':initiator,'recipient':recipient,'services':sorted(services)}
    document=_sign(seed,payload);verify_offer(document);return document


def _time(now):
    if type(now) is not int or not 0<=now<=MAX_EPOCH:raise ValueError('Use an integer UTC evaluation time')


def accept(seed,document,*,now,expected_peer):
    _time(now);data=verify_offer(document)
    if verify_identity(data['recipient'])['public_key']!=public_key(seed):raise ValueError('Only the intended recipient can accept this offer')
    if fingerprint(data['initiator'])!=expected_peer:raise ValueError('Initiator fingerprint was not independently confirmed')
    if not data['issued_at']<=now<data['expires_at']:raise ValueError('Offer is not currently valid')
    payload={'kind':'regional-acceptance','schema_version':1,'offer_sha256':hashlib.sha256(canonical(document)).hexdigest(),'accepted_at':now}
    result={'kind':'regional-agreement','schema_version':1,'offer':document,'acceptance':_sign(seed,payload)}
    verify_agreement(result);return result


def verify_agreement(document):
    _fields(document,{'offer','acceptance'},'regional-agreement')
    offered=verify_offer(document['offer']);recipient=verify_identity(offered['recipient'])
    accepted=_verify(document['acceptance'],recipient['public_key'],'regional-acceptance')
    _fields(accepted,{'offer_sha256','accepted_at'},'regional-acceptance')
    if accepted['offer_sha256']!=hashlib.sha256(canonical(document['offer'])).hexdigest():raise ValueError('Acceptance refers to a different signed offer')
    if type(accepted['accepted_at']) is not int or not offered['issued_at']<=accepted['accepted_at']<offered['expires_at']:raise ValueError('Acceptance was outside the offer lifetime')
    return offered


def evaluate(document,*,local_fingerprint,approved_peers,revoked_ids,now):
    _time(now);data=verify_agreement(document)
    parties=[fingerprint(data[k]) for k in ('initiator','recipient')]
    if local_fingerprint not in parties:raise ValueError('This institution is not a party to the agreement')
    if not isinstance(approved_peers,(list,tuple,set,frozenset)) or not isinstance(revoked_ids,(list,tuple,set,frozenset)):raise ValueError('Use explicit local trust and revocation collections')
    if any(not _hex(v,64) for v in approved_peers) or any(not _hex(v,32) for v in revoked_ids):raise ValueError('Invalid local trust or revocation record')
    peer=parties[1-parties.index(local_fingerprint)]
    state='mutually-approved'
    if data['agreement_id'] in revoked_ids:state='revoked'
    elif now>=data['expires_at']:state='expired'
    elif now<document['acceptance']['payload']['accepted_at']:state='not-yet-valid'
    elif peer not in approved_peers:state='peer-not-approved'
    return {'state':state,'agreement_id':data['agreement_id'],'peer_fingerprint':peer,'services':list(data['services']),
            'expires_at':data['expires_at'],'transport':'not-verified'}

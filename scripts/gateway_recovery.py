"""A persistent approval floor prevents restored gateways replaying old consent."""
import json
import re
from regional_workspace import private_read,private_write
import regional_agreements as agreements

REFERENCE='recovery-required.json'


def marker_path(store):return store.base.parent/'rdc-gateway-recovery.json'


def reference(store):
    from gateway_store import decode
    path=store.base/REFERENCE
    if not (path.exists() or path.is_symlink()):return None
    data=decode(private_read(path))
    if not isinstance(data,dict) or set(data)!={'schema_version','gateway_fingerprint','approval_floor'} or type(data['schema_version']) is not int or data['schema_version']!=1 or data['gateway_fingerprint']!=agreements.fingerprint(store.identity()) or type(data['approval_floor']) is not int or not 0<data['approval_floor']<2**53:
        raise ValueError('Invalid gateway recovery history reference')
    return data


def load(store):
    from gateway_store import decode
    store.check();required=reference(store);path=marker_path(store)
    if not (path.exists() or path.is_symlink()):
        if required:raise ValueError('Gateway recovery history is missing; keep access closed')
        return None
    data=decode(private_read(path))
    if (not isinstance(data,dict) or set(data)!={'schema_version','gateway_fingerprint','transaction_id','approval_floor','review_pending'}
        or type(data['schema_version']) is not int or data['schema_version']!=1
        or data['gateway_fingerprint']!=agreements.fingerprint(store.identity())
        or not isinstance(data['transaction_id'],str) or not re.fullmatch('[a-f0-9]{32}',data['transaction_id'])
        or type(data['approval_floor']) is not int or not 0<data['approval_floor']<2**53
        or type(data['review_pending']) is not bool):raise ValueError('Invalid gateway recovery review record')
    if required and data['approval_floor']<required['approval_floor']:raise ValueError('Gateway recovery history went backwards')
    return data


def write_reference(store,record):
    private_write(store.base/REFERENCE,json.dumps({name:record[name] for name in ('schema_version','gateway_fingerprint','approval_floor')}).encode(),replace=True)


def suspend(store,transaction_id,*,now):
    """Called under recovery isolation before any restored service can start."""
    from gateway_store import decode
    previous=load(store)
    if not isinstance(transaction_id,str) or not re.fullmatch('[a-f0-9]{32}',transaction_id) or type(now) is not int or not 0<now<2**53:raise ValueError('Invalid gateway recovery transaction')
    floor=max(now,previous['approval_floor'] if previous else 0)
    clock=store.base/'clock.json'
    if clock.exists() or clock.is_symlink():
        checkpoint=decode(private_read(clock))
        if not isinstance(checkpoint,dict) or set(checkpoint)!={'schema_version','latest_utc'} or type(checkpoint['schema_version']) is not int or checkpoint['schema_version']!=1 or type(checkpoint['latest_utc']) is not int or not 0<=checkpoint['latest_utc']<2**53:raise ValueError('Invalid gateway clock history')
        floor=max(floor,checkpoint['latest_utc'])
    record={'schema_version':1,'gateway_fingerprint':agreements.fingerprint(store.identity()),'transaction_id':transaction_id,'approval_floor':floor,'review_pending':True}
    private_write(marker_path(store),json.dumps(record).encode(),replace=True)
    write_reference(store,record)
    return record


def fresh_documents(record,documents):
    if record is None:return True
    return all(document['offer']['payload']['issued_at']>=record['approval_floor'] and document['acceptance']['payload']['accepted_at']>=record['approval_floor'] for document in documents)


def review(store,candidate):
    record=load(store)
    if record is None or not record['review_pending']:return
    if store.pending()!=candidate or store.state()!=candidate:raise ValueError('Recovery review requires the matching committed policy intent')
    if not fresh_documents(record,candidate['agreements']):raise ValueError('Gateway recovery requires newly issued bilateral approvals')
    private_write(marker_path(store),json.dumps(dict(record,review_pending=False)).encode(),replace=True)

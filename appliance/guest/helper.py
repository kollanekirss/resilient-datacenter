"""Bounded stdin-only helper with durable exactly-once dispatch intent.

A process crash leaves pending intent. Inspection never replays mutations, and
operator recovery must establish the original outcome before a new operation.
"""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import re
import sys
from ..contracts import ApplianceError, canonical, fields, identity, require
from .. import state as records
from . import state as guest_state

MAX_BYTES=512*1024
ACTIONS={'connector':frozenset(('inspect','configure','enroll','verify','snapshot','snapshot-read','snapshot-cleanup')),
         'headscale':frozenset(('inspect','configure','enroll','verify','snapshot','snapshot-read','snapshot-cleanup')),
         'derp':frozenset(('inspect','configure','verify','snapshot','snapshot-read','snapshot-cleanup'))}
MUTATIONS=frozenset(('configure','enroll','snapshot','snapshot-cleanup'))
_PRIVATE=re.compile(r'(?:authorization|auth[_-]?key|private[_-]?key|key[_-]?pem|credential|password|secret|token)',re.I)


def _mutates(request):
    return request['action'] in MUTATIONS or (request['action']=='verify'
        and request['role'] in ('headscale','derp') and request.get('parameters',{}).get('reconnect') is True)


def _was_mutating(record):
    # Old records did not distinguish read-only verification from a reconnect.
    # Preserve uncertainty for hosted reconnects; connector verify never starts
    # a daemon and must remain available to reconcile a lost enrollment reply.
    return record.get('mutating',record.get('action') in MUTATIONS or
        (record.get('action')=='verify' and record.get('role') in ('headscale','derp')))


def _boot_id():
    try:value=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:raise ApplianceError('guest-boot-identity') from None
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value),'guest-boot-identity')
    return value


def validate_request(request):
    fields(request,{'schema','operation_id','plan_id','role','action','parameters'})
    require(request['schema']==1,'guest-request-schema')
    require(type(request['operation_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',request['operation_id']),'guest-operation-id')
    require(type(request['plan_id']) is str and re.fullmatch(r'[0-9a-f]{64}',request['plan_id']),'guest-plan-id')
    require(type(request['role']) is str and type(request['action']) is str and request['role'] in ACTIONS and request['action'] in ACTIONS[request['role']],'unsupported-guest-action')
    require(type(request['parameters']) is dict,'guest-parameters')
    if request['action']=='snapshot-cleanup':
        fields(request['parameters'],{'snapshot_id'})
        snapshot_id=request['parameters']['snapshot_id']
        require(type(snapshot_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',snapshot_id),'snapshot-id')
    require(len(canonical(request))<=MAX_BYTES,'guest-request-too-large')
    return request


def _unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'guest-json-duplicate');result[key]=value
    return result


def decode_request(raw):
    require(type(raw) is bytes and len(raw)<=MAX_BYTES,'guest-request-too-large')
    try:return validate_request(json.loads(raw,object_pairs_hook=_unique))
    except ApplianceError:raise
    except (ValueError,UnicodeError,RecursionError,TypeError):raise ApplianceError('guest-request-json') from None


def _private_values(value):
    found=[]
    if isinstance(value,dict):
        for key,item in value.items():
            if _PRIVATE.search(key):
                if isinstance(item,str) and len(item)>=4:found.append(item)
                elif isinstance(item,(dict,list)):found.extend(_private_values(item))
            else:found.extend(_private_values(item))
    elif isinstance(value,list):
        for item in value:found.extend(_private_values(item))
    return found


def _strings(value):
    if isinstance(value,str):return [value] if len(value)>=4 else []
    if isinstance(value,dict):return [s for item in value.values() for s in _strings(item)]
    if isinstance(value,list):return [s for item in value for s in _strings(item)]
    return []


def _safe_keys(value):
    if isinstance(value,dict):
        require(all(not _PRIVATE.search(key) for key in value),'guest-reply-private')
        for item in value.values():_safe_keys(item)
    elif isinstance(value,list):
        for item in value:_safe_keys(item)


def validate_reply(reply, request):
    allowed={'chunk_base64','offset','length','digest'} if request['action']=='snapshot-read' else set()
    fields(reply,{'operation_id','phase','code','observations'},allowed)
    require(reply['operation_id']==request['operation_id'],'guest-reply-binding')
    require(reply['phase'] in ('pending','complete','failed'),'guest-reply-phase')
    require(type(reply['code']) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,95}',reply['code']),'guest-reply-code')
    require(type(reply['observations']) is dict,'guest-reply-observations')
    raw=canonical(reply);require(len(raw)<=MAX_BYTES,'guest-response-too-large')
    _safe_keys(reply['observations'])
    require(not any(value in raw.decode() for value in _private_values(request['parameters'])),'guest-reply-private')
    if allowed & set(reply):
        require(allowed<=set(reply),'guest-data-reply')
        require(type(reply['offset']) is int and reply['offset']>=0 and type(reply['length']) is int and 0<=reply['length']<=256*1024,'guest-data-reply')
        require(type(reply['digest']) is str and re.fullmatch(r'[0-9a-f]{64}',reply['digest']) and type(reply['chunk_base64']) is str,'guest-data-reply')
    return reply


def _path(state, operation_id):
    require(type(operation_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',operation_id),'guest-operation-id')
    return Path(state)/'operations'/(operation_id+'.json')


def query_operation(operation_id,state):
    value=records.read(_path(state,operation_id))
    require(value.get('schema')==1 and value.get('operation_id')==operation_id,'guest-operation-record')
    return value['reply']


def reconcile_enrollment(operation_id,state,observations):
    """Trusted connector handler calls only after observing its original node.

    This changes no guest configuration and is never exposed as a request action.
    The connector's saved attempt/controller/prefs are the reconciliation proof.
    """
    path=_path(state,operation_id);record=records.read(path)
    require(record.get('role')=='connector' and record.get('action')=='enroll','guest-reconcile-action')
    request={'schema':1,'operation_id':operation_id,'plan_id':record['plan_id'],'role':'connector','action':'enroll','parameters':{}}
    bound=guest_state.binding(state,request)
    require(type(observations) is dict and observations.get('registered') is True and bool(observations.get('node_id')),'guest-reconcile-observation')
    reply={'operation_id':operation_id,'phase':'complete','code':'connector-enrollment-reconciled',
           'observations':{**observations,'machine_id':bound['machine_id'],'boot_id':_boot_id()}}
    validate_reply(reply,request)
    if record['reply']['phase']=='complete':
        require(record['reply']['observations']==reply['observations'],'guest-reconcile-changed')
        return record['reply']
    require(record['reply']['phase']=='pending','guest-reconcile-phase')
    records.write(path,{**record,'reply':reply})
    return reply


def _handler(role,action):
    module='snapshot' if action.startswith('snapshot') else role
    return importlib.import_module('appliance.guest.'+module).handle


def _preflight(request,state,runner):
    if request['action'].startswith('snapshot') or request['parameters'] in ({'runtime':True},{'query_operation':True}):return
    module=importlib.import_module('appliance.guest.'+request['role'])
    preflight=getattr(module,'preflight',None)
    if preflight is not None:preflight(request,Path(state),runner)


def dispatch(request,state,runner=None):
    validate_request(request);bound=guest_state.binding(state,request)
    if request['action']=='inspect' and request['parameters']=={'query_operation':True}:
        record=records.read(_path(state,request['operation_id']))
        require(record.get('role')==request['role'] and record.get('plan_id')==request['plan_id'],'guest-binding')
        return record['reply']
    with records.lock(Path(state)/'dispatch-lock'):
        path=_path(state,request['operation_id']);digest=identity(request)
        if path.exists():
            record=records.read(path)
            require(record.get('request_id')==digest,'guest-operation-reused')
            return record['reply']
        if _mutates(request):
            directory=Path(state)/'operations'
            if directory.exists():
                for existing in directory.glob('*.json'):
                    old=records.read(existing)
                    require(old.get('reply',{}).get('phase')!='pending' or not _was_mutating(old),'guest-operation-needs-inspection')
        if runner is None:
            from ..runner import Runner
            runner=Runner(max_output_bytes=MAX_BYTES)
        _preflight(request,state,runner)
        pending={'operation_id':request['operation_id'],'phase':'pending','code':'guest-operation-pending','observations':{}}
        record={'schema':1,'operation_id':request['operation_id'],'request_id':digest,'role':request['role'],
                'plan_id':request['plan_id'],'action':request['action'],'mutating':_mutates(request),'reply':pending}
        if request['action']=='snapshot-cleanup':record['snapshot_id']=request['parameters']['snapshot_id']
        records.write(path,record)
        try:
            if runner is None:
                from ..runner import Runner
                runner=Runner(max_output_bytes=MAX_BYTES)
            if request['action']=='inspect' and request['parameters']=={'runtime':True}:
                reply={'plan_id':bound['plan_id'],'role':bound['role'],'runtime':guest_state.inspect_runtime(state,runner)}
            else:reply=_handler(request['role'],request['action'])(request,Path(state),runner)
            if type(reply) is dict and not {'code','observations'}<=set(reply):
                data={key:reply.pop(key) for key in ('chunk_base64','offset','length','digest') if key in reply} if request['action']=='snapshot-read' else {}
                reply={'operation_id':request['operation_id'],'phase':reply.get('phase','complete'),'code':'ok','observations':reply,**data}
            if type(reply) is dict and type(reply.get('observations')) is dict:
                reply['observations']={**reply['observations'],'machine_id':bound['machine_id'],'boot_id':_boot_id()}
            validate_reply(reply,request)
            # Snapshot contents must never be retained in status journals.
            stored={k:v for k,v in reply.items() if k not in ('chunk_base64','offset','length','digest')}
            if 'chunk_base64' in reply:stored['code']='snapshot-data-not-retained'
            records.write(path,{**record,'reply':stored})
            return reply
        except ApplianceError:
            # Even command failures may have applied a mutation. Do not turn
            # uncertainty into an error record that would authorize replay.
            raise
        except Exception:raise ApplianceError('guest-operation-interrupted') from None


def main():
    operation='invalid-request'
    try:
        require(os.geteuid()==0,'guest-root-required')
        request=decode_request(sys.stdin.buffer.read(MAX_BYTES+1));operation=request['operation_id']
        from ..contracts import load_json
        state=Path('/var/lib/rdc-guest')
        seed=load_json(Path('/etc/rdc-guest.json'),limit=4096)
        guest_state.initialize(state,seed,Path('/etc/machine-id').read_text().strip())
        reply=dispatch(request,state)
    except ApplianceError as error:
        reply={'operation_id':operation,'phase':'failed','code':error.code,'observations':{}}
    except Exception:
        reply={'operation_id':operation,'phase':'failed','code':'guest-helper-failed','observations':{}}
    sys.stdout.buffer.write(canonical(reply)+b'\n')


if __name__=='__main__':main()

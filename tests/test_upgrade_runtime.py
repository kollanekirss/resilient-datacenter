import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_retire_checks_both_reviewed_owners_and_removes_only_stopped_container_ids():
    from upgrade_runtime import retire_containers
    from application_catalogue import for_owner
    from service_runtime import owner_digest,validate_container
    from test_upgrade_transaction import plan
    data=plan();calls=[];records={}
    for index,name in enumerate(('postgres','synapse')):
        owner=data['source_owner' if index==0 else 'target_owner']['applications']
        records[name]={'Id':str(index+1)*64,'Image':for_owner(owner)[name]['config_digest'],
            'Config':{'Labels':{'org.rdc.owner':owner_digest({'ownership':owner}),'org.rdc.component':name}},'State':{'Running':False}}
    def podman(*args):
        calls.append(args)
        if args[:2]==('container','inspect'):return json.dumps([records[args[2]]])
        return ''
    runtime=SimpleNamespace(UNITS={'postgres':'postgres','synapse':'synapse'},podman=podman,validate_container=validate_container)
    retire_containers(runtime,data)
    assert calls[-2:]==[('rm','1'*64),('rm','2'*64)]
    calls.clear();records['synapse']['State']['Running']=True
    with pytest.raises(ValueError):retire_containers(runtime,data)
    assert not any(c[0]=='rm' for c in calls)
    calls.clear();records['synapse']['State']['Running']=False
    records['synapse']['Config']['Labels']['org.rdc.owner']='foreign'
    with pytest.raises(ValueError):retire_containers(runtime,data)
    assert not any(c[0]=='rm' for c in calls)

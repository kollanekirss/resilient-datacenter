from copy import deepcopy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_ingress_requires_exact_interface_boundary():
    from service_runtime import ingress_entries,validate_ingress
    expected=ingress_entries('100.64.0.22')
    actual=deepcopy(expected)
    for item in actual:
        next(iter(item.values()))['handle']=123
    validate_ingress({'nftables':[{'metainfo':{'version':'fixture'}},*actual]},'100.64.0.22')
    for altered in (expected[:-1],expected+[expected[-1]],ingress_entries('100.64.0.23')):
        with pytest.raises(ValueError):validate_ingress({'nftables':altered},'100.64.0.22')
    altered=deepcopy(expected);altered[-1]['rule']['expr'][-1]={'accept':None}
    with pytest.raises(ValueError):validate_ingress({'nftables':altered},'100.64.0.22')
    altered=deepcopy(expected);altered[-1]['rule']['expr'][0]['match']['right']='eth0'
    with pytest.raises(ValueError):validate_ingress({'nftables':altered},'100.64.0.22')
    with pytest.raises(ValueError):ingress_entries('192.168.1.10')


def test_missing_ingress_is_not_healthy_and_existing_foreign_is_not_replaced(monkeypatch):
    import service_runtime as runtime
    calls=[]
    def nft(*args,input=None):
        calls.append((args,input));return {'nftables':[]}
    monkeypatch.setattr(runtime,'ingress_nft',nft)
    with pytest.raises(ValueError):runtime.application_ingress({'bind_address':'100.64.0.22'})
    assert len(calls)==1
    calls.clear()
    def foreign(*args,input=None):
        calls.append((args,input))
        if args==('-j','list','tables'):return {'nftables':[{'table':{'family':'inet','name':'rdc_application'}}]}
        return {'nftables':[]}
    monkeypatch.setattr(runtime,'ingress_nft',foreign)
    with pytest.raises(ValueError):runtime.application_ingress({'bind_address':'100.64.0.22'},create=True)
    assert all(input is None for _,input in calls)

import hashlib
import importlib
import os
import pytest
from test_gateway_store import fixture
from test_certificate_activation import validate


class Runtime:
    def __init__(self,store,fail=0):self.store=store;self.fail=fail;self.closed=False;self.restarts=0;self.probes=[]
    def close(self):self.closed=True
    def restart(self,service):self.restarts+=1
    def verify(self,hostname,fingerprint):
        self.probes.append((hostname,fingerprint))
        if self.fail:self.fail-=1;raise ValueError('Injected TLS failure')
    def reopen(self):
        assert not (self.store.base/'certificate-pending.json').exists()
        self.closed=False


def activate(store,cert=b'new',runtime=None,**kwargs):
    return importlib.import_module('gateway_certificates').activate_certificate(
        store,cert,b'key',runtime=runtime or Runtime(store),validator=validate,gid=os.getgid(),**kwargs)


def test_gateway_certificate_validates_every_pinned_domain_before_mutation(tmp_path):
    store,_=fixture(tmp_path);seen=[];m=importlib.import_module('gateway_certificates')
    names=sorted(store.identity()['payload']['services'].values())
    def check(cert,key,name):
        seen.append(name)
        if name==names[-1]:raise ValueError('Missing pinned name')
        return validate(cert,key,name)
    with pytest.raises(ValueError,match='Missing pinned name'):
        m.activate_certificate(store,b'new',b'key',initial=True,validator=check,runtime=Runtime(store),gid=os.getgid())
    assert seen==names
    assert not (store.base/'tls/active').exists()
    assert not (store.base/'certificate-pending.json').exists()


def test_gateway_tls_replacement_preserves_approval_state_and_verifies_all_names(tmp_path):
    store,_=fixture(tmp_path);before=(store.base/'state.json').read_bytes()
    activate(store,b'old',initial=True);runtime=Runtime(store)
    result=activate(store,runtime=runtime)
    assert result['state']=='active' and not runtime.closed
    assert (store.base/'tls/active/tls.crt').read_bytes()==b'new'
    assert (store.base/'tls/previous/tls.crt').read_bytes()==b'old'
    assert (store.base/'state.json').read_bytes()==before
    assert [name for name,_ in runtime.probes]==sorted(store.identity()['payload']['services'].values())


def test_gateway_tls_failed_activation_reopens_only_after_verified_rollback(tmp_path):
    store,_=fixture(tmp_path);activate(store,b'old',initial=True);runtime=Runtime(store,fail=1)
    from certificate_lifecycle import ActivationError
    with pytest.raises(ActivationError) as error:activate(store,runtime=runtime)
    assert error.value.recovered and not runtime.closed
    assert (store.base/'tls/active/tls.crt').read_bytes()==b'old'
    assert not (store.base/'certificate-pending.json').exists()


def test_gateway_tls_unverified_rollback_stays_closed_and_requires_same_intent(tmp_path):
    store,_=fixture(tmp_path);activate(store,b'old',initial=True);runtime=Runtime(store,fail=2)
    from certificate_lifecycle import ActivationError
    with pytest.raises(ActivationError) as error:activate(store,runtime=runtime)
    assert not error.value.recovered and runtime.closed
    pending=store.base/'certificate-pending.json';assert pending.exists()
    with pytest.raises(ValueError,match='same pending'):activate(store,b'different')
    result=activate(store)
    assert result['state']=='active' and not pending.exists()


def test_policy_intent_blocks_separate_certificate_transaction(tmp_path):
    store,document=fixture(tmp_path);activate(store,b'old',initial=True)
    from test_regional_agreements import NOW
    store.begin(store.candidate([document],[],now=NOW+2))
    with pytest.raises(ValueError,match='policy'):activate(store)
    assert (store.base/'tls/active/tls.crt').read_bytes()==b'old'


def test_initial_install_never_replaces_an_existing_gateway_certificate(tmp_path):
    store,_=fixture(tmp_path);activate(store,b'old',initial=True)
    with pytest.raises(ValueError,match='replacement'):
        activate(store,b'new',initial=True)
    assert (store.base/'tls/active/tls.crt').read_bytes()==b'old'


def test_reopening_failure_keeps_certificate_intent_closed(tmp_path):
    store,_=fixture(tmp_path);activate(store,b'old',initial=True)
    class CannotOpen(Runtime):
        def reopen(self):raise ValueError('Membership unavailable')
    runtime=CannotOpen(store)
    with pytest.raises(ValueError,match='Membership'):activate(store,runtime=runtime)
    assert runtime.closed and (store.base/'certificate-pending.json').exists()

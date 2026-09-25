import importlib
from copy import deepcopy
import pytest
from test_gateway_contracts import profile
from test_regional_agreements import agreement,NOW


def fixture(tmp_path):
    m=importlib.import_module('gateway_store');document,own,_=agreement();store=m.Store(tmp_path/'gateway')
    store.initialize(profile(),own)
    return store,document


def test_gateway_identity_is_pinned_and_journal_requires_explicit_resume(tmp_path):
    store,document=fixture(tmp_path);old=store.state();candidate=store.candidate([document],[],now=NOW+2)
    store.begin(candidate)
    assert store.pending() and store.state()==old
    with pytest.raises(ValueError):store.candidate([],[],now=NOW+2)
    store.commit(candidate);assert store.state()==candidate and store.pending()
    store.finish();assert not store.pending()
    store.initialize(profile(),store.identity())
    other=deepcopy(profile());other['lan_address']='10.203.1.2'
    with pytest.raises(ValueError):store.initialize(other,store.identity())


def test_gateway_revocation_is_monotonic_and_replayed_agreement_cannot_reopen(tmp_path):
    store,document=fixture(tmp_path);identifier=document['offer']['payload']['agreement_id']
    first=store.candidate([document],[],now=NOW+2);store.begin(first);store.commit(first);store.finish()
    revoked=store.candidate([], [identifier],now=NOW+3);store.begin(revoked);store.commit(revoked);store.finish()
    replay=store.candidate([document],[],now=NOW+4)
    assert replay['revoked_ids']==[identifier] and store.peers(replay,now=NOW+4)==[]
    with pytest.raises(ValueError):store.begin(first)
    # A tampered pending state cannot drop previously durable revocations.
    changed=deepcopy(replay);changed['revoked_ids']=[]
    with pytest.raises(ValueError):store.begin(changed)


def test_gateway_refuses_shared_state_or_symlink(tmp_path):
    store,_=fixture(tmp_path);path=store.base/'state.json';path.chmod(0o644)
    with pytest.raises(ValueError):store.state()
    path.unlink();path.symlink_to(tmp_path/'elsewhere')
    with pytest.raises(ValueError):store.state()


def test_missing_initialized_gateway_state_is_not_recreated_and_cannot_erase_revocations(tmp_path):
    store,_=fixture(tmp_path);identity=store.identity();(store.base/'state.json').unlink()
    with pytest.raises(ValueError):store.initialize(profile(),identity)


def test_operator_lock_can_wait_for_short_guard_without_losing_exclusion(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    store,_=fixture(tmp_path);started=Event();acquired=Event()
    def operator():
        started.set()
        with store.lock(wait_seconds=1):acquired.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with store.lock():
            future=pool.submit(operator);assert started.wait(1)
            assert not acquired.wait(.1)
        future.result(timeout=2)
    assert acquired.is_set()
    with store.lock():
        with pytest.raises(BlockingIOError):
            with store.lock(wait_seconds=.02):pass

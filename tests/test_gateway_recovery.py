import importlib
import json
import pytest
from test_gateway_store import fixture
from test_regional_agreements import NOW,pair
from regional_workspace import private_write


def fresh(now):
    import regional_agreements as agreements
    a,b,north,south=pair()
    offer=agreements.offer(a,north,south,['matrix','nextcloud'],now=now,expires_at=now+3600,expected_peer=agreements.fingerprint(south))
    return agreements.accept(b,offer,now=now+1,expected_peer=agreements.fingerprint(north))


def committed(store,documents,now,revoked=None):
    candidate=store.candidate(documents,revoked or [],now=now);store.begin(candidate);store.commit(candidate)
    return candidate


def test_recovered_gateway_requires_new_approval_and_keeps_floor_after_review(tmp_path):
    store,old=fixture(tmp_path);committed(store,[old],NOW+2);store.finish()
    recovery=importlib.import_module('gateway_recovery')
    recovery.suspend(store,'a'*32,now=NOW+10)
    assert store.recovery_pending() and store.peers(now=NOW+11)==[]
    with pytest.raises(ValueError,match='recovery'):
        store.candidate([old],[],now=NOW+11)
    document=fresh(NOW+11);candidate=committed(store,[document],NOW+13)
    store.review_recovery(candidate);store.finish()
    assert not store.recovery_pending() and len(store.peers(now=NOW+14))==1
    with pytest.raises(ValueError,match='recovery'):
        store.candidate([old],[],now=NOW+14)
    assert store.recovery()['approval_floor']==NOW+10


def test_recovery_cannot_forget_later_floor_or_erase_history(tmp_path):
    store,_=fixture(tmp_path);recovery=importlib.import_module('gateway_recovery')
    recovery.suspend(store,'a'*32,now=NOW+30)
    recovery.suspend(store,'b'*32,now=NOW+10)
    assert store.recovery()['approval_floor']==NOW+30
    (store.base.parent/'rdc-gateway-recovery.json').unlink()
    with pytest.raises(ValueError,match='history'):store.peers(now=NOW+40)


def test_recovery_review_requires_matching_committed_policy_intent(tmp_path):
    store,_=fixture(tmp_path);recovery=importlib.import_module('gateway_recovery')
    recovery.suspend(store,'a'*32,now=NOW+10)
    candidate=store.candidate([fresh(NOW+11)],[],now=NOW+13)
    with pytest.raises(ValueError):store.review_recovery(candidate)
    store.begin(candidate)
    with pytest.raises(ValueError):store.review_recovery(candidate)
    assert store.recovery_pending()


def test_recovery_marker_must_match_ownership_and_typed_floor(tmp_path):
    store,_=fixture(tmp_path);recovery=importlib.import_module('gateway_recovery')
    recovery.suspend(store,'a'*32,now=NOW+10)
    path=store.base.parent/'rdc-gateway-recovery.json';original=json.loads(path.read_text())
    for changes in ({'gateway_fingerprint':'f'*64},{'approval_floor':True},{'review_pending':'false'},{'extra':'field'}):
        private_write(path,json.dumps(dict(original,**changes)).encode(),replace=True)
        with pytest.raises(ValueError):store.recovery()

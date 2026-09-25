from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from operation_results import check


def test_restore_waits_for_actual_enrolled_identity(monkeypatch):
    from restore_runtime import verify_peer
    import local_checks
    states=iter([[check('client.stopped','fail')],[check('client.inspect_denied','unknown')],
                 [check('ownership.valid','pass'),check('client.verified','pass')]])
    calls=[]
    def inspect(manifest,**kwargs):calls.append(kwargs);return next(states)
    monkeypatch.setattr(local_checks,'inspect_local_checks',inspect)
    pauses=[];verify_peer({},attempts=3,pause=pauses.append)
    assert len(calls)==3 and pauses==[1,1]
    assert all(c=={'require_owned':True,'check_tls':False} for c in calls)


def test_restore_never_accepts_wrong_or_permanently_unverified_identity(monkeypatch):
    from restore_runtime import verify_peer
    import local_checks
    for result in ([check('ownership.mismatch','fail')],[check('client.awaiting_enrollment','unknown')],
                   [check('client.verified','pass'),check('client.state_mismatch','fail')],[]):
        monkeypatch.setattr(local_checks,'inspect_local_checks',lambda *args,**kwargs:result)
        with pytest.raises(ValueError):verify_peer({},attempts=2,pause=lambda _:None)

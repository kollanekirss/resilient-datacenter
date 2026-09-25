import importlib
import pytest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))


class Store:
    def __init__(self,events):self.events=events;self.pending=False
    def begin(self,candidate):self.events.append('journal');self.pending=True
    def commit(self,candidate):self.events.append('commit')
    def finish(self):self.events.append('finish');self.pending=False


class Runtime:
    def __init__(self,events,fail=None):self.events=events;self.fail=fail
    def step(self,name):
        self.events.append(name)
        if name==self.fail:raise ValueError('Injected '+name+' failure')
    def close(self):self.step('close')
    def validate(self,candidate):self.step('validate')
    def install(self,candidate):self.step('install')
    def restart(self):self.step('restart')
    def open(self,candidate):self.step('open')


def test_changes_journal_and_close_before_touching_approved_configuration():
    m=importlib.import_module('gateway_transition');events=[];store=Store(events)
    m.apply(store,Runtime(events),{'generation':2})
    assert events==['journal','close','validate','commit','install','restart','open','finish']
    assert not store.pending


@pytest.mark.parametrize('failure',['close','validate','install','restart','open'])
def test_failed_change_keeps_recovery_pending_and_never_reopens_previous_peers(failure):
    m=importlib.import_module('gateway_transition');events=[];store=Store(events)
    with pytest.raises(m.TransitionError):m.apply(store,Runtime(events,fail=failure),{'generation':2})
    assert store.pending and events[-1]=='close' and 'finish' not in events
    assert events.count('open')<=1

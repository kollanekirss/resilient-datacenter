import importlib
import json
import pytest
from test_nextcloud_regional import configuration
from test_nextcloud_runtime import settings


class Runtime:
    def __init__(self,connector,fail=False):self.connector=connector;self.fail=fail;self.internal=False
    def stop(self):self.internal=False
    def validate(self,config):pass
    def restart(self):
        if self.fail and self.connector.active(settings()) is not None:
            raise ValueError('injected activation failure')
        self.internal=True


def setup(tmp_path,monkeypatch):
    connector=importlib.import_module('nextcloud_regional')
    monkeypatch.setattr(connector,'BASE',tmp_path/'connector')
    monkeypatch.setattr(connector,'RESTORE',tmp_path/'no-restore')
    monkeypatch.setattr(connector.time,'time',lambda:1800000000)
    monkeypatch.setattr(connector.os,'chown',lambda *args:None)
    return connector,importlib.import_module('nextcloud_link')


def test_failed_file_attachment_remains_suspended_and_resumes_same_identity(tmp_path,monkeypatch):
    connector,module=setup(tmp_path,monkeypatch);runtime=Runtime(connector,fail=True)
    with pytest.raises(ValueError,match='injected'):
        module.transition(configuration(),settings(),runtime)
    assert runtime.internal
    assert connector.active(settings()) is None
    assert json.loads((connector.BASE/'pending.json').read_text())==configuration()
    assert (connector.BASE/'disabled.json').exists()
    runtime.fail=False;module.transition(configuration(),settings(),runtime)
    assert connector.active(settings())==configuration()
    assert not (connector.BASE/'pending.json').exists()


def test_file_attachment_refuses_different_pending_document_or_institution_key(tmp_path,monkeypatch):
    connector,module=setup(tmp_path,monkeypatch);runtime=Runtime(connector,fail=True)
    with pytest.raises(ValueError):module.transition(configuration(),settings(),runtime)
    original=(connector.BASE/'pending.json').read_bytes()
    different=dict(configuration(),peers=[])
    with pytest.raises(ValueError,match='same pending'):module.transition(different,settings(),runtime)
    assert (connector.BASE/'pending.json').read_bytes()==original
    different=dict(configuration(),gateway_fingerprint='b'*64)
    with pytest.raises(ValueError,match='identity'):module.transition(different,settings(),runtime)
    assert connector.active(settings()) is None


def test_file_attachment_recovers_empty_directory_interruption(tmp_path,monkeypatch):
    connector,module=setup(tmp_path,monkeypatch)
    connector.BASE.mkdir(mode=0o750)
    assert connector.configured(settings()) is None
    module.transition(configuration(),settings(),Runtime(connector))
    assert connector.active(settings())==configuration()


def test_disable_clears_first_attachment_journal_even_before_configuration_commit(tmp_path,monkeypatch):
    connector,module=setup(tmp_path,monkeypatch)
    class Invalid(Runtime):
        def validate(self,config):raise ValueError('native validation failed')
    with pytest.raises(ValueError,match='native validation'):
        module.transition(configuration(),settings(),Invalid(connector))
    assert connector.configured(settings()) is None
    assert (connector.BASE/'pending.json').exists()
    assert module.disable_transition(settings(),Runtime(connector))['state']=='connector-disabled'
    assert not (connector.BASE/'pending.json').exists()
    module.transition(dict(configuration(),peers=[]),settings(),Runtime(connector))
    assert connector.active(settings()) is None

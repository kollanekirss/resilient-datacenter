import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


@pytest.mark.parametrize('operation', ['request', 'upload'])
@pytest.mark.parametrize('reason,body,privilege', [
    ('Permission check failed (/vms/299, VM.Config.Options)', b'', 'VM.Config.Options'),
    ('Forbidden', b'{"message":"Permission check failed (/vms/299, VM.Config.Memory)","data":null}', 'VM.Config.Memory'),
    ('Permission check failed', b'', None),
    ('SECRET', b'{"message":"SECRET","errors":{"password":"SECRET"}}', None),
    ('Forbidden', b'<html>SECRET</html>', None),
    ('Forbidden', b'[' * 2000, None),
    ('Forbidden', b' ' * 5000 + b'SECRET', None),
    ('Permission check failed (/vms/299, SECRET)', b'', None),
], ids=['reason-privilege','body-privilege','bare-denial','private-json','html','deep-json','oversized','unknown-privilege'])
def test_http_permission_errors_are_actionable_bounded_and_private(monkeypatch, operation, reason, body, privilege):
    import io
    import urllib.error
    m = importlib.import_module('proxmox_api')
    stream = io.BytesIO(body)
    failure = urllib.error.HTTPError('https://SECRET/', 403, reason, {}, stream)
    class Denied:
        calls = 0
        def open(self, *args, **kwargs):
            self.calls += 1
            raise failure
    denied = Denied()
    monkeypatch.setattr(m.urllib.request, 'build_opener', lambda *args: denied)
    api = m.Client('https://pve.example.org:8006', {'token_id':'user@pve!rdc', 'token_secret':'SECRET'})
    with pytest.raises(ValueError) as error:
        if operation == 'request':
            api.request('POST', '/nodes/pve/qemu', {'vmid':299})
        else:
            api.upload('pve', 'local', 'rdc-' + 'a'*64 + '.iso', io.BytesIO(b'x'), 1, 'a'*64)
    message = str(error.value)
    assert '403' in message and 'permission' in message.lower()
    assert 'SECRET' not in message and len(message) < 700
    if privilege: assert privilege in message
    assert 'no automatic retry' in message.lower()
    assert denied.calls == 1
    assert stream.closed


@pytest.mark.parametrize('code,reason', [(401, 'authentication'), (500, 'task state'), (302, 'task state')])
def test_other_http_failures_show_status_without_raw_response(monkeypatch, code, reason):
    import io
    import urllib.error
    m = importlib.import_module('proxmox_api')
    class Failed:
        def open(self, *args, **kwargs):
            raise urllib.error.HTTPError('https://SECRET/', code, 'SECRET', {}, io.BytesIO(b'SECRET'))
    monkeypatch.setattr(m.urllib.request, 'build_opener', lambda *args: Failed())
    api = m.Client('https://pve.example.org', {'token_id':'user@pve!rdc','token_secret':'SECRET'})
    with pytest.raises(ValueError) as error: api.request('GET', '/version')
    assert str(code) in str(error.value) and reason in str(error.value).lower()
    assert 'SECRET' not in str(error.value)

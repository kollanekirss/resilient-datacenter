import base64
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appliance.contracts import ApplianceError
from appliance import state as records


def module():
    return importlib.import_module('appliance.guest.snapshot')


class ServiceRunner:
    def __init__(self, fail=None):
        self.calls, self.active, self.fail = [], True, fail

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1] == self.fail:
            raise ApplianceError('command-failed')
        if argv[1] == 'stop': self.active = False
        if argv[1] == 'start': self.active = True
        return SimpleNamespace(stdout=(b'active\n' if self.active else b'inactive\n'))


def test_failed_capture_still_restarts_original(tmp_path, monkeypatch):
    snapshot = module()
    def fail(*args, **kwargs): raise ApplianceError('capture-broken')
    monkeypatch.setattr(snapshot, 'capture_files', fail)
    runner = ServiceRunner()
    with pytest.raises(ApplianceError, match='role-capture-failed'):
        snapshot.snapshot_role('headscale', 'capture-one', tmp_path, runner)
    assert ['/usr/bin/systemctl', 'start', 'headscale.service'] in runner.calls
    result = records.read(tmp_path / 'snapshots/capture-one.json')
    assert result['capture_error'] == 'capture-broken'
    assert result['restart_error'] is None


def test_stop_timeout_still_attempts_restart(tmp_path):
    runner = ServiceRunner('stop')
    with pytest.raises(ApplianceError, match='role-capture-failed'):
        module().snapshot_role('headscale', 'capture-one', tmp_path, runner)
    assert any(call[1] == 'start' for call in runner.calls)


def test_capture_and_restart_failures_recorded_separately(tmp_path, monkeypatch):
    snapshot = module()
    def fail(*args, **kwargs): raise ApplianceError('capture-broken')
    monkeypatch.setattr(snapshot, 'capture_files', fail)
    with pytest.raises(ApplianceError, match='role-restart-failed'):
        snapshot.snapshot_role('headscale', 'capture-one', tmp_path, ServiceRunner('start'))
    result = records.read(tmp_path / 'snapshots/capture-one.json')
    assert result['capture_error'] == 'capture-broken'
    assert result['restart_error'] == 'command-failed'


def test_snapshot_read_binds_declared_bytes_and_bounds_chunks(tmp_path, monkeypatch):
    snapshot = module()
    monkeypatch.setattr(snapshot, 'capture_files', lambda *a: {
        'identity_id': 'a' * 64, 'versions': {'headscale': '0.29.4'},
        'files': {'role/config.json': b'{"secret":"private"}'}})
    result = snapshot.snapshot_role('headscale', 'capture-one', tmp_path, ServiceRunner())
    chunk = snapshot.snapshot_read('capture-one', 'role/config.json', 0, 8, state=tmp_path)
    assert base64.b64decode(chunk['chunk_base64']) == b'{"secret'
    assert chunk['length'] == 8 and chunk['offset'] == 0
    assert result['snapshot']['files']['role/config.json']['size_bytes'] == 20
    with pytest.raises(ApplianceError):
        snapshot.snapshot_read('capture-one', '../headscale/tls.key', 0, 8, state=tmp_path)
    with pytest.raises(ApplianceError):
        snapshot.snapshot_read('capture-one', 'role/config.json', 0, 262145, state=tmp_path)
    snapshot.snapshot_cleanup('capture-one', state=tmp_path)
    with pytest.raises(ApplianceError):
        snapshot.snapshot_read('capture-one', 'role/config.json', 0, 8, state=tmp_path)


def test_interrupted_capture_recovers_original_without_activating_copy(tmp_path):
    records.write(tmp_path / 'snapshots/capture-one.json',
        {'operation_id': 'capture-one', 'role': 'connector', 'phase': 'pending',
         'snapshot': None, 'capture_error': None, 'restart_error': None})
    runner = ServiceRunner()
    module().recover_snapshots(tmp_path, runner)
    assert runner.calls[0] == ['/usr/bin/systemctl', 'start', 'tailscaled.service']
    assert records.read(tmp_path / 'snapshots/capture-one.json')['phase'] == 'failed'


@pytest.mark.parametrize('operation', ['../bad', '', '/tmp/no', 'a' * 129])
def test_bad_id_cannot_stop_a_service(tmp_path, operation):
    runner = ServiceRunner()
    with pytest.raises(ApplianceError):
        module().snapshot_role('headscale', operation, tmp_path, runner)
    assert not runner.calls


def test_role_archive_round_trip_and_corruption_rejected():
    import hashlib
    from appliance.role_export import pack_role, unpack_role
    raw = b'private-authority-state'
    manifest = {'schema': 1, 'role': 'headscale', 'snapshot_id': 'capture-one',
        'identity_id': 'a' * 64, 'versions': {'headscale': '0.29.4'}, 'checked_at': 123,
        'capture_error': None, 'restart_error': None,
        'files': {'role/db.sqlite': {'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}}}
    archive = pack_role(manifest, {'role/db.sqlite': raw})
    restored, files = unpack_role(archive, role='headscale')
    assert restored == manifest and files['role/db.sqlite'] == raw
    with pytest.raises(ApplianceError): unpack_role(archive, role='derp')
    with pytest.raises(ApplianceError): unpack_role(archive[:600], role='headscale')
    manifest['restart_error'] = 'restart-failed'
    with pytest.raises(ApplianceError): pack_role(manifest, {'role/db.sqlite': raw})


def test_transport_corrupted_chunk_is_rejected_and_guest_cleaned(site, tmp_path, monkeypatch):
    import hashlib
    from appliance import guests
    from appliance.role_export import collect_roles
    site['roles']['connector']['selected'] = True
    site['vms']['connector'] = {'vmid': 103}
    calls = []
    def call(vmid, request, runner, **kwargs):
        calls.append(request['action'])
        parameters = request['parameters']
        if request['action'] == 'snapshot':
            observed = {'phase': 'complete', 'capture_error': None, 'restart_error': None,
                'snapshot': {'snapshot_id': request['operation_id'], 'files': {
                    'role/config.json': {'size_bytes': 4, 'sha256': hashlib.sha256(b'good').hexdigest()}}}}
        elif request['action'] == 'snapshot-read':
            observed = {'snapshot_id': parameters['snapshot_id'], 'relative_path': 'role/config.json',
                'offset': 1, 'length': 4, 'digest': hashlib.sha256(b'evil').hexdigest(),
                'chunk_base64': base64.b64encode(b'evil').decode()}
        else: observed = {'cleaned': True}
        return {'phase': 'complete', 'observations': observed}
    monkeypatch.setattr(guests, 'guest_call', call)
    with pytest.raises(ApplianceError, match='role-export-chunk-order'):
        collect_roles(site, object(), tmp_path, private=tmp_path)
    assert calls[-1] == 'snapshot-cleanup'


def test_export_rejects_role_state_not_matching_selected_roles(tmp_path):
    from appliance.export import pack
    from appliance.contracts import canonical
    material = {}
    for name in ('site.json', 'release.lock.json', 'build.json', 'vms.json', 'router.xml', 'host.json'):
        raw = canonical({'roles': {'connector': {'selected': True}}}) if name == 'site.json' else b'{}'
        (tmp_path / name).write_bytes(raw)
        (tmp_path / name).chmod(0o600)
        material[name] = tmp_path / name
    with pytest.raises(ApplianceError, match='export-role-state-missing'):
        pack(material)


def _snapshot_guest(tmp_path, monkeypatch, *, configured=True):
    from appliance.guest import helper, state as guest_state
    guest_state.initialize(tmp_path, {'schema': 1, 'plan_id': 'a' * 64,
        'role': 'headscale', 'vmid': 103}, '1' * 32)
    monkeypatch.setattr(helper, '_boot_id', lambda: '11111111-1111-1111-1111-111111111111')
    if configured:
        records.write(tmp_path / 'image.json', {'versions': {'headscale': '0.29.4'}})
        directory = tmp_path / 'headscale'
        records.write(directory / 'authority.json', {'tls_files': {
            'certificate': str(directory / 'tls.crt'), 'key': str(directory / 'tls.key'),
            'trust': str(directory / 'trust.pem')}})
        records.write(directory / 'config.json', {})
        records.write(directory / 'policy.json', {'acls': []})
        with records._directory_fd(directory) as fd:
            for name in ('noise.key', 'db.sqlite', 'tls.crt', 'tls.key', 'trust.pem'):
                records._write_at(fd, name, b'private-test-state')
    request = {'schema': 1, 'operation_id': 'capture-one', 'plan_id': 'a' * 64,
        'role': 'headscale', 'action': 'snapshot', 'parameters': {}}
    return helper, request


def test_known_capture_failure_closes_helper_journal_and_allows_cleanup(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch, configured=False)
    runner = ServiceRunner()
    reply = helper.dispatch(request, tmp_path, runner)
    assert reply['phase'] == 'failed' and reply['code'] == 'role-capture-failed'
    assert runner.active is True
    assert helper.query_operation('capture-one', tmp_path)['phase'] == 'failed'
    cleanup = {**request, 'operation_id': 'cleanup-one', 'action': 'snapshot-cleanup',
               'parameters': {'snapshot_id': 'capture-one'}}
    assert helper.dispatch(cleanup, tmp_path, runner)['phase'] == 'complete'
    assert helper.dispatch({**request, 'operation_id': 'capture-two'}, tmp_path, runner)['phase'] == 'failed'


@pytest.mark.parametrize('interrupted_write,expected_phase', [
    ('snapshot', 'failed'), ('helper', 'complete')])
def test_boot_recovers_capture_and_original_pending_helper_without_replay(
        tmp_path, monkeypatch, interrupted_write, expected_phase):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    runner, real_write = ServiceRunner(), records.write
    def interrupt(path, value):
        parent = 'snapshots' if interrupted_write == 'snapshot' else 'operations'
        if Path(path) == tmp_path / parent / 'capture-one.json' and (
                value.get('phase') == 'complete' or value.get('reply', {}).get('phase') == 'complete'):
            raise KeyboardInterrupt()
        return real_write(path, value)
    with monkeypatch.context() as crash:
        crash.setattr(records, 'write', interrupt)
        with pytest.raises(KeyboardInterrupt): helper.dispatch(request, tmp_path, runner)
    assert helper.query_operation('capture-one', tmp_path)['phase'] == 'pending'
    previous_stops = sum(call[1] == 'stop' for call in runner.calls)
    module().recover_snapshots(tmp_path, runner)
    assert helper.query_operation('capture-one', tmp_path)['phase'] == expected_phase
    assert sum(call[1] == 'stop' for call in runner.calls) == previous_stops
    assert not (tmp_path / 'snapshots/capture-one').exists()
    # The old operation reads back, while a genuinely new capture is allowed.
    assert helper.dispatch(request, tmp_path, runner)['phase'] == expected_phase
    assert helper.dispatch({**request, 'operation_id': 'capture-two'}, tmp_path, runner)['phase'] == 'complete'


@pytest.mark.parametrize('interrupted_write', ['snapshot', 'helper'])
def test_boot_finishes_interrupted_cleanup_and_releases_mutation_guard(tmp_path, monkeypatch, interrupted_write):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    runner, real_write = ServiceRunner(), records.write
    assert helper.dispatch(request, tmp_path, runner)['phase'] == 'complete'
    cleanup = {**request, 'operation_id': 'cleanup-one', 'action': 'snapshot-cleanup',
               'parameters': {'snapshot_id': 'capture-one'}}
    def interrupt(path, value):
        stop = (Path(path) == tmp_path / 'snapshots/capture-one.json' and value.get('phase') == 'cleaned'
                if interrupted_write == 'snapshot' else
                Path(path) == tmp_path / 'operations/cleanup-one.json' and value.get('reply', {}).get('phase') == 'complete')
        if stop: raise KeyboardInterrupt()
        return real_write(path, value)
    with monkeypatch.context() as crash:
        crash.setattr(records, 'write', interrupt)
        with pytest.raises(KeyboardInterrupt): helper.dispatch(cleanup, tmp_path, runner)
    assert helper.query_operation('cleanup-one', tmp_path)['phase'] == 'pending'
    module().recover_snapshots(tmp_path, runner)
    assert helper.query_operation('cleanup-one', tmp_path)['phase'] == 'complete'
    assert not (tmp_path / 'snapshots/capture-one').exists()
    assert helper.dispatch({**request, 'operation_id': 'capture-two'}, tmp_path, runner)['phase'] == 'complete'


def test_recovery_removes_owned_atomic_write_orphans(tmp_path):
    records.write(tmp_path / 'snapshots/capture-one.json', {'operation_id': 'capture-one',
        'role': 'headscale', 'phase': 'pending', 'snapshot': None,
        'capture_error': None, 'restart_error': None})
    directory = tmp_path / 'snapshots/capture-one'
    with records._directory_fd(directory, create=True) as fd:
        records._write_at(fd, '.record-' + 'a' * 32, b'partial-private-state')
    module().recover_snapshots(tmp_path, ServiceRunner())
    assert not directory.exists()
    assert records.read(tmp_path / 'snapshots/capture-one.json')['phase'] == 'failed'


@pytest.mark.parametrize('hostile', ['unexpected-name', 'symlink', 'hardlink', 'public-mode'])
def test_cleanup_rejects_hostile_capture_storage(tmp_path, monkeypatch, hostile):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    helper.dispatch(request, tmp_path, ServiceRunner())
    directory = tmp_path / 'snapshots/capture-one'
    path = directory / ('.record-' + 'a' * 32)
    if hostile == 'symlink': path.symlink_to(tmp_path / 'binding.json')
    elif hostile == 'hardlink':
        import os
        os.link(tmp_path / 'binding.json', path)
    else:
        if hostile == 'unexpected-name': path = directory / 'unexpected'
        path.write_bytes(b'hostile')
        path.chmod(0o644 if hostile == 'public-mode' else 0o600)
    with pytest.raises(ApplianceError): module().snapshot_cleanup('capture-one', state=tmp_path)
    assert path.lstat() and (tmp_path / 'binding.json').exists()


@pytest.mark.parametrize('mismatch', ['role', 'plan_id', 'request_id', 'snapshot_id'])
def test_recovery_does_not_reconcile_unbound_cleanup(tmp_path, monkeypatch, mismatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    helper.dispatch(request, tmp_path, ServiceRunner())
    cleanup = {**request, 'operation_id': 'cleanup-one', 'action': 'snapshot-cleanup',
               'parameters': {'snapshot_id': 'capture-one'}}
    from appliance.contracts import identity
    pending = {'schema': 1, 'operation_id': 'cleanup-one', 'request_id': identity(cleanup),
        'plan_id': request['plan_id'], 'role': 'headscale', 'action': 'snapshot-cleanup',
        'snapshot_id': 'capture-one', 'mutating': True,
        'reply': {'operation_id': 'cleanup-one', 'phase': 'pending',
                  'code': 'guest-operation-pending', 'observations': {}}}
    pending[mismatch] = {'role': 'derp', 'plan_id': 'b' * 64,
                         'request_id': 'c' * 64, 'snapshot_id': 'another-capture'}[mismatch]
    records.write(tmp_path / 'operations/cleanup-one.json', pending)
    with pytest.raises(ApplianceError): module().recover_snapshots(tmp_path, ServiceRunner())
    assert helper.query_operation('cleanup-one', tmp_path)['phase'] == 'pending'
    assert (tmp_path / 'snapshots/capture-one').exists()


def test_boot_recovery_holds_dispatch_lock_before_mutating_snapshot(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    helper.dispatch(request, tmp_path, ServiceRunner())
    with records.lock(tmp_path / 'dispatch-lock'):
        with pytest.raises(ApplianceError, match='operation-locked'):
            module().recover_snapshots(tmp_path, ServiceRunner())
    assert (tmp_path / 'snapshots/capture-one').exists()


def test_boot_closes_capture_interrupted_before_its_first_record_without_starting_service(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    runner, real_write = ServiceRunner(), records.write
    def interrupt(path, value):
        if Path(path) == tmp_path / 'snapshots/capture-one.json': raise KeyboardInterrupt()
        return real_write(path, value)
    with monkeypatch.context() as crash:
        crash.setattr(records, 'write', interrupt)
        with pytest.raises(KeyboardInterrupt): helper.dispatch(request, tmp_path, runner)
    assert helper.query_operation('capture-one', tmp_path)['phase'] == 'pending'
    module().recover_snapshots(tmp_path, runner)
    reply = helper.query_operation('capture-one', tmp_path)
    assert reply['phase'] == 'failed' and reply['code'] == 'snapshot-not-started'
    assert runner.calls == []
    assert helper.dispatch({**request, 'operation_id': 'capture-two'}, tmp_path, runner)['phase'] == 'complete'


def test_missing_cleanup_target_is_a_known_failure_without_poisoning_guest(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    cleanup = {**request, 'operation_id': 'cleanup-one', 'action': 'snapshot-cleanup',
               'parameters': {'snapshot_id': 'missing-capture'}}
    runner = ServiceRunner()
    reply = helper.dispatch(cleanup, tmp_path, runner)
    assert reply['phase'] == 'failed' and reply['code'] == 'snapshot-not-found'
    assert helper.query_operation('cleanup-one', tmp_path)['phase'] == 'failed'
    assert runner.calls == []
    assert helper.dispatch(request, tmp_path, runner)['phase'] == 'complete'


def test_boot_reconciles_cleanup_interrupted_before_reading_missing_target(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    cleanup = {**request, 'operation_id': 'cleanup-one', 'action': 'snapshot-cleanup',
               'parameters': {'snapshot_id': 'missing-capture'}}
    runner, real_read = ServiceRunner(), records.read
    def interrupt(path):
        if Path(path) == tmp_path / 'snapshots/missing-capture.json': raise KeyboardInterrupt()
        return real_read(path)
    with monkeypatch.context() as crash:
        crash.setattr(records, 'read', interrupt)
        with pytest.raises(KeyboardInterrupt): helper.dispatch(cleanup, tmp_path, runner)
    module().recover_snapshots(tmp_path, runner)
    reply = helper.query_operation('cleanup-one', tmp_path)
    assert reply['phase'] == 'failed' and reply['code'] == 'snapshot-not-found'
    assert runner.calls == []
    assert helper.dispatch(request, tmp_path, runner)['phase'] == 'complete'


def test_boot_rejects_snapshot_record_for_another_guest_role(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    helper.dispatch(request, tmp_path, ServiceRunner())
    path = tmp_path / 'snapshots/capture-one.json'
    record = records.read(path)
    records.write(path, {**record, 'role': 'derp'})
    runner = ServiceRunner()
    with pytest.raises(ApplianceError): module().recover_snapshots(tmp_path, runner)
    assert runner.calls == []
    assert (tmp_path / 'snapshots/capture-one').exists()


def test_abrupt_capture_exception_retains_valid_failed_outcome_for_boot_reconciliation(tmp_path, monkeypatch):
    helper, request = _snapshot_guest(tmp_path, monkeypatch)
    runner = ServiceRunner()
    def interrupt(*args): raise KeyboardInterrupt()
    with monkeypatch.context() as crash:
        crash.setattr(module(), 'capture_files', interrupt)
        with pytest.raises(KeyboardInterrupt): helper.dispatch(request, tmp_path, runner)
    assert runner.active is True
    assert helper.query_operation('capture-one', tmp_path)['phase'] == 'pending'
    # Finally ran, so its durable result must never claim complete with no data.
    assert records.read(tmp_path / 'snapshots/capture-one.json')['phase'] == 'failed'
    calls = list(runner.calls)
    module().recover_snapshots(tmp_path, runner)
    assert helper.query_operation('capture-one', tmp_path)['phase'] == 'failed'
    assert runner.calls == calls
    assert helper.dispatch({**request, 'operation_id': 'capture-two'}, tmp_path, runner)['phase'] == 'complete'

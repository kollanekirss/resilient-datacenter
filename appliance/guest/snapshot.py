"""Private, bounded role captures. Restoring files never starts an identity.

The original service is paused for capture and always restarted. Transfer uses
only manifest-declared names over the existing guest agent, never a WAN server.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from ..contracts import ApplianceError, fields, identity, integer, require
from .. import state as records

STATE = Path('/var/lib/rdc-guest')
MAX_BYTES = 6 * 1024 * 1024
MAX_CHUNK = 256 * 1024
SERVICES = {'connector': 'tailscaled.service', 'headscale': 'headscale.service', 'derp': 'derper.service'}


def _id(value):
    require(type(value) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', value)
            is not None, 'snapshot-id')
    return value


def _name(value):
    require(type(value) is str and len(value) < 200 and
            value.startswith(('role/', 'tailscale/', 'service/')) and
            all(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', p) and p not in ('.', '..')
                for p in value.split('/')) and not PurePosixPath(value).is_absolute(), 'snapshot-path')
    return value


def service_name(role):
    require(type(role) is str and role in SERVICES, 'snapshot-role')
    return SERVICES[role]


def _capture_tree(path, prefix, output):
    """Descriptor-relative traversal; reject links, foreign files and oversize state."""
    from ..files import _parent
    with _parent(Path('/'), str(Path(path).absolute() / '.snapshot-anchor')) as (directory, _):
        def visit(fd, relative, depth):
            require(depth <= 8, 'snapshot-depth')
            for name in sorted(os.listdir(fd)):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022,
                        'snapshot-file-owner')
                key = _name(relative + '/' + name)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        require(os.fstat(child).st_ino == info.st_ino, 'snapshot-file-changed')
                        visit(child, key, depth + 1)
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'snapshot-file-type')
                    require(len(output) < 256 and info.st_size <= MAX_BYTES, 'snapshot-size')
                    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    with os.fdopen(handle, 'rb') as source:
                        opened = os.fstat(source.fileno())
                        require((opened.st_ino, opened.st_dev) == (info.st_ino, info.st_dev), 'snapshot-file-changed')
                        raw = source.read(MAX_BYTES + 1)
                        after = os.fstat(source.fileno())
                    unchanged = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
                    require(unchanged(info) == unchanged(after) ==
                            unchanged(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'snapshot-file-changed')
                    require(len(raw) <= MAX_BYTES and sum(map(len, output.values())) + len(raw) <= MAX_BYTES,
                            'snapshot-size')
                    output[key] = raw
        visit(directory, prefix, 0)


def capture_files(role, state):
    service_name(role)
    path, files = Path(state) / role, {}
    _capture_tree(path, 'role', files)
    required = {'connector': {'role/identity.json', 'role/config.json'},
                'headscale': {'role/authority.json', 'role/config.json', 'role/policy.json',
                              'role/noise.key', 'role/db.sqlite'},
                'derp': {'role/identity.json', 'role/config.json', 'role/derper.key'}}[role]
    if role == 'connector':
        _capture_tree(Path('/var/lib/tailscale'), 'tailscale', files)
        required.add('tailscale/tailscaled.state')
        service = Path('/etc/systemd/system/tailscaled.service.d')
        if service.exists(): _capture_tree(service, 'service', files)
    require(required <= set(files), 'snapshot-incomplete-state')
    # SQLite sidecars, when present, are part of the same stopped-service copy.
    identity_name = 'authority.json' if role == 'headscale' else 'identity.json'
    role_identity = records.read(path / identity_name)
    if role in ('headscale', 'derp'):
        tls = role_identity.get('tls_files', {})
        require(type(tls) is dict and {'certificate', 'key', 'trust'} <= set(tls), 'snapshot-tls-missing')
        for key in ('certificate', 'key', 'trust'):
            try:
                relative = Path(tls[key]).relative_to(path).as_posix()
            except (ValueError, TypeError):
                raise ApplianceError('snapshot-tls-path') from None
            require(_name('role/' + relative) in files, 'snapshot-tls-missing')
    image = records.read(Path(state) / 'image.json')
    require(type(image.get('versions')) is dict and image['versions'], 'snapshot-versions')
    return {'identity_id': identity(role_identity), 'versions': image['versions'], 'files': files}


def _store(snapshot_id, captured, state):
    files = captured['files']
    require(type(files) is dict and 0 < len(files) <= 256 and
            all(type(v) is bytes for v in files.values()) and
            sum(map(len, files.values())) <= MAX_BYTES, 'snapshot-size')
    destination = Path(state) / 'snapshots' / snapshot_id
    manifest = {}
    for name, raw in sorted(files.items()):
        _name(name)
        digest = hashlib.sha256(raw).hexdigest()
        # Stored names are digests of logical paths, not guest supplied paths.
        with records._directory_fd(destination, create=True) as fd:
            records._write_at(fd, hashlib.sha256(name.encode()).hexdigest(), raw)
        manifest[name] = {'size_bytes': len(raw), 'sha256': digest}
    return {'schema': 1, 'snapshot_id': snapshot_id, 'identity_id': captured['identity_id'],
            'versions': captured['versions'], 'checked_at': int(time.time()), 'files': manifest}


def _restart(role, runner):
    unit = service_name(role)
    runner.run(['/usr/bin/systemctl', 'start', unit], timeout_s=30)
    status = runner.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'], timeout_s=10)
    require(status.stdout.strip() == b'active', 'role-not-active')


def _capture_record(record, snapshot_id):
    fields(record, {'operation_id', 'role', 'phase', 'snapshot', 'capture_error', 'restart_error'})
    require(record['operation_id'] == _id(snapshot_id), 'snapshot-record-binding')
    service_name(record['role'])
    require(record['phase'] in ('pending', 'complete', 'failed', 'cleaned'), 'snapshot-record-phase')
    for key in ('capture_error', 'restart_error'):
        value = record[key]
        require(value is None or type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,95}', value),
                'snapshot-record-error')
    failed = record['capture_error'] is not None or record['restart_error'] is not None
    require(record['phase'] != 'failed' or failed, 'snapshot-record-phase')
    require(record['phase'] not in ('pending', 'complete') or not failed, 'snapshot-record-phase')
    snapshot = record['snapshot']
    if snapshot is None:
        require(record['phase'] != 'complete', 'snapshot-record-manifest')
        return record
    require(record['phase'] in ('complete', 'failed'), 'snapshot-record-manifest')
    fields(snapshot, {'schema', 'snapshot_id', 'identity_id', 'versions', 'checked_at', 'files'})
    require(snapshot['schema'] == 1 and snapshot['snapshot_id'] == snapshot_id and
            type(snapshot['identity_id']) is str and re.fullmatch('[0-9a-f]{64}', snapshot['identity_id']) and
            type(snapshot['versions']) is dict and snapshot['versions'] and
            type(snapshot['checked_at']) is int and snapshot['checked_at'] > 0,
            'snapshot-record-manifest')
    require(type(snapshot['files']) is dict and 0 < len(snapshot['files']) <= 256, 'snapshot-record-manifest')
    total = 0
    for name, metadata in snapshot['files'].items():
        _name(name)
        fields(metadata, {'size_bytes', 'sha256'})
        total += integer(metadata['size_bytes'], 0, MAX_BYTES)
        require(type(metadata['sha256']) is str and re.fullmatch('[0-9a-f]{64}', metadata['sha256']),
                'snapshot-record-manifest')
    require(total <= MAX_BYTES, 'snapshot-size')
    return record


def _capture_reply(request, record):
    require(record['role'] == request['role'] and record['phase'] in ('complete', 'failed'),
            'snapshot-record-binding')
    code = ('role-restart-failed' if record['restart_error'] else
            'role-capture-failed' if record['capture_error'] else 'ok')
    return {'operation_id': request['operation_id'], 'phase': record['phase'],
            'code': code, 'observations': record}


def snapshot_role(role, operation_id, state, runner):
    _id(operation_id)
    unit = service_name(role)
    parent = Path(state) / 'snapshots'
    with records.lock(parent):
        record_path = parent / (operation_id + '.json')
        if record_path.exists():
            existing = records.read(record_path)
            require(existing.get('role') == role and existing.get('phase') == 'complete', 'snapshot-outcome-uncertain')
            return existing
        record = {'operation_id': operation_id, 'role': role, 'phase': 'pending',
                  'snapshot': None, 'capture_error': None, 'restart_error': None}
        records.write(record_path, record)
        # Until all bytes are stored, even an unexpected exception that reaches
        # finally must leave a failed outcome, never a complete empty capture.
        record['capture_error'] = 'capture-interrupted'
        try:
            runner.run(['/usr/bin/systemctl', 'stop', unit], timeout_s=30)
            stopped = runner.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'], timeout_s=10)
            require(stopped.stdout.strip() in (b'inactive', b'failed'), 'role-not-stopped')
            record['snapshot'] = _store(operation_id, capture_files(role, state), state)
            record['capture_error'] = None
        except (ApplianceError, OSError) as error:
            record['capture_error'] = error.code if isinstance(error, ApplianceError) else 'snapshot-io'
        finally:
            try:
                _restart(role, runner)
            except (ApplianceError, OSError) as error:
                record['restart_error'] = error.code if isinstance(error, ApplianceError) else 'snapshot-io'
            record['phase'] = 'failed' if record['capture_error'] or record['restart_error'] else 'complete'
            records.write(record_path, record)
        require(record['restart_error'] is None, 'role-restart-failed')
        require(record['capture_error'] is None, 'role-capture-failed')
        return record


def snapshot_read(snapshot_id, relative_path, offset, limit, *, state=STATE):
    _id(snapshot_id); _name(relative_path)
    integer(offset, 0, MAX_BYTES); integer(limit, 1, MAX_CHUNK)
    with records.lock(Path(state) / 'snapshots'):
        record = records.read(Path(state) / 'snapshots' / (snapshot_id + '.json'))
        require(record.get('phase') == 'complete', 'snapshot-not-complete')
        manifest = record['snapshot']['files']
        require(relative_path in manifest, 'snapshot-undeclared-file')
        from ..export import _private_bytes
        raw = _private_bytes(Path(state) / 'snapshots' / snapshot_id /
                             hashlib.sha256(relative_path.encode()).hexdigest(), MAX_BYTES)
        require(len(raw) == manifest[relative_path]['size_bytes'] and
                hashlib.sha256(raw).hexdigest() == manifest[relative_path]['sha256'], 'snapshot-content-changed')
        require(offset <= len(raw), 'snapshot-offset')
        chunk = raw[offset:offset + limit]
        return {'snapshot_id': snapshot_id, 'relative_path': relative_path, 'offset': offset,
                'length': len(chunk), 'digest': hashlib.sha256(chunk).hexdigest(),
                'chunk_base64': base64.b64encode(chunk).decode('ascii')}


def _remove_capture(snapshot_id, state):
    directory = Path(state) / 'snapshots' / snapshot_id
    try:
        directory.lstat()
    except FileNotFoundError:
        return
    with records._directory_fd(directory) as fd:
        names = os.listdir(fd)
        # Atomic writes can leave a private temporary after process/power loss.
        # Validate every entry before deleting any; arbitrary files stay visible.
        for name in names:
            require(re.fullmatch(r'(?:[0-9a-f]{64}|\.record-[0-9a-f]{32})', name), 'snapshot-storage-name')
            records._file_info(os.stat(name, dir_fd=fd, follow_symlinks=False))
        for name in names:
            os.unlink(name, dir_fd=fd)
        os.fsync(fd)
    directory.rmdir()
    with records._directory_fd(directory.parent) as fd:
        os.fsync(fd)


def snapshot_cleanup(snapshot_id, *, state=STATE):
    _id(snapshot_id)
    with records.lock(Path(state) / 'snapshots'):
        path = Path(state) / 'snapshots' / (snapshot_id + '.json')
        record = _capture_record(records.read(path), snapshot_id)
        require(record.get('phase') != 'pending', 'snapshot-outcome-uncertain')
        _remove_capture(snapshot_id, state)
        record.update(phase='cleaned', snapshot=None)
        records.write(path, record)


def _pending_snapshot_operations(state, captures):
    from . import helper, state as guest_state
    pending = []
    for path in sorted((Path(state) / 'operations').glob('*.json')):
        operation = records.read(path)
        if operation.get('action') not in ('snapshot', 'snapshot-cleanup') or operation.get('reply', {}).get('phase') != 'pending':
            continue
        operation_id, action = _id(path.stem), operation['action']
        snapshot_id = operation_id if action == 'snapshot' else _id(operation.get('snapshot_id'))
        require(operation.get('schema') == 1 and operation.get('operation_id') == operation_id,
                'snapshot-operation-binding')
        request = {'schema': 1, 'operation_id': operation_id, 'plan_id': operation.get('plan_id'),
                   'role': operation.get('role'), 'action': action,
                   'parameters': {} if action == 'snapshot' else {'snapshot_id': snapshot_id}}
        helper.validate_request(request)
        bound = guest_state.binding(state, request)
        require(operation.get('request_id') == identity(request), 'snapshot-operation-binding')
        if snapshot_id in captures:
            require(captures[snapshot_id]['role'] == request['role'], 'snapshot-operation-binding')
        elif action == 'snapshot':
            # Intent is durable before the first stop. No record and no stored
            # capture therefore proves the handler never reached that command.
            try:
                (Path(state) / 'snapshots' / snapshot_id).lstat()
            except FileNotFoundError:
                pass
            else:
                raise ApplianceError('snapshot-outcome-uncertain')
        helper.validate_reply(operation['reply'], request)
        pending.append((path, operation, request, bound, snapshot_id))
    return pending


def _finish_snapshot_operation(item, reply):
    from . import helper
    path, operation, request, bound, _ = item
    reply['observations'] = {**reply['observations'], 'machine_id': bound['machine_id'],
                             'boot_id': helper._boot_id()}
    helper.validate_reply(reply, request)
    records.write(path, {**operation, 'reply': reply})


def recover_snapshots(state, runner):
    """Recover original services and close proven journals; never replay captures."""
    parent, results = Path(state) / 'snapshots', []
    # Match helper dispatch's lock ordering so a live capture cannot race boot recovery.
    with records.lock(Path(state) / 'dispatch-lock'), records.lock(parent):
        captures = {path.stem: _capture_record(records.read(path), path.stem)
                    for path in sorted(parent.glob('*.json'))}
        try:
            (Path(state) / 'binding.json').lstat()
        except FileNotFoundError:
            pass  # Direct library callers may have no guest helper binding.
        else:
            bound = records.read(Path(state) / 'binding.json')
            require(all(record['role'] == bound.get('role') for record in captures.values()),
                    'snapshot-record-binding')
        pending = _pending_snapshot_operations(state, captures)
        for snapshot_id, record in captures.items():
            if record['phase'] == 'pending':
                try:
                    _restart(record['role'], runner)
                    record['restart_error'] = None
                except (ApplianceError, OSError) as error:
                    record['restart_error'] = error.code if isinstance(error, ApplianceError) else 'snapshot-io'
                _remove_capture(snapshot_id, state)
                record.update(phase='failed', capture_error='capture-interrupted', snapshot=None)
                records.write(parent / (snapshot_id + '.json'), record)
                results.append(dict(record))
        # Close the capture journal before discarding a completed manifest. A
        # crash between these writes still leaves enough durable evidence.
        for item in pending:
            if item[2]['action'] != 'snapshot': continue
            record = captures.get(item[4])
            if record is None or record['phase'] == 'cleaned':
                reply = {'operation_id': item[2]['operation_id'], 'phase': 'failed',
                         'code': 'snapshot-not-started' if record is None else 'snapshot-already-cleaned',
                         'observations': {'snapshot_id': item[4]}}
            else:
                reply = _capture_reply(item[2], record)
            _finish_snapshot_operation(item, reply)
        # Completed captures abandoned by a lost host/transport are private
        # temporary material too. Boot starts a fresh export, never restores it.
        for snapshot_id, record in captures.items():
            _remove_capture(snapshot_id, state)
            if record['phase'] == 'complete':
                record.update(phase='cleaned', snapshot=None)
                records.write(parent / (snapshot_id + '.json'), record)
                results.append(dict(record))
        for item in pending:
            if item[2]['action'] != 'snapshot-cleanup': continue
            record = captures.get(item[4])
            if record is None:
                _finish_snapshot_operation(item, {'operation_id': item[2]['operation_id'],
                    'phase': 'failed', 'code': 'snapshot-not-found', 'observations': {'snapshot_id': item[4]}})
                continue
            record.update(phase='cleaned', snapshot=None)
            records.write(parent / (item[4] + '.json'), record)
            _finish_snapshot_operation(item, {'operation_id': item[2]['operation_id'],
                'phase': 'complete', 'code': 'ok', 'observations': {'cleaned': True}})
    return results


def handle(request, state, runner):
    action, parameters = request['action'], request['parameters']
    if action == 'snapshot':
        fields(parameters, set())
        try:
            record = snapshot_role(request['role'], request['operation_id'], state, runner)
        except ApplianceError as error:
            if error.code not in ('role-capture-failed', 'role-restart-failed'): raise
            record = _capture_record(records.read(Path(state) / 'snapshots' /
                                     (request['operation_id'] + '.json')), request['operation_id'])
            require(record['phase'] == 'failed', 'snapshot-outcome-uncertain')
        return _capture_reply(request, record)
    if action == 'snapshot-read':
        fields(parameters, {'snapshot_id', 'relative_path', 'offset', 'limit'})
        return snapshot_read(**parameters, state=state)
    require(action == 'snapshot-cleanup', 'guest-action')
    fields(parameters, {'snapshot_id'})
    try:
        snapshot_cleanup(parameters['snapshot_id'], state=state)
    except ApplianceError as error:
        if error.code != 'state-file-missing': raise
        return {'operation_id': request['operation_id'], 'phase': 'failed',
                'code': 'snapshot-not-found', 'observations': {'snapshot_id': parameters['snapshot_id']}}
    return {'cleaned': True}

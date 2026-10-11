"""Transfer stopped-service snapshots over the private guest agent channel."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import secrets
import tarfile

from .contracts import ApplianceError, canonical, identity, require
from . import state
from .guest.snapshot import MAX_BYTES, MAX_CHUNK, _name


def pack_role(manifest, files):
    validate_role(manifest, files)
    data = {'manifest.json': canonical(manifest), **files}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(data.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o600
            archive.addfile(member, io.BytesIO(raw))
    raw = output.getvalue()
    require(len(raw) <= MAX_BYTES + 256 * 1024, 'role-export-size')
    return raw


def validate_role(manifest, files):
    from .guest.snapshot import _id, service_name
    require(type(manifest) is dict and manifest.get('schema') == 1, 'role-export-manifest')
    service_name(manifest.get('role'))
    _id(manifest.get('snapshot_id'))
    require(type(manifest.get('identity_id')) is str and len(manifest['identity_id']) == 64 and
            type(manifest.get('versions')) is dict and manifest['versions'] and
            type(manifest.get('checked_at')) is int and manifest['checked_at'] > 0 and
            manifest.get('restart_error') is None and manifest.get('capture_error') is None,
            'role-export-manifest')
    expected = manifest.get('files')
    require(type(files) is dict and type(expected) is dict and 0 < len(files) <= 256 and
            set(files) == set(expected), 'role-export-members')
    require(all(type(v) is bytes for v in files.values()) and sum(map(len, files.values())) <= MAX_BYTES,
            'role-export-size')
    for name, raw in files.items():
        _name(name)
        require(expected[name] == {'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                'role-export-content')


def unpack_role(raw, *, role):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES + 256 * 1024 and len(raw) % 512 == 0,
            'role-export-archive')
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(member.name not in files and member.isfile() and member.mode == 0o600 and
                        not member.pax_headers and 0 <= member.size <= MAX_BYTES and len(files) < 257,
                        'role-export-member')
                if member.name != 'manifest.json': _name(member.name)
                files[member.name] = archive.extractfile(member).read(member.size + 1)
                require(sum(map(len, files.values())) <= MAX_BYTES + 65536, 'role-export-size')
        from .contracts import _unique
        manifest = json.loads(files.pop('manifest.json'), object_pairs_hook=_unique)
        require(manifest.get('role') == role, 'role-export-role')
        validate_role(manifest, files)
        return manifest, files
    except (tarfile.TarError, KeyError, ValueError, UnicodeError, OSError) as error:
        if isinstance(error, ApplianceError): raise
        raise ApplianceError('role-export-archive') from None


def collect_roles(plan, runner, staging, *, private=Path('/var/lib/rdc-appliance/private')):
    from .guests import guest_call
    output = {}
    with state._directory_fd(staging, create=True): pass
    for role in ('connector', 'headscale', 'derp'):
        if not plan['roles'][role]['selected']: continue
        operation_id = 'capture-' + secrets.token_hex(16)
        vmid = plan['vms'][role]['vmid']

        def call(action, parameters):
            request = {'schema': 1, 'operation_id': operation_id if action == 'snapshot' else secrets.token_hex(16),
                       'plan_id': identity(plan), 'role': role, 'action': action, 'parameters': parameters}
            reply = guest_call(vmid, request, runner, state=private)
            require(reply.get('phase') == 'complete', 'role-export-guest-failed')
            return {**reply['observations'], **{key: reply[key] for key in
                    ('chunk_base64', 'offset', 'length', 'digest') if key in reply}}

        captured = None
        try:
            captured = call('snapshot', {})
            require(captured.get('phase') == 'complete' and captured.get('capture_error') is None and
                    captured.get('restart_error') is None, 'role-export-capture-failed')
            manifest = captured['snapshot']
            require(manifest.get('snapshot_id') == operation_id, 'role-export-snapshot-id')
            require(type(manifest.get('files')) is dict and 0 < len(manifest['files']) <= 256,
                    'role-export-manifest')
            content, total = {}, 0
            for name, metadata in manifest['files'].items():
                _name(name)
                size = metadata.get('size_bytes')
                require(type(size) is int and 0 <= size <= MAX_BYTES, 'role-export-size')
                total += size
                require(total <= MAX_BYTES, 'role-export-size')
                chunks, offset = [], 0
                while offset < size:
                    chunk = call('snapshot-read', {'snapshot_id': operation_id,
                                 'relative_path': name, 'offset': offset, 'limit': min(MAX_CHUNK, size - offset)})
                    require(chunk.get('snapshot_id') == operation_id and chunk.get('relative_path') == name and
                            chunk.get('offset') == offset, 'role-export-chunk-order')
                    try:
                        raw = base64.b64decode(chunk['chunk_base64'], validate=True)
                    except (ValueError, KeyError):
                        raise ApplianceError('role-export-chunk') from None
                    require(0 < len(raw) <= min(MAX_CHUNK, size - offset) and chunk.get('length') == len(raw) and
                            chunk.get('digest') == hashlib.sha256(raw).hexdigest(), 'role-export-chunk')
                    chunks.append(raw); offset += len(raw)
                content[name] = b''.join(chunks)
            manifest = {**manifest, 'role': role, 'plan_id': identity(plan), 'capture_error': None, 'restart_error': None}
            raw = pack_role(manifest, content)
            name = 'role-' + role + '.tar'
            with state._directory_fd(staging) as fd:
                state._write_at(fd, name, raw)
            output[name] = Path(staging) / name
        finally:
            # Cleanup is an idempotent action with a fresh request ID, never a
            # second capture. Missing/uncertain capture stays a visible failure.
            call('snapshot-cleanup', {'snapshot_id': operation_id})
    return output

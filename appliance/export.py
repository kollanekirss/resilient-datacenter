"""Bounded private base-configuration export, separate from activation.

Restic provides encryption. A package is published only after independently
reading its exact snapshot back and verifying every captured byte. No VM disks,
role identities, application data or whole-site recovery are claimed here.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile

from .contracts import ApplianceError, canonical, require
from . import state

COMPONENTS = {'site.json', 'release.lock.json', 'build.json', 'vms.json', 'router.xml', 'host.json'}
MAX_BYTES = 8 * 1024 * 1024


def _private_bytes(path, limit=MAX_BYTES, *, readonly=False):
    path = Path(path)
    with state._directory_fd(path.parent) as fd:
        with _private_stream(fd, path.name, readonly=readonly) as stream:
            raw = stream.read(limit + 1)
            require(len(raw) <= limit, 'export-size')
            return raw


@contextmanager
def _private_stream(fd, name, *, readonly=False):
    def check(info):
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in ({0o400, 0o600} if readonly else {0o600}), 'export-input-private')
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    check(before)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(descriptor, 'rb') as stream:
        check(os.fstat(stream.fileno()))
        require(os.fstat(stream.fileno()).st_ino == before.st_ino, 'export-input-changed')
        yield stream
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'export-input-changed')


def pack(files):
    require(type(files) is dict and set(files) == COMPONENTS, 'export-components')
    content = {name: _private_bytes(path) for name, path in files.items()}
    require(sum(map(len, content.values())) <= MAX_BYTES - 65536, 'export-size')
    manifest = {'schema': 1, 'kind': 'appliance-base-config', 'files': {
        name: {'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for name, raw in content.items()}}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(content.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o600
            archive.addfile(member, io.BytesIO(raw))
    raw = output.getvalue()
    require(len(raw) <= MAX_BYTES, 'export-size')
    return raw, manifest


def unpack(raw, manifest):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES and len(raw) % 512 == 0, 'export-archive')
    require(type(manifest) is dict and set(manifest) == {'schema', 'kind', 'files'}
            and manifest['schema'] == 1 and manifest['kind'] == 'appliance-base-config'
            and type(manifest['files']) is dict and set(manifest['files']) == COMPONENTS, 'export-manifest')
    files, total = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(member.name in COMPONENTS and member.name not in files and member.isfile()
                        and member.mode == 0o600 and not member.pax_headers and 0 <= member.size <= MAX_BYTES, 'export-member')
                total += member.size
                require(total <= MAX_BYTES, 'export-size')
                data = archive.extractfile(member).read(member.size + 1)
                require({'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        == manifest['files'][member.name], 'export-content-mismatch')
                files[member.name] = data
    except (tarfile.TarError, ValueError, OSError):
        raise ApplianceError('export-archive') from None
    require(set(files) == COMPONENTS, 'export-components')
    return files


def _tool(binary=None, release=None):
    from .contracts import load_json
    from .media import verify_file
    from .plan import validate_release
    lock = validate_release(release or load_json(Path(__file__).parent / 'releases/v1.lock.json'), production=True)
    records = [item for item in lock['components'] if item['id'] == 'restic']
    require(len(records) == 1, 'export-restic-missing')
    binary = Path(binary or '/usr/lib/rdc-appliance/restic')
    require(binary.is_absolute() and binary.resolve() == binary and os.access(binary, os.X_OK), 'export-restic-path')
    verify_file(binary, records[0].get('expanded', records[0]))
    return binary


def _new_destination(path):
    path = Path(path).absolute()
    require('..' not in path.parts and path.resolve() == path and not path.exists(), 'export-destination')
    with state._directory_fd(path.parent):
        pass
    return path


def _password(path, excluded):
    path = Path(path).absolute()
    require(all(path != Path(other).absolute() and Path(other).absolute() not in path.parents
                for other in excluded), 'export-password-separate')
    raw = _private_bytes(path, 4096)
    require(16 <= len(raw) <= 4096 and len(raw.strip()) >= 16, 'export-password')
    return path


def _run(runner, binary, repo, password, args, *, stdin=b''):
    return runner.run([str(binary), '--repo', str(repo), '--password-file', str(password),
                       '--no-cache', *args], stdin=stdin, timeout_s=3600).stdout


def _ciphertext_identity(repo):
    # Includes filenames and sizes to bind the complete local repository.
    hashes, total = {}, 0
    require(repo.resolve() == repo, 'export-repository')
    for current, directories, filenames in os.walk(repo, followlinks=False):
        require(len(hashes) + len(directories) + len(filenames) <= 100000, 'export-repository-size')
        for name in directories:
            with state._directory_fd(Path(current) / name):
                pass
        for name in filenames:
            path = Path(current) / name
            raw = _private_bytes(path, 64 * 1024 * 1024, readonly=True)
            total += len(raw)
            require(total <= 256 * 1024 * 1024, 'export-repository-size')
            hashes[path.relative_to(repo).as_posix()] = {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
    require('config' in hashes, 'export-repository')
    return hashlib.sha256(canonical(hashes)).hexdigest()


def seal(files, destination, password_file, runner, *, binary=None, release=None):
    destination = _new_destination(destination)
    password = _password(password_file, [destination, *files.values()])
    binary = _tool(binary, release)
    payload, manifest = pack(files)
    with tempfile.TemporaryDirectory(prefix='.appliance-export-', dir=destination.parent) as temporary:
        work = Path(temporary)
        repo = work / 'repository'
        _run(runner, binary, repo, password, ['init', '--repository-version', '2'])
        raw = _run(runner, binary, repo, password,
                   ['backup', '--stdin', '--stdin-filename', 'appliance.tar', '--json'], stdin=payload)
        try:
            records = [json.loads(line) for line in raw.splitlines() if line]
            summaries = [r for r in records if type(r) is dict and r.get('message_type') == 'summary']
            require(len(summaries) == 1, 'export-snapshot')
            snapshot = summaries[0]['snapshot_id']
            require(type(snapshot) is str and re.fullmatch(r'[0-9a-f]{64}', snapshot), 'export-snapshot')
        except (ValueError, KeyError):
            raise ApplianceError('export-snapshot') from None
        _run(runner, binary, repo, password, ['check', '--read-data'])
        restored = _run(runner, binary, repo, password, ['dump', snapshot, '/appliance.tar'])
        unpack(restored, manifest)
        require(restored == payload, 'export-restore-proof')
        receipt = {'schema': 1, 'state': 'sealed', 'snapshot_id': snapshot, 'manifest': manifest,
                   'ciphertext_sha256': _ciphertext_identity(repo), 'restored_bytes': 'verified',
                   'hardware_recovery': 'not-run'}
        state.write(work / 'receipt.json', receipt)
        require(not destination.exists(), 'export-destination')
        os.rename(work, destination)
        with state._directory_fd(destination.parent) as fd: os.fsync(fd)
    return receipt


def inspect_export(source, password_file, output, runner, *, binary=None, release=None):
    source = Path(source).absolute()
    with state._directory_fd(source): pass
    receipt = state.read(source / 'receipt.json')
    require(set(receipt) == {'schema', 'state', 'snapshot_id', 'manifest', 'ciphertext_sha256',
                            'restored_bytes', 'hardware_recovery'} and receipt['schema'] == 1
            and receipt['state'] == 'sealed', 'export-receipt')
    snapshot = receipt['snapshot_id']
    require(type(snapshot) is str and re.fullmatch(r'[0-9a-f]{64}', snapshot), 'export-snapshot')
    repo = source / 'repository'
    require(_ciphertext_identity(repo) == receipt['ciphertext_sha256'], 'export-ciphertext-changed')
    output = _new_destination(output)
    require(source not in output.parents and output not in source.parents, 'export-destination')
    password = _password(password_file, [source, output])
    binary = _tool(binary, release)
    _run(runner, binary, repo, password, ['check', '--read-data'])
    raw = _run(runner, binary, repo, password, ['dump', snapshot, '/appliance.tar'])
    files = unpack(raw, receipt['manifest'])
    with tempfile.TemporaryDirectory(prefix='.appliance-open-', dir=output.parent) as temporary:
        work = Path(temporary)
        for name, content in files.items():
            with state._directory_fd(work) as fd:
                state._write_at(fd, name, content)
        require(not output.exists(), 'export-destination')
        os.rename(work, output)
        with state._directory_fd(output.parent) as fd: os.fsync(fd)
    return {'schema': 1, 'state': 'inspected', 'files': sorted(files), 'services': 'not-started',
            'hardware_recovery': 'not-run'}


def collect_base(plan, private, router_xml):
    """Capture an installed host's current owned base metadata into private files.

    Caller obtains router_xml freshly through the pinned router channel. Capture
    persists for explicit deletion by its owner; it must not go on generic USB.
    """
    from .contracts import identity, load_json
    import secrets
    private = Path(private)
    staged = state.read(private / 'staged.json')
    require(staged.get('complete') is True and state.read(private / 'site.json') == plan,
            'export-staged-identity')
    receipts = {}
    vm_dir = private / 'vms'
    with state._directory_fd(vm_dir): pass
    for path in sorted(vm_dir.iterdir()):
        if path.name == '.lock': continue
        require(re.fullmatch(r'[0-9]+\.json', path.name), 'export-vm-record')
        receipts[path.stem] = state.read(path)
    require(str(plan['vms']['router']['vmid']) in receipts, 'export-router-missing')
    network = private / 'network'
    host = {name: state.read(network / (name + '.json')) for name in ('known-good', 'owned')}
    pending = network / 'pending.json'
    host['pending'] = state.read(pending) if pending.exists() else None
    require(host['pending'] is None or host['pending'].get('phase') in ('confirmed', 'rolled-back'), 'export-network-pending')
    policy = network / 'pve-policy/intent.json'
    host['pve-policy'] = state.read(policy) if policy.exists() else None
    require(host['pve-policy'] is None or host['pve-policy'].get('phase') == 'complete', 'export-network-pending')
    raw = {'site.json': canonical(plan), 'build.json': canonical(load_json(private.parent / 'build.json')),
           'release.lock.json': canonical(load_json(private.parent / 'release.lock.json')),
           'vms.json': canonical(receipts), 'host.json': canonical(host), 'router.xml': _private_bytes(router_xml)}
    require(all(len(v) < MAX_BYTES for v in raw.values()), 'export-size')
    capture = private / ('capture-' + secrets.token_hex(8))
    capture.mkdir(mode=0o700)
    with state._directory_fd(capture) as fd:
        for name, data in raw.items(): state._write_at(fd, name, data)
    return {name: capture / name for name in raw}

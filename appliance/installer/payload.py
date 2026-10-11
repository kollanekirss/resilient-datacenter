"""Closed, secret-free source payload and bounded filesystem publication."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from appliance.contracts import canonical, load_json, require
from appliance.media import verify_file
from .media import _copy_verified, _safe_parents, _write_new

EXTENSIONS = {'.py', '.php', '.sh', '.service', '.timer'}
MAX_SOURCE = 2 * 1024 * 1024


def _allowed(relative: str) -> bool:
    return (Path(relative).suffix in EXTENSIONS or relative == 'releases/v1.lock.json'
            or bool(re.fullmatch(r'systemd/[A-Za-z0-9_.@-]+\.service\.d/[A-Za-z0-9_.-]+\.conf',relative)))


def owned_path(root: Path, relative: str) -> Path:
    require(type(relative) is str and bool(relative) and '\\' not in relative and '\0' not in relative,
            'payload-path')
    path = PurePosixPath(relative)
    require(not path.is_absolute() and all(p not in ('', '.', '..') for p in relative.split('/')),
            'payload-path')
    return _safe_parents(Path(root).joinpath(*path.parts))


def file_record(path: Path) -> dict:
    path = _safe_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), 'payload-file')
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        require(info.st_size > 0, 'payload-empty-file')
    return {'sha256': digest.hexdigest(), 'size_bytes': info.st_size, 'max_bytes': info.st_size}


def prepare_runtime(package: Path, destination: Path) -> dict:
    package, destination = _safe_parents(package), _safe_parents(destination)
    require(package.name == 'appliance' and package.is_dir(), 'payload-source')
    require(not destination.exists(), 'payload-destination-exists')
    files = []
    # Build an explicit manifest from package code only; no arbitrary input tree.
    for source in sorted(package.rglob('*')):
        relative = source.relative_to(package)
        if any(p.startswith('.') or p == '__pycache__' for p in relative.parts):
            continue
        require(not source.is_symlink(), 'payload-symlink')
        if not source.is_file() or not _allowed(relative.as_posix()):
            continue
        raw = source.read_bytes()
        require(0 < len(raw) <= MAX_SOURCE, 'payload-source-size')
        require(not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]', raw),
                'payload-private-key')
        files.append({'path': 'appliance/' + relative.as_posix(), **file_record(source)})
    require(files and any(f['path'] == 'appliance/__init__.py' for f in files), 'payload-source')
    destination.mkdir(mode=0o700)
    for record in files:
        target = owned_path(destination, record['path'])
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _copy_verified(package.parent / record['path'], target, record)
    manifest = {'schema': 1, 'files': files}
    _write_new(destination / 'runtime.json', canonical(manifest))
    return verify_runtime(destination)


def verify_runtime(root: Path) -> dict:
    root = _safe_parents(root)
    manifest = load_json(root / 'runtime.json')
    require(set(manifest) == {'schema', 'files'} and manifest['schema'] == 1
            and type(manifest['files']) is list and 0 < len(manifest['files']) <= 256, 'payload-manifest')
    names = []
    for record in manifest['files']:
        require(type(record) is dict and set(record) == {'path', 'sha256', 'size_bytes', 'max_bytes'},
                'payload-manifest')
        path = owned_path(root, record['path'])
        require(record['path'].startswith('appliance/') and _allowed(record['path'][len('appliance/'):]), 'payload-path')
        require(record['size_bytes'] <= MAX_SOURCE, 'payload-source-size')
        verify_file(path, record)
        names.append(record['path'])
    require(len(names) == len(set(names)), 'payload-duplicate')
    actual = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'payload-symlink')
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    require(actual == set(names) | {'runtime.json'}, 'payload-extra-files')
    return manifest


def verify_install_payload(root: Path) -> tuple[dict, dict]:
    from appliance.plan import validate_release
    from .adapters.pve import ADAPTER_ID, SOURCE_REVISION
    root = _safe_parents(root)
    release = validate_release(load_json(root / 'release.lock.json'), production=True)
    runtime = verify_runtime(root / 'runtime')
    build = load_json(root / 'build.json')
    from appliance.contracts import identity
    require(build.get('schema') == 1 and build.get('adapter_id') == ADAPTER_ID
            and build.get('source_revision') == SOURCE_REVISION
            and build.get('release_identity') == identity(release)
            and build.get('runtime_identity') == identity(runtime), 'payload-build-mismatch')
    require(build.get('qualification') == 'not-run' and build.get('qualification_build') is True,
            'qualification-build-required')
    by_id = {item['id']:item for item in release['components']}
    require({p.name for p in (root / 'media').iterdir()} == {'opnsense-dvd','probe-image','restic'}, 'payload-extra-files')
    for name in ('opnsense-dvd','probe-image','restic'):
        content = by_id[name].get('expanded',by_id[name])
        verify_file(owned_path(root,'media/' + name),content)
    return release,build

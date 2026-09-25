"""Private network preparation kit. Generation does not connect to any server."""
import json
import hashlib
import os
from pathlib import Path
import sys
from portable_plan import require, fields
from portable_state import directory, regular, read
from portable_network import derive, fingerprint
from portable_network_render import artifacts


def contents(plan, settings):
    result = artifacts(plan, settings)
    result['site.json'] = json.dumps(plan, indent=2) + '\n'
    result['network.json'] = json.dumps(settings, indent=2) + '\n'
    return result


def prepare(plan, settings, destination):
    policy = derive(plan, settings)
    files = contents(plan, settings)
    destination = Path(destination).absolute()
    directory(destination.parent)
    require(not destination.exists() and not destination.is_symlink(), 'Choose a new network-kit directory; existing paths are never overwritten.')
    try:
        destination.mkdir(mode=0o700)  # exclusive claim; incomplete kits have no manifest
    except FileExistsError:
        raise ValueError('Network-kit destination already exists.') from None
    for relative, value in files.items():
        path = destination / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
    manifest = {'schema_version': 1, 'site_sha256': policy['site_sha256'], 'settings_sha256': policy['settings_sha256'],
                'files': {key: hashlib.sha256(value.encode()).hexdigest() for key, value in files.items()}}
    from portable_state import write
    write(destination / 'manifest.json', manifest)
    verify(destination, plan=plan, settings=settings)
    return {'state': 'network-prepared', 'kit': str(destination), 'network_verified': False,
            'notice': 'Private local network kit prepared. Follow START-HERE.md; no server or network was changed.'}


def verify(destination, *, plan=None, settings=None):
    require(Path(destination).exists(), 'Network-kit directory does not exist.')
    destination = directory(destination)
    manifest = read(destination / 'manifest.json')
    fields(manifest, 'schema_version site_sha256 settings_sha256 files')
    require(type(manifest['schema_version']) is int and manifest['schema_version'] == 1, 'Unsupported kit manifest.')
    saved_plan = read(destination / 'site.json'); saved_settings = read(destination / 'network.json')
    policy = derive(saved_plan, saved_settings)
    require(manifest['site_sha256'] == policy['site_sha256'] and manifest['settings_sha256'] == policy['settings_sha256'],
            'Kit manifest does not match the site/settings.')
    require(plan is None or fingerprint(plan) == policy['site_sha256'], 'Kit belongs to another site plan.')
    require(settings is None or fingerprint(settings) == policy['settings_sha256'], 'Kit belongs to different network settings.')
    expected = contents(saved_plan, saved_settings)
    require(type(manifest['files']) is dict and set(manifest['files']) == set(expected), 'Kit file inventory differs from this implementation.')
    for relative, wanted in expected.items():
        path = destination / relative
        require(path.parent.exists(), 'Kit directory is missing.')
        directory(path.parent)
        with regular(path) as stream:
            actual = stream.read(131073)
        require(actual == wanted.encode() and hashlib.sha256(actual).hexdigest() == manifest['files'][relative],
                'Kit files differ from their reviewed configuration. Regenerate in a new directory.')
    allowed = set(expected) | {'manifest.json'}
    for path in destination.rglob('*'):
        require(not path.is_symlink(), 'Symlinks are not accepted in a network kit.')
        require(path.is_dir() or str(path.relative_to(destination)) in allowed, 'Unexpected file in network kit.')
    return {'state': 'network-kit-verified', 'network_verified': False,
            'binding': policy['site_sha256'] + ':' + policy['settings_sha256'],
            'dns_address': saved_plan['vms']['dns']['address'],
            'administrator_address': saved_settings['administrator_address'],
            'notice': 'Kit integrity verified against this project version; deployment and network health are not verified.'}


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'Supply one kit directory.')
        print(json.dumps(verify(Path(sys.argv[1]))))
    except (ValueError, OSError):
        print('Network kit verification failed; use a complete private kit from this project version.', file=sys.stderr)
        raise SystemExit(1)

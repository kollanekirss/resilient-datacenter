"""Archive parsing and Restic protocol tested without activating any services."""
import importlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

import pytest

from appliance.contracts import ApplianceError


def module():
    return importlib.import_module('appliance.export')


@pytest.fixture
def material(tmp_path):
    files = {}
    for name in ('site.json', 'release.lock.json', 'build.json', 'vms.json', 'router.xml', 'host.json'):
        source = tmp_path / name
        source.write_bytes(b'<opnsense/>' if name.endswith('.xml') else b'{}')
        source.chmod(0o600)
        files[name] = source
    return files


def test_capture_requires_complete_material(material):
    del material['router.xml']
    with pytest.raises(ApplianceError, match='export-components'):
        module().pack(material)


def test_pack_round_trip_proves_each_component_hash(material):
    raw, manifest = module().pack(material)
    result = module().unpack(raw, manifest)
    assert result['router.xml'] == b'<opnsense/>'
    assert result['site.json'] == b'{}'
    tampered = bytearray(raw)
    tampered[512] ^= 1
    with pytest.raises(ApplianceError):
        module().unpack(bytes(tampered), manifest)


def test_source_symlink_is_refused(material, tmp_path):
    link = tmp_path / 'linked'
    link.symlink_to(material['site.json'])
    material['site.json'] = link
    with pytest.raises(ApplianceError): module().pack(material)


@pytest.mark.parametrize('name', ['../escape', '/etc/shadow', 'site.json/../escape'])
def test_archive_traversal_is_refused(material, name):
    _, manifest = module().pack(material)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        info = tarfile.TarInfo(name); info.size = 1
        archive.addfile(info, io.BytesIO(b'x'))
    with pytest.raises(ApplianceError): module().unpack(stream.getvalue(), manifest)


def test_truncated_archive_is_refused(material):
    raw, manifest = module().pack(material)
    with pytest.raises(ApplianceError): module().unpack(raw[:100], manifest)


def test_duplicate_members_are_refused(material):
    _, manifest = module().pack(material)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for _ in range(2):
            info = tarfile.TarInfo('site.json'); info.size = 2
            archive.addfile(info, io.BytesIO(b'{}'))
    with pytest.raises(ApplianceError): module().unpack(stream.getvalue(), manifest)


class ResticTransport:
    """External tool protocol only; no encryption assurance from this double."""
    def __init__(self, corrupt=False):
        self.payload = None
        self.corrupt = corrupt

    def run(self, argv, *, stdin=b'', timeout_s=30):
        repo = Path(argv[argv.index('--repo') + 1])
        if 'init' in argv:
            repo.mkdir(mode=0o700)
            (repo / 'config').write_bytes(b'encrypted-test-fixture')
            (repo / 'config').chmod(0o600)
            raw = b''
        elif 'backup' in argv:
            assert argv[-3:] == ['--stdin-filename', 'appliance.tar', '--json']
            self.payload = stdin
            raw = json.dumps({'message_type': 'summary', 'snapshot_id': 'a' * 64}).encode()
        elif 'dump' in argv:
            assert argv[-2:] == ['a' * 64, '/appliance.tar']
            raw = b'corrupted' if self.corrupt else self.payload
        elif 'check' in argv:
            raw = b''
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, raw, b'')


def test_failed_restore_proof_does_not_publish_export(material, tmp_path, monkeypatch):
    export = module()
    monkeypatch.setattr(export, '_tool', lambda *args: Path('/verified/restic'))
    password = tmp_path / 'password'; password.write_bytes(b'long-separate-password'); password.chmod(0o600)
    destination = tmp_path / 'sealed'
    with pytest.raises(ApplianceError):
        export.seal(material, destination, password, ResticTransport(corrupt=True))
    assert not destination.exists()


def test_seal_inspection_retains_private_bytes_without_activation(material, tmp_path, monkeypatch):
    export = module()
    monkeypatch.setattr(export, '_tool', lambda *args: Path('/verified/restic'))
    password = tmp_path / 'password'; password.write_bytes(b'long-separate-password'); password.chmod(0o600)
    destination = tmp_path / 'sealed'
    transport = ResticTransport()
    receipt = export.seal(material, destination, password, transport)
    assert receipt['snapshot_id'] == 'a' * 64
    assert 'long-separate-password' not in json.dumps(receipt)
    opened = tmp_path / 'opened'
    inspected = export.inspect_export(destination, password, opened, transport)
    assert inspected['services'] == 'not-started'
    assert (opened / 'router.xml').read_bytes() == b'<opnsense/>'
    assert (opened / 'site.json').stat().st_mode & 0o777 == 0o600


def test_password_cannot_be_captured_material(material, tmp_path, monkeypatch):
    export = module()
    monkeypatch.setattr(export, '_tool', lambda *args: Path('/verified/restic'))
    material['site.json'].write_bytes(b'long-secret-password')
    with pytest.raises(ApplianceError, match='export-password-separate'):
        export.seal(material, tmp_path / 'sealed', material['site.json'], ResticTransport())


def test_collection_requires_staged_plan_identity(site, tmp_path):
    private = tmp_path / 'private'; private.mkdir(mode=0o700)
    router = tmp_path / 'router.xml'; router.write_text('<opnsense/>'); router.chmod(0o600)
    with pytest.raises(ApplianceError):
        module().collect_base(site, private, router)
    assert not list(private.glob('capture-*'))


def test_readonly_restic_repository_objects_are_valid(tmp_path):
    repo = tmp_path / 'repository'; repo.mkdir(mode=0o700)
    item = repo / 'config'; item.write_bytes(b'encrypted'); item.chmod(0o400)
    assert len(module()._ciphertext_identity(repo)) == 64
    item.chmod(0o444)
    with pytest.raises(ApplianceError): module()._ciphertext_identity(repo)

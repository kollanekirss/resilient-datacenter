from pathlib import Path
import copy
import hashlib
import pytest
from appliance.contracts import ApplianceError
from appliance.guest import image


def test_build_recipe_is_closed_when_package_inputs_are_not_pinned():
    recipe=image.template()
    assert recipe['qualification']=='not-run'
    with pytest.raises(ApplianceError,match='role-image-packages-unpinned'):image.validate_recipe(recipe)


def test_build_script_disables_services_and_clears_duplicate_identity():
    script=image.install_script()
    assert 'systemctl mask ssh.service ssh.socket' in script
    assert 'cloud-init clean --logs --machine-id --seed' in script
    assert '/var/lib/tailscale' in script and '/var/lib/rdc-guest' in script
    assert '/etc/ssh/ssh_host_' in script
    assert 'apt-get' not in script and 'curl' not in script
    assert 'headscale.service derper.service tailscaled.service' in script


def test_image_template_pins_binaries_and_derper_build_source():
    recipe=image.template()
    assert set(recipe['binaries'])=={'tailscale','tailscaled','headscale','derper'}
    assert recipe['derper_build']['go']=='1.27.1'
    assert recipe['derper_build']['module']=='tailscale.com/cmd/derper@v1.104.1'
    assert len(recipe['derper_build']['source_commit'])==40
    for binary in recipe['binaries'].values():
        assert len(binary['sha256'])==64 and binary['size_bytes']>0


def test_package_manifest_rejects_unpinned_or_partial_dependencies():
    recipe=image.template();recipe['packages']=[{'name':'qemu-guest-agent','version':'1.0','filename':'qemu.deb','sha256':'a'*64,'size_bytes':1,'max_bytes':1}]
    with pytest.raises(ApplianceError,match='role-image-package-manifest'):image.validate_recipe(recipe)


def test_package_preparation_is_download_only_and_never_uses_host_status(tmp_path,monkeypatch):
    from subprocess import CompletedProcess
    base=tmp_path/'base.manifest';base.write_text('\n'.join(name+'\t1.0' for name in sorted(image.REQUIRED)))
    pin={'sha256':hashlib.sha256(base.read_bytes()).hexdigest(),'size_bytes':base.stat().st_size,'max_bytes':base.stat().st_size}
    monkeypatch.setattr(image,'BASE_MANIFEST',pin)
    keyring=tmp_path/'keyring';keyring.write_bytes(b'test-keyring');monkeypatch.setattr(image,'ARCHIVE_KEYRING',keyring)
    inputs=tmp_path/'inputs';inputs.mkdir();output=tmp_path/'recipe.json';calls=[]
    class Apt:
        def run(self,argv,**kw):
            calls.append(argv)
            if argv[0]=='/usr/bin/apt-get':
                root=Path(next(v[4:] for v in argv if v.startswith('Dir=')))
                if argv[-1]=='update':
                    (root/'var/lib/apt/lists/test_InRelease').write_bytes(b'signed metadata')
                    (root/'var/lib/apt/lists/test_Packages').write_bytes(b'index')
                else:(root/'var/cache/apt/archives/qemu-guest-agent_1.1_amd64.deb').write_bytes(b'new package')
                out=b''
            else:out=b'Package: qemu-guest-agent\nVersion: 1.1\nArchitecture: amd64\n'
            return CompletedProcess(argv,0,out,b'')
    result=image.prepare_packages(base,inputs,output,Apt())
    assert result['package_manifest']['qemu-guest-agent']=='1.1'
    assert result['packages'][0]['sha256']==hashlib.sha256(b'new package').hexdigest()
    apt=[c for c in calls if c[0]=='/usr/bin/apt-get']
    assert all('--download-only' in c for c in apt)
    assert all(any(v.startswith('Dir::State::status=') and '/var/lib/dpkg/status' not in v for v in c) for c in apt)
    assert not any('AllowUnauthenticated' in v for c in calls for v in c)
    image.validate_recipe(result)


def test_role_archive_extraction_refuses_symlinks(tmp_path):
    import io,tarfile
    archive=tmp_path/'vendor.tgz'
    with tarfile.open(archive,'w:gz') as out:
        member=tarfile.TarInfo('tailscale_1.104.1_amd64/tailscale');member.type=tarfile.SYMTYPE;member.linkname='/etc/shadow';out.addfile(member)
    with pytest.raises(ApplianceError,match='role-image-archive-member'):
        image.extract_tailscale(archive,tmp_path,image.template())


def test_existing_binary_inputs_are_reverified_without_build(tmp_path,monkeypatch):
    recipe=image.template()
    for name,item in recipe['binaries'].items():
        raw=name.encode();(tmp_path/item['filename']).write_bytes(raw)
        item.update(sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),max_bytes=len(raw))
    monkeypatch.setattr(image,'template',lambda:recipe)
    class NoCommands:
        def run(self,*a,**k):pytest.fail('Verified existing binary inputs need no commands')
    result=image.prepare_binaries(tmp_path,NoCommands())
    assert result['qualification']=='not-run'
    (tmp_path/recipe['binaries']['derper']['filename']).write_bytes(b'tampered')
    with pytest.raises(ApplianceError):image.prepare_binaries(tmp_path,NoCommands())


def test_image_identity_covers_boot_and_daemon_service_units():
    sources=image._sources()
    assert 'guest/rdc-guest.service' in sources
    assert 'guest/tailscaled.service' in sources


def test_snapshot_recovery_is_not_ordered_before_services_it_starts():
    import inspect
    assert 'recover_snapshots' not in inspect.getsource(image.initialize)
    unit=(image.ROOT/'rdc-guest-recovery.service').read_text()
    after=next(line for line in unit.splitlines() if line.startswith('After='))
    assert all(name in after for name in ('rdc-guest.service','tailscaled.service','headscale.service','derper.service'))
    assert not any(line.startswith('Before=') for line in unit.splitlines())
    assert 'rdc-guest-recovery.service' in image.install_script()

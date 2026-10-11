import hashlib
import json
import subprocess
import tomllib
from pathlib import Path

import pytest

from appliance.contracts import ApplianceError


def test_answer_has_only_static_management_and_one_explicit_disk(site):
    from appliance.installer.adapters.pve import answer_bytes
    answer = tomllib.loads(answer_bytes(site, '$6$salt$' + 'a' * 86,
                         disk_path='/dev/sda', management_name='enp1s0').decode())
    assert answer['network']['source'] == 'from-answer'
    assert answer['network']['cidr'] == '10.77.0.2/24'
    assert answer['network']['filter'] == {'ID_NET_NAME': 'enp1s0'}
    assert answer['disk-setup']['disk-list'] == ['sda']
    assert answer['global']['reboot-on-error'] is False
    assert answer['first-boot'] == {'source': 'from-iso', 'ordering': 'before-network'}
    assert 'root-password' not in answer['global']


@pytest.mark.parametrize('password', ['password', '$6$bad\nvalue', '', '$6$x$short'])
def test_answer_refuses_non_hash_or_injection(site, password):
    from appliance.installer.adapters.pve import answer_bytes
    with pytest.raises(ApplianceError):
        answer_bytes(site, password, disk_path='/dev/sda', management_name='enp1s0')


@pytest.mark.parametrize('disk,name', [('/dev/sda;reboot', 'eth0'), ('/dev/sda1', 'eth0'),
                                      ('/dev/sda', '*'), ('sda', 'eth0')])
def test_answer_refuses_ambiguous_selectors(site, disk, name):
    from appliance.installer.adapters.pve import answer_bytes
    with pytest.raises(ApplianceError):
        answer_bytes(site, '$6$salt$' + 'a' * 86, disk_path=disk, management_name=name)


def test_boot_config_every_kernel_gets_ipv6_disabled():
    from appliance.installer.iso import patch_boot_config
    value = b'menuentry "A" {\n linux /boot/linux26 quiet\n initrd /boot/initrd.img\n}\nmenuentry "B" {\n linuxefi /boot/linux26 proxdebug\n}\n'
    result = patch_boot_config(value)
    assert result.count(b'ipv6.disable=1') == 2
    assert result.count(b'rdc.appliance=1') == 2
    assert b'proxdebug' not in result


def test_boot_config_unknown_kernel_or_network_boot_refused():
    from appliance.installer.iso import patch_boot_config
    for value in (b'linux /unknown/kernel\n', b'linux /boot/linux26 ip=dhcp\n', b'configfile elsewhere.cfg\n'):
        with pytest.raises(ApplianceError):
            patch_boot_config(value)


def test_launcher_only_accepts_reviewed_upstream_bytes():
    from appliance.installer.iso import patch_launcher
    with pytest.raises(ApplianceError, match='upstream-launcher-mismatch'):
        patch_launcher(b'#!/bin/sh\ndhclient\n')


def test_initrd_audit_refuses_networking_and_unrecognized_dispatch():
    from appliance.installer.iso import audit_init_script
    for value in (b'udhcpc\nexec switch_root /mnt /usr/sbin/unconfigured.sh', b'exec /bin/sh'):
        with pytest.raises(ApplianceError):
            audit_init_script(value)
    audit_init_script(b'#!/bin/sh\nexec switch_root /mnt /usr/sbin/unconfigured.sh\n')


def test_runtime_payload_excludes_mutable_files_and_secrets(tmp_path):
    from appliance.installer.payload import prepare_runtime, verify_runtime
    source = tmp_path / 'source'; (source / 'appliance').mkdir(parents=True)
    (source / 'appliance/__init__.py').write_text('VERSION = 1\n')
    (source / 'appliance/site.json').write_text('{"secret":"private"}')
    (source / 'appliance/extra.py').symlink_to('/etc/passwd')
    with pytest.raises(ApplianceError):
        prepare_runtime(source / 'appliance', tmp_path / 'out')
    (source / 'appliance/extra.py').unlink()
    result = prepare_runtime(source / 'appliance', tmp_path / 'good')
    assert [i['path'] for i in result['files']] == ['appliance/__init__.py']
    assert verify_runtime(tmp_path / 'good') == result
    (tmp_path / 'good/appliance/__init__.py').write_text('tampered')
    with pytest.raises(ApplianceError):
        verify_runtime(tmp_path / 'good')


def test_runtime_manifest_does_not_authorize_path_escape(tmp_path):
    from appliance.installer.payload import verify_runtime
    (tmp_path / 'runtime.json').write_text(json.dumps({'schema': 1, 'files': [
        {'path': '../outside', 'size_bytes': 1, 'max_bytes': 1, 'sha256': 'a' * 64}]}))
    with pytest.raises(ApplianceError):
        verify_runtime(tmp_path)


def test_first_boot_missing_receipt_never_runs_command(tmp_path):
    from appliance.installer.first_boot import first_boot
    class NoCommands:
        def run(self, *args, **kwargs):
            pytest.fail('unverified staging invoked a command')
    with pytest.raises(ApplianceError, match='staging-incomplete'):
        first_boot(tmp_path, NoCommands())


def test_staging_receipt_rejects_escape_before_read(tmp_path):
    from appliance.installer.first_boot import verify_staging
    private = tmp_path / 'var/lib/rdc-appliance/private'; private.mkdir(parents=True, mode=0o700)
    (private / 'staged.json').write_text(json.dumps({'schema':1,'complete':True,'plan_id':'a'*64,
         'build_id':'b'*64,'files':[{'relative_path':'../outside','component':{
             'sha256':'c'*64,'size_bytes':1,'max_bytes':1}}]}))
    (private / 'staged.json').chmod(0o600)
    with pytest.raises(ApplianceError):
        verify_staging(tmp_path)


def test_unqualified_iso_requires_explicit_disposable_build(tmp_path):
    from appliance.installer.iso import build_iso
    release = json.loads((Path(__file__).parents[2] / 'appliance/releases/v1.lock.json').read_text())
    with pytest.raises(ApplianceError, match='qualification-build-required'):
        build_iso(release, tmp_path / 'bundle', tmp_path / 'out.iso', runner=object())


def test_install_never_uses_non_live_host(site,tmp_path):
    from appliance.installer.live import install_site
    with pytest.raises(ApplianceError, match='live-environment-required'):
        install_site(site,tmp_path,'a'*64,object(),password_hash='$6$salt$'+'a'*86,
                     consent_boot_id='fake',root=tmp_path)

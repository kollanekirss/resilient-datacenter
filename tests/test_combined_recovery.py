import importlib
from pathlib import Path
import io
import sys
import tarfile
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def api():return importlib.import_module('ci_site_recovery_contract')


def test_guest_lan_command_retains_restricted_console():
    command=api().guest_command('/private/guest',22222,'chat')
    assert 'restrict=on' in ' '.join(command)
    assert 'tap,id=kit,ifname=rs-chat,script=no,downscript=no' in command
    assert 'user,id=home,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22' in command


def test_guest_roles_cannot_supply_arbitrary_network_arguments():
    with pytest.raises(ValueError):api().guest_command('/private/guest',22222,'unknown')


def test_replacement_requires_old_process_confirmed_dead():
    class Process:
        def poll(self):return None
    class Guest:process=Process()
    with pytest.raises(ValueError):api().require_fenced({'chat':Guest(),'files':Guest()})
    Guest.process=None
    with pytest.raises(ValueError):api().require_fenced({'chat':Guest(),'files':Guest()})


def test_safe_archive_preserves_numeric_ownership_without_path_escape(tmp_path):
    file=tmp_path/'snapshot.tar'
    with tarfile.open(file,'w') as archive:
        member=tarfile.TarInfo('data/example');member.size=4;member.uid=999;member.gid=999
        archive.addfile(member,io.BytesIO(b'data'))
    target=tmp_path/'stage'
    # Extractor supports metadata ownership only as root; filtering itself is pure.
    with tarfile.open(file) as archive:
        info=api().archive_member(archive.getmembers()[0],str(target))
        assert info.uid==999 and info.gid==999
    for name in ('../escape','/absolute'):
        member=tarfile.TarInfo(name)
        with pytest.raises(ValueError):api().archive_member(member,str(target))


def test_archive_rejects_devices_and_outside_links(tmp_path):
    for kind in (tarfile.CHRTYPE,tarfile.FIFOTYPE,tarfile.SYMTYPE):
        member=tarfile.TarInfo('data/link');member.type=kind;member.linkname='../../outside'
        with pytest.raises(ValueError):api().archive_member(member,str(tmp_path/'stage'))


def test_evidence_cannot_claim_opnsense_or_zero_data_loss():
    result=api().evidence(12.5,{'chat':10,'files':20})
    assert result['routing']=='linux-fixture'
    assert result['opnsense']=='not-tested'
    assert result['known_later_writes_absent']=={'chat_messages':1,'file_versions':1}
    assert result['recovery_seconds']==12.5


def test_fenced_guests_and_exact_snapshot_modes(tmp_path):
    class Process:
        def poll(self):return 0
    class Guest:process=Process()
    api().require_fenced({'chat':Guest(),'files':Guest()})
    with pytest.raises(ValueError):api().require_fenced({'chat':Guest()})
    member=tarfile.TarInfo('private');member.mode=0o400
    assert api().archive_member(member,str(tmp_path)).mode==0o400
    member.mode=0o4600
    with pytest.raises(ValueError):api().archive_member(member,str(tmp_path))

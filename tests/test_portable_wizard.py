import importlib
import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))


def test_prepare_wizard_saves_private_plan_without_servers(tmp_path):
    m=importlib.import_module('portable_wizard');answers=iter(['']*9+['SAVE','q'])
    result=m.wizard(tmp_path/'journey',input_fn=lambda _:next(answers),output_fn=lambda _:None)
    assert result['state']=='saved'
    file=tmp_path/'journey/site.json'
    assert file.stat().st_mode&0o777==0o600
    assert json.loads(file.read_text())['site']=='tallinn-kit'
    assert not (tmp_path/'journey/guest-state').exists()


def test_cancel_wizard_does_not_write(tmp_path):
    m=importlib.import_module('portable_wizard')
    result=m.wizard(tmp_path/'journey',input_fn=lambda _:':cancel',output_fn=lambda _:None)
    assert result['state']=='cancelled'
    assert not (tmp_path/'journey/site.json').exists()


def test_resume_lists_guests_and_does_not_ask_for_credentials(tmp_path):
    m=importlib.import_module('portable_wizard');folder=tmp_path/'journey';folder.mkdir(mode=0o700)
    p=folder/'site.json';p.write_bytes((ROOT/'examples/portable-site.json').read_bytes());p.chmod(0o600)
    output=[]
    result=m.wizard(folder,input_fn=lambda _: 'q',output_fn=output.append)
    assert result['state']=='saved'
    assert any('Guest' in text for text in output)


def test_prepare_refuses_unrelated_existing_workspace(tmp_path):
    m=importlib.import_module('portable_wizard');folder=tmp_path/'existing';folder.mkdir(mode=0o700)
    (folder/'journey.json').write_text('unrelated')
    with pytest.raises(ValueError):m.wizard(folder,input_fn=lambda _: '',output_fn=lambda _:None)
    assert not (folder/'site.json').exists()


def test_invalid_guest_choice_stays_in_menu(tmp_path):
    m=importlib.import_module('portable_wizard');folder=tmp_path/'journey';folder.mkdir(mode=0o700)
    p=folder/'site.json';p.write_bytes((ROOT/'examples/portable-site.json').read_bytes());p.chmod(0o600)
    answers=iter(['6','not-a-role','q'])
    assert m.wizard(folder,input_fn=lambda _:next(answers),output_fn=lambda _:None)['state']=='saved'


def test_wizard_completion_does_not_claim_no_servers_changed(tmp_path,monkeypatch,capsys):
    m=importlib.import_module('portable_wizard');rdc=importlib.import_module('rdc')
    monkeypatch.setattr(m,'wizard',lambda _: {'state':'saved','notice':'Operations may have run.'})
    assert rdc.main(['start','--platform','proxmox','--output-dir',str(tmp_path/'workspace')])==0
    assert 'No servers were changed' not in capsys.readouterr().out


def test_corrupt_progress_is_displayed_without_crashing(tmp_path):
    m=importlib.import_module('portable_wizard');folder=tmp_path/'journey';folder.mkdir(mode=0o700)
    p=folder/'site.json';p.write_bytes((ROOT/'examples/portable-site.json').read_bytes());p.chmod(0o600)
    state=folder/'guest-state';state.mkdir(mode=0o700)
    bad=state/'edge.json';bad.write_text('[]');bad.chmod(0o600)
    output=[]
    assert m.wizard(folder,input_fn=lambda _: 'q',output_fn=output.append)['state']=='saved'
    assert any('invalid' in s for s in output)

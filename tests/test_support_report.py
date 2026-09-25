import importlib
import json
import os
from pathlib import Path
import pytest
from test_setup_contracts import ROOT


def api(): return importlib.import_module('support_report')


def sample():
    from operation_results import Check
    return api().make_report((Check('dns.resolve','fail','check-dns'),),
        {'version':'0.2.0-dev','commit':'a'*40,'private_path':'/PRIVATE_PATH','token':'PRIVATE_TOKEN'},
        {'system':'Linux','architecture':'x86_64','hostname':'PRIVATE_HOST'},
        generated_at='2026-09-25T00:00:00+00:00')


def test_report_projection_drops_private_fields():
    report=sample()
    assert 'PRIVATE_' not in json.dumps(report)
    assert report['schema_version']==1
    assert report['checks'][0]['code']=='dns.resolve'


def test_nominally_allowed_keys_cannot_smuggle_private_values():
    from operation_results import Check
    report=api().make_report((Check('PRIVATE_CODE','PRIVATE_OUTCOME','PRIVATE_STEP'),),
        {'version':'PRIVATE_VERSION','commit':'PRIVATE_COMMIT','dirty':'PRIVATE_DIRTY','components':{'headscale':'PRIVATE_PIN'}},
        {'system':'PRIVATE_SYSTEM','architecture':'PRIVATE_ARCH'},generated_at='PRIVATE_TIME')
    assert 'PRIVATE_' not in json.dumps(report)
    assert report['checks'][0]['outcome']=='unknown'


def test_report_is_private_and_cannot_replace_existing(tmp_path):
    target=tmp_path/'report.json'; api().write_report(target,sample())
    assert target.stat().st_mode & 0o777==0o600
    before=target.read_bytes()
    with pytest.raises((ValueError,OSError)): api().write_report(target,{})
    assert target.read_bytes()==before


def test_symlink_destination_and_parent_are_refused(tmp_path):
    actual=tmp_path/'actual'; actual.mkdir()
    link=tmp_path/'alias'; link.symlink_to(actual,target_is_directory=True)
    with pytest.raises((ValueError,OSError)): api().write_report(link/'report',sample())
    secret=actual/'secret'; secret.write_text('untouched')
    target=tmp_path/'report'; target.symlink_to(secret)
    with pytest.raises((ValueError,OSError)): api().write_report(target,sample())
    assert secret.read_text()=='untouched'


def test_unsafe_or_missing_parent_is_not_created(tmp_path):
    with pytest.raises((ValueError,OSError)): api().write_report(tmp_path/'missing'/'report',sample())
    assert not (tmp_path/'missing').exists()
    tmp_path.chmod(0o777)
    with pytest.raises((ValueError,OSError)): api().write_report(tmp_path/'report',sample())


def test_racing_existing_report_is_not_overwritten(tmp_path,monkeypatch):
    m=api(); real=m.os.link; target=tmp_path/'report'
    def race(source,dest,*a,**kw):
        target.write_text('other-writer')
        return real(source,dest,*a,**kw)
    monkeypatch.setattr(m.os,'link',race)
    with pytest.raises(FileExistsError): m.write_report(target,sample())
    assert target.read_text()=='other-writer'
    assert sorted(p.name for p in tmp_path.iterdir())==['report']

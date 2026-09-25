import bz2
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))


def test_verified_media_and_tamper(tmp_path,monkeypatch):
    m=importlib.import_module('guest_media'); iso=b'ISO-test'*100; packed=bz2.compress(iso)
    item={'url':'https://example.org/image.bz2','sha256':hashlib.sha256(packed).hexdigest(), 'download_bytes':len(packed), 'iso_max_bytes':len(iso), 'compression':'bz2','version':'test'}
    monkeypatch.setattr(m,'catalogue',lambda:{'opnsense':item})
    def fetch(url):return io.BytesIO(packed)
    record=m.prepare('opnsense',tmp_path/'cache',open_url=fetch)
    assert record['sha256']==hashlib.sha256(iso).hexdigest()
    assert m.verify(tmp_path/'cache','opnsense')==record
    (tmp_path/'cache'/record['filename']).write_bytes(b'changed')
    with pytest.raises(ValueError):m.verify(tmp_path/'cache','opnsense')


@pytest.mark.parametrize('fault',['hash','size','expansion'])
def test_corrupt_download_not_published(tmp_path,monkeypatch,fault):
    m=importlib.import_module('guest_media'); blob=bz2.compress(b'A'*100)
    item={'url':'https://example.org/image.bz2','sha256':hashlib.sha256(blob).hexdigest(), 'download_bytes':len(blob), 'iso_max_bytes':100,'compression':'bz2','version':'test'}
    if fault=='hash':item['sha256']='0'*64
    if fault=='size':item['download_bytes']-=1
    if fault=='expansion':item['iso_max_bytes']=99
    monkeypatch.setattr(m,'catalogue',lambda:{'opnsense':item})
    with pytest.raises(ValueError):m.prepare('opnsense',tmp_path/'cache',open_url=lambda _:io.BytesIO(blob))
    assert not list((tmp_path/'cache').glob('*.json'))


def test_catalogue_has_pinned_official_sources():
    m=importlib.import_module('guest_media')
    data=m.catalogue()
    assert set(data)=={'ubuntu','opnsense'}
    assert data['ubuntu']['url'].startswith('https://releases.ubuntu.com/')
    assert data['opnsense']['url'].startswith('https://pkg.opnsense.org/')
    assert all(len(v['sha256'])==64 and v['download_bytes']>0 for v in data.values())

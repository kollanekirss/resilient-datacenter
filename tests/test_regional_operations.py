import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_cancelled_identity_preparation_creates_nothing(tmp_path):
    m=importlib.import_module('regional_operations');output=tmp_path/'identity.json'
    assert m.wizard(output,input_fn=lambda _:':cancel',output_fn=lambda _:None)['state']=='cancelled'
    assert not output.exists()


def test_noninteractive_signing_cannot_create_a_workspace(tmp_path,monkeypatch):
    m=importlib.import_module('regional_operations')
    monkeypatch.setattr(m.sys.stdin,'isatty',lambda:False)
    with pytest.raises(ValueError,match='interactive'):
        m.action(SimpleNamespace(regional_action='init',workspace=tmp_path/'workspace',profile=tmp_path/'profile.json'))
    assert not (tmp_path/'workspace').exists()


def test_cli_has_no_passphrase_argument():
    m=importlib.import_module('rdc')
    from operation_results import OperationError
    with pytest.raises(OperationError):m.parser().parse_args(['regional','offer','--workspace','/tmp/w','--services','matrix','--peer-fingerprint','a'*64,'--output-file','/tmp/o','--passphrase','secret'])
    args=m.parser().parse_args(['regional','offer','--workspace','/tmp/w','--services','matrix','--peer-fingerprint','a'*64,'--output-file','/tmp/o'])
    assert args.days==30


@pytest.mark.parametrize('payload',[[],None,'unexpected'])
def test_inspection_rejects_invalid_envelope_shapes(tmp_path,payload):
    import json
    m=importlib.import_module('regional_operations');path=tmp_path/'partner.json'
    path.write_text(json.dumps({'payload':payload,'signature':'00'*64}))
    with pytest.raises(ValueError):m.action(SimpleNamespace(regional_action='inspect',document=path))

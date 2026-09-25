import importlib
import json
from test_backup_contracts import profile


def test_backup_setup_keeps_secrets_out_and_changes_no_server(tmp_path):
    m=importlib.import_module('backup_setup');data=profile();target=tmp_path/'backup.json'
    replies=iter([str(data[k]) for k in ('institution_id','node_name','role','backup_host','backup_port','backup_host_key')])
    result=m.wizard(target,input_fn=lambda _:next(replies),output_fn=lambda _:None)
    assert result['state']=='prepared' and json.loads(target.read_text())==data
    assert target.stat().st_mode & 0o777==0o600


def test_cancelled_backup_setup_creates_nothing(tmp_path):
    m=importlib.import_module('backup_setup')
    assert m.wizard(tmp_path/'backup.json',input_fn=lambda _:':cancel',output_fn=lambda _:None)['state']=='cancelled'
    assert not list(tmp_path.iterdir())

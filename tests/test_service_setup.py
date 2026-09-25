import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from service_setup import wizard
from service_contracts import validate


def test_wizard_writes_private_nonsecret_profile_after_identity_review(tmp_path):
    answers=iter(['south','home-services','matrix.south.test','chat.south.test','/root/cert.pem','/root/key.pem','SAVE'])
    target=tmp_path/'service.json'
    assert wizard(target,input_fn=lambda prompt:next(answers),output_fn=lambda text:None)['state']=='prepared'
    assert validate(json.loads(target.read_text()))==[]
    assert target.stat().st_mode&0o077==0


def test_cancelled_wizard_has_no_configuration_output(tmp_path):
    target=tmp_path/'service.json'
    assert wizard(target,input_fn=lambda prompt:':cancel',output_fn=lambda text:None)['state']=='cancelled'
    assert not target.exists()

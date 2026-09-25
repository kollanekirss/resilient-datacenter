import importlib
import json
from test_gateway_contracts import profile
from test_regional_agreements import pair


def test_gateway_guided_setup_builds_private_profile_without_installation(tmp_path):
    m=importlib.import_module('gateway_setup');_,_,own,_=pair();target=tmp_path/'gateway.json'
    answers=iter(['10.203.1.0/24','10.203.1.1','10.203.1.10','10.203.1.11','/root/gateway.crt','/root/gateway.key','SAVE'])
    result=m.wizard(own, '/root/public-identity.json',target,input_fn=lambda _:next(answers),output_fn=lambda _:None)
    assert result['state']=='prepared' and json.loads(target.read_text())==profile()
    assert target.stat().st_mode&0o777==0o600


def test_gateway_parser_separates_local_install_and_partner_admission():
    from rdc import parser
    result=parser().parse_args(['gateway','policy','--agreement','one.json','--agreement','two.json'])
    assert result.gateway_action=='policy' and len(result.agreement)==2
    result=parser().parse_args(['gateway','revoke','1'*32]);assert result.agreement_id=='1'*32
    assert parser().parse_args(['gateway','resume']).gateway_action=='resume'


def test_public_link_export_and_application_attachment_are_distinct_commands():
    from rdc import parser
    assert parser().parse_args(['gateway','service-link','--output-file','link.json']).gateway_action=='service-link'
    result=parser().parse_args(['services','regional','attach','link.json'])
    assert result.action=='regional' and result.regional_service_action=='attach'
    assert parser().parse_args(['services','regional','disable']).regional_service_action=='disable'

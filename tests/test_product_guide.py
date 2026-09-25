import importlib
import json
from pathlib import Path
import sys
import pytest
from test_product_journey import answers
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_guide_routes_chat_setup_to_existing_wizard_with_one_path_argument(tmp_path):
    journey=importlib.import_module('product_journey');m=importlib.import_module('product_guide')
    folder=tmp_path/'private plan with spaces';folder.mkdir()
    path=folder/'journey.json';path.write_text(json.dumps(journey.record(answers())))
    replies=iter(['3','1'])
    argv=m.choose(path,input_fn=lambda _:next(replies),output_fn=lambda _:None)
    assert argv==['services','setup','--output-file',str(folder/'matrix.json')]
    from rdc import parser
    args=parser().parse_args(argv)
    assert args.output_file==folder/'matrix.json'
    assert sorted(p.name for p in folder.iterdir())==['journey.json']


def test_guide_only_offers_selected_services_and_partner_roles_when_relevant(tmp_path):
    journey=importlib.import_module('product_journey');m=importlib.import_module('product_guide')
    personal=m.groups(journey.record(answers()),tmp_path)
    assert 'matrix' in personal and 'nextcloud' not in personal and 'gateway' not in personal
    regional=m.groups(journey.record(answers('regional','both','existing')),tmp_path)
    assert {'matrix','nextcloud','gateway','approvals'}<=set(regional)


def test_every_fixed_guided_task_uses_the_existing_argument_parser(tmp_path):
    journey=importlib.import_module('product_journey');m=importlib.import_module('product_guide')
    from rdc import parser
    for tasks in m.groups(journey.record(answers('regional','both')),tmp_path).values():
        for task in tasks:
            def reply(prompt):
                if 'snapshot ID' in prompt:return 'a'*64
                if 'fingerprint' in prompt:return 'b'*64
                if 'agreement ID' in prompt:return 'c'*32
                if 'How many' in prompt:return '1'
                if 'package' in prompt:return 'matrix'
                return str(tmp_path/'reviewed document.json')
            argv=m.arguments(task,reply)
            assert parser().parse_args(argv).command in ('setup','infrastructure','node','doctor','services','files','gateway','regional','backup')


def test_invalid_selection_and_cancel_never_dispatch(tmp_path):
    journey=importlib.import_module('product_journey');m=importlib.import_module('product_guide')
    path=tmp_path/'journey.json';path.write_text(json.dumps(journey.record(answers())))
    assert m.choose(path,input_fn=lambda _:'0',output_fn=lambda _:None) is None
    with pytest.raises(ValueError):m.choose(path,input_fn=lambda _:'--install-all',output_fn=lambda _:None)


def test_common_cli_dispatches_guided_task_without_a_second_execution_engine(tmp_path,monkeypatch):
    import rdc
    import product_journey
    path=tmp_path/'journey.json';path.write_text(json.dumps(product_journey.record(answers())))
    replies=iter(['3','1']);monkeypatch.setattr('builtins.input',lambda _:next(replies))
    calls=[]
    monkeypatch.setattr(rdc,'service_action',lambda args:(calls.append(args) or {'state':'prepared'}))
    assert rdc.main(['guide',str(path)])==0
    assert len(calls)==1 and calls[0].action=='setup' and calls[0].output_file==tmp_path/'matrix.json'


def test_common_cli_start_is_preparation_only(tmp_path,monkeypatch):
    import rdc
    replies=iter(['personal','north','matrix','Alice Example','tallinn','tartu','new','SAVE'])
    monkeypatch.setattr('builtins.input',lambda _:next(replies))
    assert rdc.main(['start','--output-dir',str(tmp_path)])==0
    assert json.loads((tmp_path/'journey.json').read_text())['state']=='prepared'

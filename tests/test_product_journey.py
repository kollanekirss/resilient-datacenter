import importlib
import json
import pytest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def answers(purpose='personal',services='matrix',network='new'):
    return {'purpose':purpose,'institution_id':'north','services':services,'responsible_operator':'Alice Example',
            'primary_location':'tallinn','recovery_location':'tartu','network':network}


def test_personal_plan_separates_roles_and_recovery_from_replication():
    m=importlib.import_module('product_journey');record=m.record(answers())
    roles={item['role']:item for item in record['machines']}
    assert {'controller','relay','matrix','backup','matrix-replacement'}<=set(roles)
    assert roles['matrix']['location']=='tallinn' and roles['backup']['location']=='tartu'
    assert roles['matrix-replacement']['state']=='capacity-to-prepare'
    assert roles['controller']['machine']!=roles['relay']['machine']
    assert record['state']=='prepared'


def test_institution_and_regional_roles_keep_authorities_distinct():
    m=importlib.import_module('product_journey')
    institution=m.record(answers('institution','both'))
    assert {'matrix','nextcloud'}<={item['role'] for item in institution['machines']}
    regional=m.record(answers('regional','both','existing'))
    assert not any(item['role']=='controller' for item in regional['machines'])
    assert next(item for item in regional['machines'] if item['role']=='gateway-backup')['network']=='regional'
    for item in regional['machines']:
        if item['role']=='gateway':assert item['network']=='regional' and item['forwarding']=='disabled'
        elif item['role'] in ('matrix','nextcloud'):assert item['network']=='institutional'


@pytest.mark.parametrize('change',[{'command':'install everything'},{'services':'sharepoint'},{'recovery_location':'tallinn'},
                                  {'institution_id':'../other'},{'responsible_operator':'Alice\nRUN secret'}])
def test_journey_rejects_unknown_or_unsafe_answers(change):
    m=importlib.import_module('product_journey')
    with pytest.raises(ValueError):m.record(dict(answers(),**change))


def test_wizard_saves_draft_then_resumes_without_claiming_deployment(tmp_path):
    m=importlib.import_module('product_journey');output=[]
    replies=iter(['personal','north',':save'])
    assert m.wizard(tmp_path,input_fn=lambda _:next(replies),output_fn=output.append)['state']=='draft'
    draft=tmp_path/'draft.yml';assert draft.stat().st_mode&0o777==0o600
    replies=iter(['','','matrix','Alice Example','tallinn','tartu','new','SAVE'])
    result=m.wizard(tmp_path,resume=draft,input_fn=lambda _:next(replies),output_fn=output.append)
    assert result['state']=='prepared' and result['deployment']=='not-performed'
    document=json.loads((tmp_path/'journey.json').read_text());assert document==m.record(answers())
    guide=(tmp_path/'START-HERE.md').read_text()
    assert 'not two writable copies' in guide and 'backup' in guide and './rdc guide' in guide
    assert (tmp_path/'journey.json').stat().st_mode&0o777==0o600


def test_cancel_does_not_create_outputs(tmp_path):
    m=importlib.import_module('product_journey');output=tmp_path/'unused'
    assert m.wizard(output,input_fn=lambda _:':cancel',output_fn=lambda _:None)['state']=='cancelled'
    assert not output.exists()

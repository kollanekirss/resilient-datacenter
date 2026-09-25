import importlib
from test_setup_contracts import infrastructure as original_infrastructure
import pytest


def infrastructure():
    data=original_infrastructure();data['all']['vars']['enrollment_nodes'].append({'name':'other-client','node_tag':'tag:other-client'})
    return data


def test_explicit_service_access_only_grants_the_selected_direction_and_port():
    from setup_contracts import validate_infrastructure,normalize_infrastructure
    data=infrastructure();nodes=data['all']['vars']['enrollment_nodes']
    data['all']['vars']['service_access']=[{'source':nodes[0]['name'],'destination':nodes[1]['name'],'service':'https'}]
    assert validate_infrastructure(data,check_files=False)==[]
    assert normalize_infrastructure(data)['policy']['grants']==[{'src':[nodes[0]['node_tag']],'dst':[nodes[1]['node_tag']],'ip':['tcp:443']}]


@pytest.mark.parametrize('entry',[{'source':'unknown','destination':'other','service':'https'},
                                  {'source':'*','destination':'*','service':'all'},None,{'command':'execute'}])
def test_unknown_nodes_wildcards_and_commands_are_rejected(entry):
    from setup_contracts import validate_infrastructure
    data=infrastructure();data['all']['vars']['service_access']=[entry]
    assert validate_infrastructure(data,check_files=False)


def test_access_preparation_does_not_mutate_source_and_remove_is_exact():
    m=importlib.import_module('service_access');data=infrastructure();nodes=data['all']['vars']['enrollment_nodes']
    revised=m.change(data,nodes[0]['name'],nodes[1]['name'],'https')
    assert 'service_access' not in data['all']['vars']
    assert len(revised['all']['vars']['service_access'])==1
    assert m.change(revised,nodes[0]['name'],nodes[1]['name'],'https')==revised
    removed=m.change(revised,nodes[0]['name'],nodes[1]['name'],'https',remove=True)
    assert removed['all']['vars']['service_access']==[]

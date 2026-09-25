import copy
import pytest
from test_setup_contracts import infrastructure,setup_api


def multiple():
    data=infrastructure();hosts=data['all']['children']['relay']['hosts']
    original=next(iter(hosts.values()))
    hosts['second-relay']={**original,'ansible_host':'9.9.9.9'}
    data['all']['vars']['additional_relays']=[{'host':'second-relay','hostname':'relay-two.pilot.test','region_id':902}]
    return data


def test_multiple_locations_normalize_without_changing_legacy_ownership():
    data=multiple();module=setup_api()
    assert module.validate_infrastructure(data,check_files=False)==[]
    result=module.normalize_infrastructure(data)
    assert len(result['relays'])==2
    assert result['relays'][1]=={'host':'second-relay','hostname':'relay-two.pilot.test','region_id':902,'address':'9.9.9.9'}
    assert result['relay_hostnames']['second-relay']=='relay-two.pilot.test'
    assert all(x['schema_version']==2 for x in result['ownership'].values())
    legacy=module.normalize_infrastructure(infrastructure())
    assert len(legacy['relays'])==1 and legacy['relays'][0]['region_id']==901


@pytest.mark.parametrize('change',[
    lambda d:d['all']['vars']['additional_relays'][0].update(region_id=901),
    lambda d:d['all']['vars']['additional_relays'][0].update(region_id=True),
    lambda d:d['all']['vars']['additional_relays'][0].update(host='unmanaged'),
    lambda d:d['all']['vars']['additional_relays'][0].update(hostname=d['all']['vars']['derp_hostname']),
    lambda d:d['all']['vars']['additional_relays'][0].update(command='private-command'),
    lambda d:d['all']['children']['relay']['hosts']['second-relay'].update(ansible_host=next(iter(d['all']['children']['controller']['hosts'].values()))['ansible_host']),
    lambda d:d['all']['children']['relay']['hosts']['second-relay'].pop('tls_private_key'),
    lambda d:d['all']['vars'].update(additional_relays=[]),
    lambda d:d['all']['vars'].update(additional_relays='unsafe'),
])
def test_invalid_multi_relay_input_is_rejected_before_remote_actions(change):
    data=multiple();change(data)
    assert setup_api().validate_infrastructure(data,check_files=False)


def test_managed_certificates_bind_each_relay_to_its_own_hostname():
    data=multiple();data['all']['vars'].update(schema_version=3,tls_mode='managed-acme',acme_email='operator@pilot.test',acme_terms_accepted=True)
    for section in data['all']['children'].values():
        for host in section['hosts'].values():
            host.pop('tls_certificate');host.pop('tls_private_key')
    assert setup_api().validate_infrastructure(data,check_files=False)==[]
    result=setup_api().normalize_infrastructure(data)
    assert result['ownership']['second-relay']['certificate_hostname']=='relay-two.pilot.test'


def test_rendered_map_contains_every_validated_region_and_distinct_endpoint():
    from pathlib import Path
    from jinja2 import Environment,FileSystemLoader,StrictUndefined
    import yaml
    root=Path(__file__).resolve().parents[1]
    topology=setup_api().normalize_infrastructure(multiple())
    template=Environment(loader=FileSystemLoader(root/'roles'),undefined=StrictUndefined).get_template('controller/templates/derp-map.yml.j2')
    result=yaml.safe_load(template.render(profile_relays=topology['relays']))
    assert set(result['regions'])=={901,902}
    assert result['regions'][902]['nodes'][0]['hostname']=='relay-two.pilot.test'
    assert result['regions'][902]['nodes'][0]['ipv4']=='9.9.9.9'

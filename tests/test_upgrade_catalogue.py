import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_only_complete_reviewed_predecessors_have_a_forward_transition():
    import application_catalogue as m
    for package,component,source,target in [('matrix','synapse','1.160.0','1.161.0'),('nextcloud','nextcloud','35.0.0','35.0.1')]:
        before=m.predecessor(package);after=m.current(package)
        assert before[component]['version']==source and after[component]['version']==target
        transition=m.transition(package,before)
        assert transition['target']==after and transition['source']==before
        assert m.transition(package,after) is None
        changed=json.loads(json.dumps(before));changed[component]['image']='unreviewed@sha256:'+'a'*64
        with pytest.raises(ValueError):m.transition(package,changed)
        changed=json.loads(json.dumps(before));changed['postgres']['version']='18.0'
        with pytest.raises(ValueError):m.transition(package,changed)


def test_backup_can_identify_exact_prior_images_without_accepting_owner_changes():
    import application_catalogue as m
    from test_backup_service_scope import fixture
    from backup_scope import include
    network,application=fixture()
    prior=dict(application,images={k:v['image'] for k,v in m.predecessor('matrix').items()})
    assert m.for_owner(prior)==m.predecessor('matrix')
    assert include(network,prior)['applications']==prior
    with pytest.raises(ValueError):include(network,dict(prior,node_name='another'))
    altered=dict(prior,images=dict(prior['images'],synapse='ghcr.io/element-hq/synapse@sha256:'+'b'*64))
    with pytest.raises(ValueError):include(network,altered)


def test_version_transition_cannot_silently_downgrade_or_take_arbitrary_tags():
    import application_catalogue as m
    with pytest.raises(ValueError):m.predecessor('gateway')
    with pytest.raises(ValueError):m.transition('matrix',{'image':'latest'})

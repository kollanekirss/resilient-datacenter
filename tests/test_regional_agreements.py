"""Offline bilateral consent, not proof that regional traffic is admitted."""
from copy import deepcopy
import importlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

NOW=1800000000


def api():return importlib.import_module('regional_agreements')


def pair():
    m=api();a=bytes.fromhex('11'*32);b=bytes.fromhex('22'*32)
    def identity(key,name,ip):
        return m.identity(key,institution_id=name,regional_controller='regional.example.test',gateway_node=name+'-gateway',gateway_ipv4=ip,
                          services={'matrix':'matrix.'+name+'.test','nextcloud':'files.'+name+'.test'})
    return a,b,identity(a,'north','100.64.0.10'),identity(b,'south','100.64.0.11')


def agreement():
    m=api();a,b,north,south=pair()
    offer=m.offer(a,north,south,['matrix','nextcloud'],now=NOW,expires_at=NOW+3600,expected_peer=m.fingerprint(south))
    return m.accept(b,offer,now=NOW+1,expected_peer=m.fingerprint(north)),north,south


def test_bilateral_signature_does_not_imply_local_trust_or_transport():
    m=api();document,north,south=agreement()
    result=m.evaluate(document,local_fingerprint=m.fingerprint(north),approved_peers=[],revoked_ids=[],now=NOW+2)
    assert result['state']=='peer-not-approved'
    result=m.evaluate(document,local_fingerprint=m.fingerprint(north),approved_peers=[m.fingerprint(south)],revoked_ids=[],now=NOW+2)
    assert result['state']=='mutually-approved' and result['transport']=='not-verified'
    assert result['services']==['matrix','nextcloud']
    assert m.evaluate(document,local_fingerprint=m.fingerprint(north),approved_peers=[m.fingerprint(south)],revoked_ids=[result['agreement_id']],now=NOW+2)['state']=='revoked'
    assert m.evaluate(document,local_fingerprint=m.fingerprint(north),approved_peers=[m.fingerprint(south)],revoked_ids=[],now=NOW+3600)['state']=='expired'


def test_altered_identity_offer_or_acceptance_never_verifies():
    m=api();document,north,south=agreement()
    for change in ('domain','services','expiry','signature','acceptance'):
        tampered=deepcopy(document)
        offer=tampered['offer']['payload']
        if change=='domain':offer['recipient']['payload']['services']['matrix']='matrix.attacker.test'
        elif change=='services':offer['services']=['matrix']
        elif change=='expiry':offer['expires_at']+=1
        elif change=='signature':tampered['offer']['signature']='00'*64
        else:tampered['acceptance']['payload']['offer_sha256']='00'*32
        with pytest.raises(ValueError):m.verify_agreement(tampered)


def test_fingerprint_confirmation_and_recipient_key_are_required():
    m=api();a,b,north,south=pair()
    with pytest.raises(ValueError):m.offer(a,north,south,['matrix'],now=NOW,expires_at=NOW+60,expected_peer='00'*32)
    offer=m.offer(a,north,south,['matrix'],now=NOW,expires_at=NOW+60,expected_peer=m.fingerprint(south))
    with pytest.raises(ValueError):m.accept(a,offer,now=NOW+1,expected_peer=m.fingerprint(north))
    with pytest.raises(ValueError):m.accept(b,offer,now=NOW+1,expected_peer='00'*32)
    with pytest.raises(ValueError):m.accept(b,offer,now=NOW+60,expected_peer=m.fingerprint(north))


def test_approval_cannot_cross_networks_or_claim_same_service_identity():
    m=api();a,b,north,south=pair()
    for changes in ({'regional_controller':'another.test'},{'gateway_ipv4':'100.64.0.10'},
                    {'services':{'matrix':'matrix.north.test'}},{'institution_id':'north'}):
        data={k:v for k,v in south['payload'].items() if k not in ('kind','schema_version','public_key')};data.update(changes)
        other=m.identity(b,**data)
        with pytest.raises(ValueError):m.offer(a,north,other,['matrix'],now=NOW,expires_at=NOW+60,expected_peer=m.fingerprint(other))


@pytest.mark.parametrize('services',[[],['matrix','matrix'],['shell'],['matrix','nextcloud','ssh']])
def test_scope_is_a_nonempty_supported_set(services):
    m=api();a,b,north,south=pair()
    with pytest.raises(ValueError):m.offer(a,north,south,services,now=NOW,expires_at=NOW+60,expected_peer=m.fingerprint(south))


@pytest.mark.parametrize('expiry',[NOW,NOW-1,NOW+90*86400+1,True,'tomorrow'])
def test_agreement_lifetime_is_bounded(expiry):
    m=api();a,b,north,south=pair()
    with pytest.raises(ValueError):m.offer(a,north,south,['matrix'],now=NOW,expires_at=expiry,expected_peer=m.fingerprint(south))


@pytest.mark.parametrize('raw',[b'{"kind":"a","kind":"b"}',b'{"x":NaN}',b'{"x":1.2}',b'[]',b'x'*32769],ids=['duplicate-key','nonfinite','float','array','oversized'])
def test_import_rejects_ambiguous_or_oversized_documents(raw):
    with pytest.raises(ValueError):api().decode(raw)

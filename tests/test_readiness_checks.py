import importlib
from datetime import datetime,timedelta,timezone
from pathlib import Path
import sys
import json
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
NOW=datetime(2026,9,26,tzinfo=timezone.utc)


def api():return importlib.import_module('readiness_checks')


@pytest.fixture
def certificates():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic root')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(key.public_key())
        .serial_number(1).not_valid_before(NOW-timedelta(days=1)).not_valid_after(NOW+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False).sign(key,hashes.SHA256()))
    def leaf(days=90,hostname='chat.example.test',wrong_key=False,names=None):
        leafkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
            .issuer_name(ca_name).public_key(leafkey.public_key()).serial_number(2)
            .not_valid_before(NOW-timedelta(days=2)).not_valid_after(NOW+timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (names or [hostname])]),False)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(key,hashes.SHA256()))
        private=key if wrong_key else leafkey
        return cert.public_bytes(serialization.Encoding.PEM),private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),ca.public_bytes(serialization.Encoding.PEM)
    return leaf


def test_certificate_checks_actual_chain_key_name_and_window(certificates):
    assert api().certificate(*certificates(),['chat.example.test'],NOW,30)['state']=='verified'


@pytest.mark.parametrize('kwargs,state',[({'days':-1},'expired'),({'days':10},'expired'),({'wrong_key':True},'invalid'),({'hostname':'wrong.example.test'},'invalid')])
def test_certificate_rejects_invalid_material(certificates,kwargs,state):
    assert api().certificate(*certificates(**kwargs),['chat.example.test'],NOW,30)['state']==state


def test_untrusted_chain_rejected(certificates):
    cert,key,_=certificates()
    assert api().certificate(cert,key,b'garbage',['chat.example.test'],NOW,30)['state']=='invalid'


def plan():
    value=json.loads((Path(__file__).resolve().parents[1]/'examples/portable-site.json').read_text())
    value['domains']={role:role+'.south.test' for role in ('chat','element','files')}
    return value


def snapshot(role='chat'):
    p=plan();owner=api().expected_owner(p,role)
    from backup_contracts import resources,binary_paths
    return {'schema_version':1,'ownership':owner,'paths':list(resources(owner).paths),
        'captured_at':(NOW-timedelta(hours=2)).isoformat(),
        'services_originally_active':dict.fromkeys(resources(owner).services,True),
        'binary_sha256':dict.fromkeys(binary_paths(owner),'a'*64)}


def test_backup_age_is_metadata_evidence_not_recovery_proof():
    result=api().backup(snapshot(),plan(),'chat',NOW,24)
    assert result['state']=='recorded' and result['age_seconds']==7200
    assert result['basis']=='saved-snapshot-metadata'


@pytest.mark.parametrize('change,state',[('old','stale'),('future','invalid'),('naive','invalid'),('wrong-site','invalid'),('wrong-role','invalid'),('incomplete','invalid')])
def test_backup_evidence_rejects_bad_binding_or_time(change,state):
    data=snapshot()
    if change=='old':data['captured_at']=(NOW-timedelta(days=2)).isoformat()
    if change=='future':data['captured_at']=(NOW+timedelta(seconds=1)).isoformat()
    if change=='naive':data['captured_at']='2026-09-26T00:00:00'
    if change=='wrong-site':data['ownership']['institution_id']='wrong'
    if change=='wrong-role':data=snapshot('files')
    if change=='incomplete':data['paths']=[]
    assert api().backup(data,plan(),'chat',NOW,24)['state']==state


def test_exercise_record_is_bound_and_never_verified():
    from portable_network import fingerprint
    data={'schema_version':1,'site_sha256':fingerprint(plan()),'role':'chat','backup_metadata_sha256':'a'*64,'performed_at':NOW.isoformat(),'result':'pass'}
    assert api().exercise(data,plan(),'chat','a'*64,NOW,30)['state']=='recorded'
    assert api().exercise(data,plan(),'chat','b'*64,NOW,30)['state']=='invalid'
    data['result']='fail'
    assert api().exercise(data,plan(),'chat','a'*64,NOW,30)['state']=='invalid'


def test_unsupported_private_key_is_invalid_evidence_not_a_crash(certificates):
    import base64
    from cryptography.hazmat.primitives.asymmetric import ec
    key=ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    key=key.replace(bytes.fromhex('06082a8648ce3d030107'),bytes.fromhex('06082a8648ce3d03017f'))
    pem=b'-----BEGIN PRIVATE KEY-----\n'+base64.encodebytes(key)+b'-----END PRIVATE KEY-----\n'
    cert,_,ca=certificates()
    assert api().certificate(cert,pem,ca,['chat.example.test'],NOW,30)['state']=='invalid'


@pytest.mark.parametrize('when,state',[('2026-09-27T00:00:00+00:00','invalid'),('2026-08-01T00:00:00+00:00','stale'),('2026-09-26T00:00:00','invalid')])
def test_exercise_age_and_clock_are_checked(when,state):
    from portable_network import fingerprint
    data={'schema_version':1,'site_sha256':fingerprint(plan()),'role':'files','backup_metadata_sha256':'a'*64,'performed_at':when,'result':'pass'}
    assert api().exercise(data,plan(),'files','a'*64,NOW,30)['state']==state

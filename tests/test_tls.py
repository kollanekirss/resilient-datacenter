import importlib.util
from pathlib import Path
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

@pytest.fixture
def certs(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'a.pilot.test')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(hours=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName('a.pilot.test')]),False).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
    cp=tmp_path/'cert.pem'; kp=tmp_path/'key.pem'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return cp,kp

def validator():
    path=Path(__file__).resolve().parents[1]/'scripts/validate_tls.py'
    assert path.exists(), 'TLS validator not implemented'
    spec=importlib.util.spec_from_file_location('tls_validator',path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.validate_certificate

def test_valid_certificate(certs):
    cp,kp=certs
    assert validator()(cp,kp,'a.pilot.test',cp)==[]

def test_wrong_hostname(certs):
    cp,kp=certs
    assert any('hostname' in e for e in validator()(cp,kp,'b.pilot.test',cp))

def test_wrong_key(certs,tmp_path):
    cp,kp=certs
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    assert any('key' in e for e in validator()(cp,kp,'a.pilot.test',cp))

def test_expired_certificate(certs):
    cp,kp=certs
    key=serialization.load_pem_private_key(kp.read_bytes(),password=None)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'a.pilot.test')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=3)).not_valid_after(datetime.now(timezone.utc)-timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('a.pilot.test')]),False).sign(key,hashes.SHA256()))
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    assert any('expired' in e for e in validator()(cp,kp,'a.pilot.test'))

def test_invalid_trust_bundle(certs,tmp_path):
    cp,kp=certs; ca=tmp_path/'bad-ca.crt'; ca.write_text('invalid certificate')
    assert any('trusted' in e for e in validator()(cp,kp,'a.pilot.test',ca))

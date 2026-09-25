"""Check certificate identity, validity, key and (when supplied) chain."""
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def validate_certificate(cert_path,key_path,hostname,ca_path=None):
    try:
        certificates=x509.load_pem_x509_certificates(Path(cert_path).read_bytes())
        cert=certificates[0]
        key=serialization.load_pem_private_key(Path(key_path).read_bytes(),password=None)
        errors=[]
        public=lambda k:k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        if public(key.public_key())!=public(cert.public_key()): errors.append('Certificate and private key do not match')
        now=datetime.now(timezone.utc)
        if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc: errors.append('Certificate is expired or not yet valid')
        names=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        match=lambda n:n==hostname or (n.startswith('*.') and hostname.split('.',1)[-1]==n[2:] and hostname.count('.')==n.count('.'))
        if not any(match(n) for n in names): errors.append('Certificate hostname does not match SAN')
        if ca_path:
            result=subprocess.run(['openssl','verify','-CAfile',str(ca_path),'-untrusted',str(cert_path),'-purpose','sslserver',str(cert_path)],capture_output=True)
            if result.returncode: errors.append('Certificate chain is not trusted by the test CA bundle')
        return errors
    except Exception:
        return ['Cannot validate certificate/private key; require PEM, unencrypted key and DNS SAN']

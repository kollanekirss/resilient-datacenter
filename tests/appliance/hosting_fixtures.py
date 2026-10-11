import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess


def hosting_site(site, *, both=True):
    site = copy.deepcopy(site)
    site['roles']['headscale'] = {'selected': True, 'authority': 'pilot-authority',
        'hostname': 'control.example.net', 'public_ipv4': '8.8.4.4',
        'certificate_ref': 'control-cert', 'exposure': 'upstream-dnat',
        'upstream_owner': 'institution-network-team'}
    site['vms']['headscale'] = {'role': 'headscale', 'vmid': 104, 'name': 'pilot-headscale',
        'memory_mib': 1024, 'vcpus': 1, 'disk_gib': 8, 'storage': 'local-lvm',
        'nics': [{'zone': 'infrastructure', 'mac': '02:bb:00:00:00:07',
                  'address': '10.77.1.11', 'connected': False}]}
    if both:
        site['networks']['relay'] = {'bridge': 'vmbr4', 'cidr': '8.8.8.0/29',
            'gateway': '8.8.8.1', 'allocation': 'static'}
        site['vms']['router']['nics'].append({'zone': 'relay', 'mac': '02:bb:00:00:00:09', 'connected': False})
        site['roles']['derp'] = {'selected': True, 'hostname': 'relay.example.net',
            'public_ipv4': '8.8.8.2', 'certificate_ref': 'relay-cert',
            'region_id': 901, 'controller_url': 'https://control.example.net',
            'routed_prefix': '8.8.8.0/29', 'gateway': '8.8.8.1',
            'upstream_owner': 'institution-network-team'}
        site['vms']['derp'] = {'role': 'derp', 'vmid': 105, 'name': 'pilot-derp',
            'memory_mib': 1024, 'vcpus': 1, 'disk_gib': 8, 'storage': 'local-lvm',
            'nics': [{'zone': 'relay', 'mac': '02:bb:00:00:00:08',
                      'address': '8.8.8.2', 'connected': False}]}
    return site


def certificates(hostname='control.example.net', *, lifetime_days=90):
    """Local CA and leaf for real TLS validation; never used as deployment input."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-only hosting CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365)).not_valid_after(now + timedelta(days=lifetime_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    return {'certificate_pem': cert.public_bytes(serialization.Encoding.PEM).decode(),
            'private_key_pem': key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'trust_pem': ca.public_bytes(serialization.Encoding.PEM).decode()}


class HostingRunner:
    """Script native process effects, while TLS and filesystem behavior are real."""
    def __init__(self, state):
        self.state, self.calls, self.failure = Path(state), [], None

    def run(self, argv, **kwargs):
        from appliance.contracts import ApplianceError
        from appliance.guest.hosting import private_write
        self.calls.append(argv)
        if self.failure and self.failure in argv:
            raise ApplianceError('command-failed')
        output = b''
        if argv == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']:
            output = b'12345678-1234-1234-1234-123456789012\n'
        if argv[:2] == ['/usr/bin/headscale', 'version']:
            output = b'v0.29.4\n'
        if argv[:2] == ['/usr/bin/derper', '-version']:
            output = b'1.104.1-t012345\n'
        if argv[:2] == ['/usr/bin/derper', '-help']:
            output = b'-verify-client-url-fail-open\n'
        if 'configtest' in argv:
            configuration = json.loads(Path(argv[1].split('=', 1)[1]).read_text())
            key = Path(configuration['noise']['private_key_path'])
            if not key.exists(): private_write(key, b'actual-native-test-noise-key')
            db = Path(configuration['database']['sqlite']['path'])
            if not db.exists(): private_write(db, b'actual-native-test-db')
        if argv == ['/usr/bin/systemctl', 'restart', 'derper.service']:
            key = self.state / 'derp/derper.key'
            if not key.exists(): private_write(key, b'{"PrivateKey":"test-only-native-derper-key"}')
        if 'users' in argv and 'list' in argv:
            output = b'[]'
        return subprocess.CompletedProcess(argv, 0, output, b'')

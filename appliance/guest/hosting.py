"""Private TLS and service helpers shared by the two hosting guests.

TLS is checked with a real in-memory TLS handshake. This validates the key,
chain, purpose, DNS identity and current validity without opening a socket or
calling the public endpoint. Public reachability is a separate external test.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import ssl
import tempfile
import time

from .. import files
from ..contracts import ApplianceError, fields, identity, require
from ..hosting import hostname, prerequisites
from ..state import read, write


def validate_tls(name, credentials):
    hostname(name)
    for key in ('certificate_pem', 'private_key_pem', 'trust_pem'):
        value = credentials.get(key)
        require(type(value) is str and 0 < len(value.encode()) <= 131072, 'hosting-tls-material')
    try:
        with tempfile.TemporaryDirectory(prefix='rdc-tls-') as temporary:
            root = Path(temporary).resolve()
            for key, filename in (('certificate_pem', 'cert.pem'), ('private_key_pem', 'key.pem')):
                files.atomic_write(Path('/'), root / filename, credentials[key].encode(), mode=0o600)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(root / 'cert.pem', root / 'key.pem', password=lambda: '')
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.minimum_version = ssl.TLSVersion.TLSv1_2
            client_context.load_verify_locations(cadata=credentials['trust_pem'])
            sin, sout, cin, cout = (ssl.MemoryBIO() for _ in range(4))
            server = server_context.wrap_bio(sin, sout, server_side=True)
            client = client_context.wrap_bio(cin, cout, server_hostname=name)
            complete = set()
            for _ in range(16):
                for label, connection in (('client', client), ('server', server)):
                    if label in complete:
                        continue
                    try:
                        connection.do_handshake()
                        complete.add(label)
                    except ssl.SSLWantReadError:
                        pass
                if cout.pending:
                    sin.write(cout.read())
                if sout.pending:
                    cin.write(sout.read())
                if len(complete) == 2:
                    break
            require(len(complete) == 2, 'hosting-tls-invalid')
            cert = client.getpeercert()
            expiration = int(ssl.cert_time_to_seconds(cert['notAfter']))
            now = int(time.time())
            require(expiration > now, 'hosting-tls-invalid')
            return {'valid': True, 'certificate_sha256': hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest(),
                    'trust_sha256': hashlib.sha256(credentials['trust_pem'].encode()).hexdigest(),
                    'expires_at': expiration, 'renewal_due': expiration - now < 30 * 86400,
                    'checked_at': now}
    except (ssl.SSLError, OSError, ValueError, KeyError):
        raise ApplianceError('hosting-tls-invalid') from None


def record(state, role):
    path = Path(state) / role / ('authority.json' if role == 'headscale' else 'identity.json')
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return read(path)


def save(state, role, value):
    write(Path(state) / role / ('authority.json' if role == 'headscale' else 'identity.json'), value)


def private_write(path, raw):
    files.atomic_write(Path('/'), Path(path), raw, mode=0o600)


def digest_file(path):
    data = files.read_optional(Path('/'), Path(path))
    require(data is not None and bool(data), 'role-identity-missing')
    return hashlib.sha256(data).hexdigest()


def check_version(runner, binary, arguments, version):
    output = runner.run([binary, *arguments], timeout_s=30).stdout.decode('utf-8', errors='replace')
    require(re.search(r'(?<![0-9.])v?' + re.escape(version) + r'(?![0-9.])', output) is not None,
            'role-binary-version')


def inputs(request, role):
    parameters = request['parameters']
    fields(parameters, {'plan', 'credentials'})
    plan, credentials = parameters['plan'], parameters['credentials']
    require(identity(plan) == request['plan_id'] and request['role'] == role, 'role-plan-binding')
    problems = prerequisites(plan, role)
    require(not problems, problems[0] if problems else 'hosting-prerequisites')
    fields(credentials, {'certificate_pem', 'private_key_pem', 'trust_pem'}
           | ({'authority'} if role == 'headscale' else set()),
           {'replace_certificate'} | ({'verifier_trust_pem'} if role == 'derp' else set()))
    require(type(credentials.get('replace_certificate', False)) is bool, 'certificate-replacement-approval')
    if role == 'headscale':
        require(credentials['authority'] == plan['roles'][role]['authority'], 'authority-approval-required')
    return plan, credentials


def install_tls(directory, name, credentials, observation, *, manual=False):
    directory = Path(directory) / 'tls' / observation['certificate_sha256']
    write(directory / 'metadata.json', observation)
    cert, key = (name + '.crt', name + '.key') if manual else ('tls.crt', 'tls.key')
    for filename, source in ((cert, 'certificate_pem'), (key, 'private_key_pem'), ('trust.pem', 'trust_pem')):
        private_write(directory / filename, credentials[source].encode())
    return {'certificate': str(directory / cert), 'key': str(directory / key),
            'trust': str(directory / 'trust.pem'), 'directory': str(directory)}


def inspect_role(request, state, runner, *, role, service, identity_file):
    current = record(state, role)
    if current is None:
        return {'role': role, 'plan_id': request['plan_id'], 'configured': False,
                'running': False, 'code': 'role-not-configured'}
    require(current['plan_id'] == request['plan_id'], 'role-plan-binding')
    actual = digest_file(Path(state) / role / identity_file)
    require(current.get('identity') == actual, 'role-identity-changed')
    require(digest_file(Path(state) / role / 'config.json') == current.get('config_id'), 'role-configuration-changed')
    policy_file = 'policy.json' if role == 'headscale' else 'hosts'
    require(digest_file(Path(state) / role / policy_file) == current.get('policy_id'), 'role-policy-changed')
    material = current.get('tls_files', {})
    prefix = Path(state) / role / 'tls' / current['tls']['certificate_sha256']
    credentials = {}
    for key, parameter in (('certificate', 'certificate_pem'), ('key', 'private_key_pem'), ('trust', 'trust_pem')):
        path = Path(material.get(key, ''))
        require(path.parent == prefix and path.name not in ('', '.', '..'), 'role-tls-path')
        raw = files.read_optional(Path('/'), path)
        require(raw is not None, 'role-tls-missing')
        try:
            credentials[parameter] = raw.decode('ascii')
        except UnicodeError:
            require(False, 'hosting-tls-material')
    tls = validate_tls(current['hostname'], credentials)
    require(tls['certificate_sha256'] == current['tls']['certificate_sha256']
            and tls['trust_sha256'] == current['tls']['trust_sha256'], 'role-tls-changed')
    if request['action'] == 'verify' and request['parameters'].get('reconnect') is True:
        require(current.get('phase') == 'configured', 'role-setup-needs-inspection')
        runner.run(['/usr/bin/systemctl', 'start', service], timeout_s=60)
    running = True
    try:
        runner.run(['/usr/bin/systemctl', 'is-active', '--quiet', service], timeout_s=15)
    except ApplianceError:
        running = False
    boot = runner.run(['/usr/bin/cat', '/proc/sys/kernel/random/boot_id'], timeout_s=10).stdout.decode().strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot), 'role-boot-observation')
    return {'role': role, 'plan_id': current['plan_id'], 'identity': actual,
            'configured': current.get('phase') == 'configured', 'running': running,
            'version': current['version'], 'tls': tls, 'tls_sha256': tls['certificate_sha256'],
            'certificate_id': tls['certificate_sha256'], 'boot_id': boot,
            'checked_at': int(time.time()), 'ordinary_client_ready': False}

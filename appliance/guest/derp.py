"""One persistent relay identity with explicit fail-closed client admission."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

from .. import files
from ..contracts import canonical, fields, identity, require
from ..derp import ROOT, VERSION, derp_config
from ..hosting import hostname, public_ipv4
from ..state import read
from .hosting import (check_version, digest_file, inputs, inspect_role, install_tls,
                      private_write, record, save, validate_tls)

SERVICE = 'derper.service'


def service_unit():
    return '''[Unit]
Description=Appliance standalone DERP relay
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 -m appliance.guest.derp serve
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
ReadWritePaths=/var/lib/rdc-guest/derp
BindReadOnlyPaths=/var/lib/rdc-guest/derp/hosts:/etc/hosts
[Install]
WantedBy=multi-user.target
'''


def command(config, *, root=ROOT):
    hostname(config['hostname'])
    public_ipv4(config['listen_address'])
    require(config['verify_client_url_fail_open'] is False, 'derp-fail-open-forbidden')
    require(type(config.get('tls_directory')) is str
            and config['tls_directory'].startswith(root + '/tls/')
            and re.fullmatch('[0-9a-f]{64}', config['tls_directory'].rsplit('/', 1)[1]), 'derp-tls-path')
    return ['/usr/bin/derper', '-a=' + config['listen_address'] + ':443',
            '-hostname=' + config['hostname'], '-certmode=manual',
            '-certdir=' + config['tls_directory'], '-c=' + root + '/derper.key',
            '-http-port=80', '-stun=true', '-stun-port=3478',
            '-verify-client-url=' + config['verify_client_url'],
            '-verify-client-url-fail-open=false', '-verify-clients=false',
            '-mesh-psk-file=', '-mesh-with=', '-home=blank']


def _inspect(request, state, runner):
    result = inspect_role(request, state, runner, role='derp', service=SERVICE, identity_file='derper.key')
    if result['configured']:
        directory = Path(state) / 'derp'
        require(digest_file(directory / 'hosts') == record(state, 'derp')['policy_id'], 'role-policy-changed')
        result.update(config_id=digest_file(directory / 'config.json'), policy_id=digest_file(directory / 'hosts'),
                      published=False)
    return result


def preflight(request, state, runner):
    """Validate without changing role files or starting a service."""
    if request['action'] != 'configure':
        return
    plan, credentials = inputs(request, 'derp')
    config = derp_config(plan)
    previous = record(state, 'derp')
    if previous:
        require(previous['hostname'] == config['hostname']
                and previous['controller_url'] == config['verify_client_url'], 'relay-identity-change-forbidden')
        require(previous.get('phase') == 'configured', 'role-setup-needs-inspection')
        require(digest_file(Path(state) / 'derp/derper.key') == previous['identity'], 'role-identity-changed')
    tls = validate_tls(config['hostname'], credentials)
    if previous and previous['tls']['certificate_sha256'] != tls['certificate_sha256']:
        require(credentials.get('replace_certificate') is True, 'certificate-replacement-approval')
    check_version(runner, '/usr/bin/derper', ['-version'], VERSION)
    result = runner.run(['/usr/bin/derper', '-help'], timeout_s=15)
    require(b'verify-client-url-fail-open' in result.stdout + result.stderr, 'derp-fail-closed-unsupported')
    verifier_trust = credentials.get('verifier_trust_pem', '')
    require(type(verifier_trust) is str and len(verifier_trust.encode()) <= 131072, 'derp-verifier-trust')
    if verifier_trust:
        import ssl
        try:
            ssl.create_default_context(cadata=verifier_trust)
        except (ssl.SSLError, ValueError):
            require(False, 'derp-verifier-trust')


def configure(request, state, runner):
    plan, credentials = inputs(request, 'derp')
    config = derp_config(plan)
    previous = record(state, 'derp')
    if previous:
        require(previous['hostname'] == config['hostname']
                and previous['controller_url'] == config['verify_client_url'], 'relay-identity-change-forbidden')
        require(previous.get('phase') == 'configured', 'role-setup-needs-inspection')
        require(digest_file(Path(state) / 'derp/derper.key') == previous['identity'], 'role-identity-changed')
    tls = validate_tls(config['hostname'], credentials)
    if previous and previous['tls']['certificate_sha256'] != tls['certificate_sha256']:
        require(credentials.get('replace_certificate') is True, 'certificate-replacement-approval')
    check_version(runner, '/usr/bin/derper', ['-version'], VERSION)
    help_result = runner.run(['/usr/bin/derper', '-help'], timeout_s=15)
    help_text = help_result.stdout + help_result.stderr
    require(b'verify-client-url-fail-open' in help_text, 'derp-fail-closed-unsupported')
    directory = Path(state) / 'derp'
    current = dict(previous) if previous else {'schema': 1, 'role': 'derp', 'phase': 'initializing',
            'plan_id': request['plan_id'], 'hostname': config['hostname'],
            'controller_url': config['verify_client_url'], 'version': VERSION}
    if previous is None:
        save(state, 'derp', current)
        require(files.read_optional(Path('/'), directory / 'derper.key') is None, 'unowned-relay-state')
    material = install_tls(directory, config['hostname'], credentials, tls, manual=True)
    config['tls_directory'] = material['directory']
    binding = config['verifier_host_binding']
    hosts = '127.0.0.1 localhost\n'
    if binding:
        hosts += binding['address'] + ' ' + binding['hostname'] + '\n'
    private_write(directory / 'hosts', hosts.encode())
    verifier_trust = credentials.get('verifier_trust_pem', '')
    require(type(verifier_trust) is str and len(verifier_trust.encode()) <= 131072, 'derp-verifier-trust')
    if verifier_trust:
        import ssl
        try:
            ssl.create_default_context(cadata=verifier_trust)
        except (ssl.SSLError, ValueError):
            require(False, 'derp-verifier-trust')
        private_write(directory / 'verifier-trust.pem', verifier_trust.encode())
    config['verifier_custom_trust'] = bool(verifier_trust)
    command(config, root=str(directory))
    private_write(directory / 'config.json', canonical(config))
    current.update(plan_id=request['plan_id'], phase='configuring', tls=tls, tls_files=material,
                   config_id=identity(config), policy_id=digest_file(directory / 'hosts'))
    save(state, 'derp', current)
    runner.run(['/usr/bin/systemctl', 'enable', SERVICE], timeout_s=30)
    runner.run(['/usr/bin/systemctl', 'restart', SERVICE], timeout_s=60)
    runner.run(['/usr/bin/systemctl', 'is-active', '--quiet', SERVICE], timeout_s=15)
    actual = digest_file(directory / 'derper.key')
    if previous:
        require(previous['identity'] == actual, 'role-identity-changed')
    current.update(identity=actual, phase='configured')
    save(state, 'derp', current)
    return _inspect(request, state, runner)


def handle(request, state, runner):
    if request['action'] in ('inspect', 'verify'):
        fields(request['parameters'], set(), {'reconnect'} if request['action'] == 'verify' else set())
        require(type(request['parameters'].get('reconnect', False)) is bool, 'role-reconnect')
        return _inspect(request, state, runner)
    require(request['action'] == 'configure', 'guest-action-forbidden')
    return configure(request, state, runner)


def main():
    require(sys.argv[1:] == ['serve'] and os.geteuid() == 0, 'derp-service-invocation')
    config = read(Path(ROOT) / 'config.json')
    argv = command(config)
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': ROOT}
    if config.get('verifier_custom_trust'):
        environment['SSL_CERT_FILE'] = ROOT + '/verifier-trust.pem'
    os.execve(argv[0], argv, environment)


if __name__ == '__main__':
    main()

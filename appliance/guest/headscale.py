"""Fixed local Headscale administration; never mint a replacement authority."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re

from .. import files
from ..contracts import canonical, fields, identity, require
from ..headscale import ROOT, VERSION, headscale_config
from .hosting import (check_version, digest_file, inputs, inspect_role, install_tls,
                      private_write, record, save, validate_tls)

SERVICE = 'headscale.service'
DENY_POLICY = {'acls': [], 'ssh': []}


def service_unit():
    return '''[Unit]
Description=Appliance Headscale authority
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/headscale --config=/var/lib/rdc-guest/headscale/config.json serve
Restart=on-failure
RestartSec=5
UMask=0077
RuntimeDirectory=rdc-headscale
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
ReadWritePaths=/var/lib/rdc-guest/headscale /run/rdc-headscale
[Install]
WantedBy=multi-user.target
'''


def _inspect(request, state, runner):
    result = inspect_role(request, state, runner, role='headscale', service=SERVICE, identity_file='noise.key')
    if result['configured']:
        directory = Path(state) / 'headscale'
        require(digest_file(directory / 'policy.json') == record(state, 'headscale')['policy_id'],
                'role-policy-changed')
        result.update(config_id=digest_file(directory / 'config.json'),
                      policy_id=digest_file(directory / 'policy.json'))
    return result


def _cli(directory):
    return ['/usr/bin/headscale', '--config=' + str(directory / 'config.json')]


def preflight(request, state, runner):
    """Reject known input errors before the helper journals mutation intent."""
    if request['action'] == 'enroll':
        parameters = request['parameters']
        fields(parameters, {'owner_approval', 'registration_id', 'user'})
        _approval(parameters)
        require(type(parameters['registration_id']) is str
                and re.fullmatch(r'[A-Za-z0-9_-]{8,256}', parameters['registration_id']), 'registration-id-invalid')
        require(type(parameters['user']) is str
                and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', parameters['user']), 'authority-user-invalid')
        observed = _inspect({**request, 'action': 'inspect', 'parameters': {}}, state, runner)
        require(observed['configured'] and observed['running'], 'authority-not-running')
    elif request['action'] == 'configure':
        if request['parameters'].get('purpose') == 'verification-policy':
            _policy_addresses(request['parameters'])
            observed = _inspect({**request, 'action': 'inspect', 'parameters': {}}, state, runner)
            require(observed['configured'] and observed['running'], 'authority-not-running')
            return
        plan, credentials = inputs(request, 'headscale')
        settings = plan['roles']['headscale']
        previous = record(state, 'headscale')
        if previous:
            require(previous['authority'] == settings['authority'] and previous['hostname'] == settings['hostname'],
                    'authority-change-forbidden')
            require(previous.get('phase') == 'configured', 'role-setup-needs-inspection')
            require(digest_file(Path(state) / 'headscale/noise.key') == previous['identity'], 'role-identity-changed')
        tls = validate_tls(settings['hostname'], credentials)
        if previous and previous['tls']['certificate_sha256'] != tls['certificate_sha256']:
            require(credentials.get('replace_certificate') is True, 'certificate-replacement-approval')
        check_version(runner, '/usr/bin/headscale', ['version'], VERSION)


def configure(request, state, runner):
    plan, credentials = inputs(request, 'headscale')
    settings = plan['roles']['headscale']
    previous = record(state, 'headscale')
    if previous:
        require(previous['authority'] == settings['authority']
                and previous['hostname'] == settings['hostname'], 'authority-change-forbidden')
        require(previous.get('phase') == 'configured', 'role-setup-needs-inspection')
        require(digest_file(Path(state) / 'headscale/noise.key') == previous['identity'], 'role-identity-changed')
    tls = validate_tls(settings['hostname'], credentials)
    if previous and previous['tls']['certificate_sha256'] != tls['certificate_sha256']:
        require(credentials.get('replace_certificate') is True, 'certificate-replacement-approval')
    check_version(runner, '/usr/bin/headscale', ['version'], VERSION)
    directory = Path(state) / 'headscale'
    current = dict(previous) if previous else {'schema': 1, 'role': 'headscale', 'phase': 'initializing',
            'plan_id': request['plan_id'], 'authority': settings['authority'],
            'hostname': settings['hostname'], 'version': VERSION}
    # Persist authority intent before configtest can create its key/database.
    if previous is None:
        save(state, 'headscale', current)
        require(files.read_optional(Path('/'), directory / 'noise.key') is None
                and files.read_optional(Path('/'), directory / 'db.sqlite') is None,
                'unowned-authority-state')
        private_write(directory / 'policy.json', canonical(DENY_POLICY))
    material = install_tls(directory, settings['hostname'], credentials, tls)
    config = headscale_config(plan, root=str(directory))
    config.update(tls_cert_path=material['certificate'], tls_key_path=material['key'])
    candidate = directory / 'candidate.json'
    private_write(candidate, canonical(config))
    runner.run(['/usr/bin/headscale', '--config=' + str(candidate), 'configtest'], timeout_s=60)
    actual_identity = digest_file(directory / 'noise.key')
    if previous:
        require(actual_identity == previous['identity'], 'role-identity-changed')
    private_write(directory / 'config.json', canonical(config))
    current.update(plan_id=request['plan_id'], identity=actual_identity, phase='configuring',
                   tls=tls, tls_files=material, config_id=identity(config),
                   policy_id=digest_file(directory / 'policy.json'))
    save(state, 'headscale', current)
    runner.run(['/usr/bin/systemctl', 'enable', SERVICE], timeout_s=30)
    runner.run(['/usr/bin/systemctl', 'restart', SERVICE], timeout_s=60)
    runner.run(['/usr/bin/systemctl', 'is-active', '--quiet', SERVICE], timeout_s=15)
    require(digest_file(directory / 'noise.key') == actual_identity, 'role-identity-changed')
    current['phase'] = 'configured'
    save(state, 'headscale', current)
    return _inspect(request, state, runner)


def _approval(parameters):
    require(type(parameters['owner_approval']) is str
            and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}', parameters['owner_approval']), 'owner-approval-required')


def approve(request, state, runner):
    parameters = request['parameters']
    fields(parameters, {'owner_approval', 'registration_id', 'user'})
    _approval(parameters)
    require(type(parameters['registration_id']) is str
            and re.fullmatch(r'[A-Za-z0-9_-]{8,256}', parameters['registration_id']), 'registration-id-invalid')
    require(type(parameters['user']) is str
            and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', parameters['user']), 'authority-user-invalid')
    observed = _inspect(request, state, runner)
    require(observed['configured'] and observed['running'], 'authority-not-running')
    command = _cli(Path(state) / 'headscale')
    # Query first; a lost mutation response is never automatically replayed by
    # the fixed helper journal. Registration IDs are public approval handles.
    output = runner.run([*command, '--output=json', 'users', 'list', '--name', parameters['user']], timeout_s=30).stdout
    try:
        users = json.loads(output)
    except (ValueError, UnicodeError):
        require(False, 'authority-users-response')
    require(type(users) is list and len(users) <= 1, 'authority-users-response')
    if not users:
        runner.run([*command, 'users', 'create', parameters['user']], timeout_s=30)
    else:
        require(users[0].get('name') == parameters['user'], 'authority-users-response')
    runner.run([*command, 'auth', 'register', '--user', parameters['user'],
                '--auth-id', parameters['registration_id']], timeout_s=30)
    return {'role': 'headscale', 'plan_id': request['plan_id'], 'identity': observed['identity'],
            'approved': True, 'approval_id': identity(parameters), 'ordinary_client_ready': False}


def _policy_addresses(parameters):
    fields(parameters, {'purpose', 'owner_approval', 'source_ipv4', 'allowed_peer_ipv4', 'denied_peer_ipv4'})
    require(parameters['purpose'] == 'verification-policy', 'authority-policy-purpose')
    _approval(parameters)
    addresses = []
    for key in ('source_ipv4', 'allowed_peer_ipv4', 'denied_peer_ipv4'):
        try:
            address = ipaddress.IPv4Address(parameters[key])
        except (ValueError, TypeError):
            require(False, 'verification-peer-address')
        require(address in ipaddress.IPv4Network('100.64.0.0/10'), 'verification-peer-address')
        addresses.append(str(address))
    require(len(set(addresses)) == 3, 'verification-peer-address')
    return addresses


def verification_policy(request, state, runner):
    parameters = request['parameters']
    addresses = _policy_addresses(parameters)
    observed = _inspect(request, state, runner)
    require(observed['configured'] and observed['running'], 'authority-not-running')
    source, allowed, denied = addresses
    policy = {'acls': [{'action': 'accept', 'src': [source], 'dst': [allowed + ':443']}],
              'ssh': [], 'tests': [{'src': source, 'accept': [allowed + ':443'], 'deny': [denied + ':443']}]}
    directory = Path(state) / 'headscale'
    candidate = directory / 'policy-candidate.json'
    private_write(candidate, canonical(policy))
    runner.run([*_cli(directory), 'policy', 'check', '--file', str(candidate)], timeout_s=30)
    private_write(directory / 'policy.json', canonical(policy))
    runner.run(['/usr/bin/systemctl', 'kill', '--kill-whom=main', '--signal=HUP', SERVICE], timeout_s=15)
    # Headscale's file-policy reload is asynchronous. Config alone never claims
    # an active allow/deny result; the independent test remains required.
    current = record(state, 'headscale')
    current['policy_id'] = identity(policy)
    current['policy_approval_id'] = identity(parameters)
    save(state, 'headscale', current)
    return {**_inspect(request, state, runner), 'policy_verified': False}


def handle(request, state, runner):
    action = request['action']
    if action in ('inspect', 'verify'):
        fields(request['parameters'], set(), {'reconnect'} if action == 'verify' else set())
        require(type(request['parameters'].get('reconnect', False)) is bool, 'role-reconnect')
        return _inspect(request, state, runner)
    if action == 'enroll':
        return approve(request, state, runner)
    require(action == 'configure', 'guest-action-forbidden')
    if request['parameters'].get('purpose') == 'verification-policy':
        return verification_policy(request, state, runner)
    return configure(request, state, runner)

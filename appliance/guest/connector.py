"""Fixed Tailscale connector operations; credentials never enter command arguments."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import ssl
from urllib.parse import urlsplit

from .. import files, state as private
from ..contracts import ApplianceError, identity, require
from ..connector import controller_url, validate_authorization

TAILSCALE = '/usr/bin/tailscale'


def verify_controller(url, fingerprint, address=None):
    """Use public trust and hostname verification, then owner-approved leaf pin."""
    host = urlsplit(controller_url(url)).hostname
    try:
        with socket.create_connection((address or host, 443), timeout=10) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as conn:
                require(hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest() == fingerprint,
                        'controller-tls-identity')
    except (OSError, ssl.SSLError):
        raise ApplianceError('controller-tls-identity') from None


def _json(runner, argv):
    raw = runner.run(argv, timeout_s=30).stdout
    require(type(raw) is bytes and len(raw) <= 512 * 1024, 'connector-response-bound')
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ApplianceError('connector-response-invalid') from None
    return result


def _observe(runner, config):
    status = _json(runner, [TAILSCALE, 'status', '--json'])
    prefs = _json(runner, [TAILSCALE, 'debug', 'prefs'])
    require(type(status) is dict and type(prefs) is dict, 'connector-response-invalid')
    require(prefs.get('ControlURL') == config['controller'] and
            all(prefs.get(k) is False for k in ('RouteAll', 'CorpDNS', 'RunSSH')) and
            prefs.get('AdvertiseRoutes') in (None, []) and prefs.get('AdvertiseTags') in (None, []) and
            prefs.get('ExitNodeID') == '' and prefs.get('ExitNodeIP') in ('', None),
            'connector-policy-drift')
    forwarding = runner.run(['/usr/sbin/sysctl', '-n', 'net.ipv4.ip_forward'], timeout_s=10).stdout
    require(forwarding.strip() == b'0', 'connector-forwarding-enabled')
    routes = _json(runner, ['/usr/sbin/ip', '-j', 'route', 'show', 'table', '52'])
    require(type(routes) is list, 'connector-routes-invalid')
    for route in routes:
        require(type(route) is dict, 'connector-routes-invalid')
        try:
            prefix = ipaddress.ip_network(route.get('dst', ''), strict=False)
        except ValueError:
            raise ApplianceError('connector-subnet-route-present') from None
        require(prefix.prefixlen == prefix.max_prefixlen, 'connector-subnet-route-present')
    node_id = status.get('Self', {}).get('ID') if type(status.get('Self')) is dict else None
    require(type(node_id) is str and 1 <= len(node_id) <= 128 and
            all(c.isalnum() or c in ':-_.' for c in node_id), 'connector-identity-unavailable')
    return {'registered': status.get('BackendState') == 'Running', 'node_id': node_id,
            'identity_preserved': True, 'policy_matches': True, 'ip_forward': False,
            'advertise_routes': [], 'accept_routes': False, 'accept_dns': False,
            'tailscale_ssh': False, 'advertise_exit_node': False,
            'config_id': identity(config), 'policy_id': identity({k: v for k, v in config.items() if k != 'controller_address'})}


def _reply(request, observed):
    return {'operation_id': request['operation_id'], 'phase': 'complete',
            'code': 'connector-inspected', 'observations': observed}


def handle(request, state, runner):
    require(request.get('role') == 'connector' and request.get('action') in
            ('configure', 'enroll', 'inspect', 'verify'), 'unsupported-guest-action')
    parameters = request.get('parameters', {})
    config = parameters.get('config')
    require(type(config) is dict and set(config) - {'controller_address'} == {'controller', 'advertise_routes',
            'advertise_exit_node', 'accept_routes', 'exit_node', 'tailscale_ssh', 'accept_dns', 'ip_forward'},
            'connector-config-invalid')
    require(controller_url(config['controller']) == config['controller'] and
            config['advertise_routes'] == [] and config['exit_node'] == '' and
            all(config[k] is False for k in ('advertise_exit_node', 'accept_routes', 'tailscale_ssh',
                                          'accept_dns', 'ip_forward')), 'connector-config-invalid')
    if config.get('controller_address') is not None:
        try:
            require(str(ipaddress.IPv4Address(config['controller_address'])) == config['controller_address'], 'connector-controller-address')
        except ValueError:
            raise ApplianceError('connector-controller-address') from None
    directory = Path(state) / 'connector'
    with private.lock(directory):
        identity_path, attempt_path = directory / 'identity.json', directory / 'attempt.json'
        saved = private.read(identity_path) if identity_path.exists() or identity_path.is_symlink() else None
        attempt = private.read(attempt_path) if attempt_path.exists() or attempt_path.is_symlink() else None
        previous = saved or attempt
        credential_path = directory / 'enrollment-credential'
        if attempt and (credential_path.exists() or credential_path.is_symlink()):
            files.delete_owned(Path('/'), credential_path, expected_sha256=attempt['credential_sha256'])
        if previous:
            require(previous['controller'] == config['controller'], 'connector-authority-change-refused')
        if request['action'] == 'configure':
            private.write(directory / 'config.json', config)
            return _reply(request, {'configured': True, 'registered': False})
        if previous is None:
            require(request['action'] == 'enroll', 'connector-not-enrolled')
            authorization = parameters.get('authorization')
            validate_authorization(config, authorization)
            verify_controller(config['controller'], authorization['tls_sha256'], config.get('controller_address'))
            credential = authorization['credential'].encode()
            private.write(attempt_path, {'schema': 1, 'controller': config['controller'],
                          'operation_id': request['operation_id'], 'phase': 'pending',
                          'credential_sha256': hashlib.sha256(credential).hexdigest()})
            private.write(directory / 'config.json', config)
            files.atomic_write(Path('/'), credential_path, credential, mode=0o600)
            try:
                if config.get('controller_address'):
                    host = urlsplit(config['controller']).hostname
                    hosts = ('127.0.0.1 localhost\n' + config['controller_address'] + ' ' + host + '\n').encode()
                    files.atomic_write(Path('/'), directory / 'hosts', hosts, mode=0o600)
                    dropin = '[Service]\nBindReadOnlyPaths=' + str(directory / 'hosts') + ':/etc/hosts\n'
                    files.atomic_write(Path('/'), Path('/etc/systemd/system/tailscaled.service.d/rdc-connector.conf'), dropin.encode())
                    runner.run(['/usr/bin/systemctl', 'daemon-reload'], timeout_s=30)
                runner.run(['/usr/bin/systemctl', 'start', 'tailscaled.service'], timeout_s=30)
                runner.run([TAILSCALE, 'up', '--login-server=' + config['controller'],
                    '--auth-key=file:' + str(credential_path), '--hostname=' + authorization['node_name'],
                    '--accept-routes=false', '--accept-dns=false', '--advertise-routes=',
                    '--advertise-exit-node=false', '--exit-node=', '--ssh=false', '--advertise-tags=',
                    '--timeout=60s'], timeout_s=75)
            finally:
                files.delete_owned(Path('/'), credential_path,
                                   expected_sha256=hashlib.sha256(credential).hexdigest())
        elif request['action'] in ('enroll', 'inspect'):
            runner.run(['/usr/bin/systemctl', 'start', 'tailscaled.service'], timeout_s=30)
        observed = _observe(runner, config)
        if saved:
            require(saved['node_id'] == observed['node_id'], 'connector-identity-changed')
        else:
            private.write(identity_path, {'schema': 1, 'controller': config['controller'],
                          'node_id': observed['node_id']})
        if attempt and (Path(state) / 'operations' / (attempt['operation_id'] + '.json')).exists():
            original = private.read(Path(state) / 'operations' / (attempt['operation_id'] + '.json'))
            if original.get('reply', {}).get('phase') == 'pending' and observed['registered']:
                from .helper import reconcile_enrollment
                reconcile_enrollment(attempt['operation_id'], state, observed)
        return _reply(request, observed)

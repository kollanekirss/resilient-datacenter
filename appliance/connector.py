"""Deliberate network-owner-approved enrollment, separate from hosted roles."""
from __future__ import annotations

from pathlib import Path
import re
import ipaddress
import secrets
import time
from urllib.parse import urlsplit

from .contracts import ApplianceError, canonical, identity, require
from . import state as private


def controller_url(value):
    require(type(value) is str and len(value) <= 253, 'controller-url-invalid')
    try:
        parsed = urlsplit(value)
        require(parsed.scheme == 'https' and parsed.hostname is not None and
                parsed.port in (None, 443) and parsed.username is None and parsed.password is None and
                parsed.path in ('', '/') and not parsed.query and not parsed.fragment and
                re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', parsed.hostname) is not None and
                '.' in parsed.hostname and value == value.lower(), 'controller-url-invalid')
    except ValueError:
        raise ApplianceError('controller-url-invalid') from None
    return value.rstrip('/')


def connector_config(plan):
    settings = plan.get('roles', {}).get('connector', {})
    require(settings.get('selected') is True, 'connector-not-selected')
    result = {'controller': controller_url(settings.get('controller')),
            'advertise_routes': [], 'advertise_exit_node': False,
            'accept_routes': False, 'exit_node': '', 'tailscale_ssh': False,
            'accept_dns': False, 'ip_forward': False}
    hosted = plan.get('roles', {}).get('headscale', {})
    if hosted.get('selected') is True and result['controller'] == 'https://' + str(hosted.get('hostname', '')):
        nics = plan.get('vms', {}).get('headscale', {}).get('nics', [])
        require(len(nics) == 1 and nics[0].get('zone') == 'infrastructure', 'connector-controller-address')
        try:
            result['controller_address'] = str(ipaddress.IPv4Address(nics[0]['address']))
        except (ValueError, KeyError):
            raise ApplianceError('connector-controller-address') from None
    return result


def validate_authorization(config, authorization, *, now=None):
    now = int(time.time()) if now is None else now
    require(type(authorization) is dict, 'enrollment-authorization-required')
    require(authorization.get('approved') is True and
            type(authorization.get('owner_reference')) is str and
            re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}', authorization['owner_reference']) is not None,
            'network-owner-approval-required')
    require(controller_url(authorization.get('controller')) == config['controller'],
            'controller-approval-mismatch')
    require(type(authorization.get('tls_sha256')) is str and
            re.fullmatch('[0-9a-f]{64}', authorization['tls_sha256']) is not None,
            'controller-tls-identity-required')
    require(type(authorization.get('expires_at')) is int and
            now < authorization['expires_at'] <= now + 3600, 'enrollment-authorization-expired')
    require(authorization.get('one_use') is True, 'single-use-authorization-required')
    require(type(authorization.get('node_name')) is str and
            re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', authorization['node_name']) is not None,
            'connector-node-name-invalid')
    require(type(authorization.get('credential')) is str and
            1 <= len(authorization['credential']) <= 4096 and
            not any(c.isspace() or ord(c) < 32 for c in authorization['credential']),
            'enrollment-credential-invalid')


def _evidence(plan, reply):
    observed = reply.get('observations', {})
    return {'schema': 1, 'capability': 'enrollment', 'role': 'connector',
            'state': 'configured' if reply.get('phase') == 'complete' and observed.get('registered') is True else 'unknown',
            'checked_at': int(time.time()), 'plan_id': identity(plan),
            'operation_id': reply['operation_id'], 'observations': observed,
            'next_action': 'Run independent peer, denial and selected-relay probes; local enrollment alone is not verification.'}


def join(plan, authorization, runner, state):
    """Record redacted intent before dispatch; subsequent calls only inspect it."""
    config = connector_config(plan)
    validate_authorization(config, authorization)
    from .guests import guest_call
    directory = Path(state) / 'connector'
    with private.lock(directory):
        path = directory / 'enrollment.json'
        if path.exists() or path.is_symlink():
            record = private.read(path)
            require(record['controller'] == config['controller'], 'connector-authority-change-refused')
            from .guests import query_guest_operation
            query_guest_operation(plan['vms']['connector']['vmid'], {
                'schema': 1, 'operation_id': record['operation_id'], 'plan_id': identity(plan),
                'role': 'connector', 'action': 'inspect', 'parameters': {}}, runner, state=state)
            return inspect(plan, runner, state)
        operation_id = identity({'plan_id': identity(plan), 'role': 'connector',
                                 'controller': config['controller'], 'action': 'enroll'})
        private.write(path, {'schema': 1, 'controller': config['controller'],
                            'operation_id': operation_id, 'phase': 'pending'})
        request = {'schema': 1, 'operation_id': operation_id, 'plan_id': identity(plan),
                   'role': 'connector', 'action': 'enroll',
                   'parameters': {'config': config, 'authorization': authorization}}
        reply = guest_call(plan['vms']['connector']['vmid'], request, runner, state=state)
        result = _evidence(plan, reply)
        private.write(path, {'schema': 1, 'controller': config['controller'],
                            'operation_id': operation_id, 'phase': reply['phase']})
        return result


def inspect(plan, runner, state, *, operation_id=None, reconnect=False):
    """Resume tailscaled with persisted identity; never supply another credential."""
    from .guests import guest_call
    config = connector_config(plan)
    request = {'schema': 1, 'operation_id': operation_id or secrets.token_hex(32),
               'plan_id': identity(plan), 'role': 'connector', 'action': 'inspect' if reconnect else 'verify',
               'parameters': {'config': config}}
    return _evidence(plan, guest_call(plan['vms']['connector']['vmid'], request, runner, state=state))

"""Deliberate creation of one persistent Headscale authority."""
from pathlib import Path
import secrets

from .contracts import identity, require
from .hosting import eligibility, prerequisites

VERSION = '0.29.4'
ROOT = '/var/lib/rdc-guest/headscale'


def headscale_config(plan, *, root=ROOT):
    settings = plan['roles']['headscale']
    address = plan['vms']['headscale']['nics'][0]['address']
    return {'server_url': 'https://' + settings['hostname'], 'listen_addr': address + ':443',
            'metrics_listen_addr': '127.0.0.1:9090', 'grpc_listen_addr': '127.0.0.1:50443',
            'grpc_allow_insecure': False, 'trusted_proxies': [],
            'noise': {'private_key_path': root + '/noise.key'},
            'prefixes': {'v4': plan['overlay_cidrs'][0], 'v6': '', 'allocation': 'sequential'},
            'derp': {'server': {'enabled': False},
                     'urls': ['https://controlplane.tailscale.com/derpmap/default'],
                     'paths': [], 'auto_update_enabled': True, 'update_frequency': '3h'},
            'database': {'type': 'sqlite', 'sqlite': {'path': root + '/db.sqlite', 'write_ahead_log': True}},
            'policy': {'mode': 'file', 'path': root + '/policy.json'},
            'tls_letsencrypt_hostname': '', 'tls_cert_path': root + '/tls.crt',
            'tls_key_path': root + '/tls.key', 'disable_check_updates': True,
            'unix_socket': '/run/rdc-headscale/headscale.sock', 'unix_socket_permission': '0600',
            'dns': {'magic_dns': False, 'base_domain': '', 'override_local_dns': False,
                    'nameservers': {'global': [], 'split': {}}, 'search_domains': [], 'extra_records': []},
            'logtail': {'enabled': False}, 'taildrop': {'enabled': False},
            'log': {'level': 'warn', 'format': 'json'}}


def create_authority(plan, credentials, runner, state):
    settings = plan['roles']['headscale']
    require(type(credentials) is dict and credentials.get('authority') == settings.get('authority')
            and bool(settings.get('authority')), 'authority-approval-required')
    problems = prerequisites(plan, 'headscale')
    require(not problems, problems[0] if problems else 'hosting-prerequisites')
    from .guests import guest_call
    request = {'schema': 1, 'operation_id': secrets.token_hex(16), 'plan_id': identity(plan),
               'role': 'headscale', 'action': 'configure',
               'parameters': {'plan': plan, 'credentials': credentials}}
    reply = guest_call(plan['vms']['headscale']['vmid'], request, runner, state=Path(state))
    result = eligibility(plan, {'guest': reply.get('observations', {})}, 'headscale')
    result.update(operation_id=request['operation_id'], phase=reply.get('phase', 'pending'))
    return result


def _call(plan, parameters, action, runner, state):
    from .guests import guest_call
    request = {'schema': 1, 'operation_id': secrets.token_hex(16), 'plan_id': identity(plan),
               'role': 'headscale', 'action': action, 'parameters': parameters}
    reply = guest_call(plan['vms']['headscale']['vmid'], request, runner, state=Path(state))
    require(reply.get('phase') == 'complete', reply.get('code', 'role-inspection-pending'))
    return reply['observations']


def inspect(plan, runner, state, *, reconnect=False):
    return _call(plan, {'reconnect': True} if reconnect else {}, 'verify' if reconnect else 'inspect', runner, state)


def approve_client(plan, authorization, runner, state):
    return _call(plan, authorization, 'enroll', runner, state)


def set_verification_policy(plan, authorization, runner, state):
    return _call(plan, {**authorization, 'purpose': 'verification-policy'}, 'configure', runner, state)

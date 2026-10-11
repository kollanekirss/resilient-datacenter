"""Source-preserving standalone relay profile with closed client admission."""
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from .contracts import identity, require
from .hosting import eligibility, prerequisites

VERSION = '1.104.1'
ROOT = '/var/lib/rdc-guest/derp'


def derp_config(plan):
    settings = plan['roles']['derp']
    controller = urlsplit(settings['controller_url']).hostname
    headscale = plan['roles']['headscale']
    colocated = headscale['selected'] and controller == headscale.get('hostname')
    return {'region_id': settings['region_id'], 'hostname': settings['hostname'],
            'listen_address': settings['public_ipv4'],
            'verify_client_url': settings['controller_url'].rstrip('/') + '/verify',
            'verify_client_url_fail_open': False,
            'verifier_host_binding': {'hostname': controller,
                'address': plan['vms']['headscale']['nics'][0]['address']} if colocated else None,
            'published': False, 'inbound_translation': False, 'outbound_translation': False}


def relay_policy(plan):
    config = derp_config(plan)
    return {'public_ipv4': plan['roles']['derp']['public_ipv4'],
            'prefix': plan['roles']['derp']['routed_prefix'],
            'inbound_translation': False, 'outbound_translation': False,
            'preserve_client_source': True,
            'services': [{'protocol': 'tcp', 'port': 443}, {'protocol': 'tcp', 'port': 80},
                         {'protocol': 'udp', 'port': 3478}],
            'verifier_host_binding': config['verifier_host_binding']}


def configure_relay(plan, credentials, runner, state):
    problems = prerequisites(plan, 'derp')
    require(not problems, problems[0] if problems else 'hosting-prerequisites')
    from .guests import guest_call
    request = {'schema': 1, 'operation_id': secrets.token_hex(16), 'plan_id': identity(plan),
               'role': 'derp', 'action': 'configure',
               'parameters': {'plan': plan, 'credentials': credentials}}
    reply = guest_call(plan['vms']['derp']['vmid'], request, runner, state=Path(state))
    result = eligibility(plan, {'guest': reply.get('observations', {})}, 'derp')
    result.update(operation_id=request['operation_id'], phase=reply.get('phase', 'pending'))
    return result


def inspect(plan, runner, state, *, reconnect=False):
    from .guests import guest_call
    request = {'schema': 1, 'operation_id': secrets.token_hex(16), 'plan_id': identity(plan),
               'role': 'derp', 'action': 'verify' if reconnect else 'inspect',
               'parameters': {'reconnect': True} if reconnect else {}}
    reply = guest_call(plan['vms']['derp']['vmid'], request, runner, state=Path(state))
    require(reply.get('phase') == 'complete', reply.get('code', 'role-inspection-pending'))
    return reply['observations']

"""Independent hosting prerequisites and interpretation of trusted observations.

This pure evaluator does not authenticate input files. External evidence must
come from probes.verify_probe, and local state from the private guest helper.
No evaluator writes role state or automatically changes an installed identity.
"""
from __future__ import annotations

import ipaddress
import re
import time
from urllib.parse import urlsplit

from .contracts import ApplianceError, identity, require

HOSTING_ROLES = ('headscale', 'derp')
CAPABILITIES = {'headscale': 'controller', 'derp': 'relay'}


def hostname(value):
    require(type(value) is str and len(value) <= 253 and value == value.lower()
            and '.' in value and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                                    for p in value.split('.')), 'hosting-hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ApplianceError('hosting-hostname')


def public_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ApplianceError('public-ipv4-required') from None
    require(address.is_global and not address.is_multicast and not address.is_reserved,
            'public-ipv4-required')
    return str(address)


def endpoint_owners(plan):
    owners = {}
    endpoints = []
    for role in HOSTING_ROLES:
        settings = plan['roles'][role]
        if settings['selected']:
            for protocol, port in ([('tcp', 443)] if role == 'headscale'
                                   else [('tcp', 443), ('tcp', 80), ('udp', 3478)]):
                endpoints.append((settings.get('public_ipv4'), protocol, port, role))
    for entry in plan.get('publications', []):
        endpoints.append((entry['public_ipv4'], entry['protocol'], entry['port'], entry['owner']))
    for address, protocol, port, owner in endpoints:
        key = (address, protocol, port)
        require(key not in owners, 'public-endpoint-conflict')
        owners[key] = owner
    return owners


def prerequisites(plan, role):
    require(role in HOSTING_ROLES, 'hosting-role')
    settings = plan['roles'][role]
    if not settings['selected']:
        return ['role-not-selected']
    reasons = []
    for check in (lambda: public_ipv4(settings.get('public_ipv4')),
                  lambda: hostname(settings.get('hostname')), lambda: endpoint_owners(plan)):
        try:
            check()
        except ApplianceError as error:
            reasons.append(error.code)
    if not settings.get('certificate_ref'):
        reasons.append('hosting-certificate-required')
    nics = plan.get('vms', {}).get(role, {}).get('nics', [])
    zone = 'infrastructure' if role == 'headscale' else 'relay'
    if len(nics) != 1 or nics[0].get('zone') != zone:
        reasons.append('hosting-guest-zone')
    if role == 'headscale':
        if not settings.get('authority'):
            reasons.append('authority-name-required')
        exposure = settings.get('exposure', 'direct')
        if exposure == 'upstream-dnat':
            if not settings.get('upstream_owner'):
                reasons.append('headscale-upstream-owner-required')
        elif exposure == 'direct':
            upstream = plan['upstream']
            address = upstream.get('address', '').split('/')[0]
            if upstream.get('mode') != 'static' or address != settings.get('public_ipv4'):
                reasons.append('headscale-direct-wan-mismatch')
        else:
            reasons.append('headscale-exposure')
    else:
        network = plan['networks'].get('relay', {})
        if (network.get('cidr') != settings.get('routed_prefix')
                or not network.get('cidr') or not settings.get('upstream_owner')):
            reasons.append('derp-routed-allocation-required')
        if network.get('gateway') != settings.get('gateway') or not settings.get('gateway'):
            reasons.append('derp-router-gateway-mismatch')
        if len(nics) != 1 or nics[0].get('address') != settings.get('public_ipv4'):
            reasons.append('derp-public-address-on-guest-required')
        try:
            prefix = ipaddress.IPv4Network(settings.get('routed_prefix'))
            address = ipaddress.IPv4Address(settings.get('public_ipv4'))
            gateway = ipaddress.IPv4Address(settings.get('gateway'))
            require(prefix.is_global and address in prefix and gateway in prefix
                    and address != gateway and address not in (prefix.network_address, prefix.broadcast_address)
                    and gateway not in (prefix.network_address, prefix.broadcast_address), 'derp-routed-allocation-required')
        except (ValueError, TypeError, ApplianceError):
            reasons.append('derp-routed-allocation-required')
        try:
            parsed = urlsplit(settings.get('controller_url', ''))
            require(parsed.scheme == 'https' and parsed.path in ('', '/') and not parsed.query
                    and not parsed.fragment and not parsed.username and not parsed.password
                    and parsed.port in (None, 443), 'derp-controller-url')
            hostname(parsed.hostname)
        except (ApplianceError, ValueError):
            reasons.append('derp-controller-url')
    return sorted(set(reasons))


def eligibility(plan, observations, role):
    """Separate planned prerequisites, actual guest setup and external proof."""
    require(role in HOSTING_ROLES and type(observations) is dict, 'hosting-observations')
    now = int(time.time())
    plan_id = identity(plan)
    reasons = prerequisites(plan, role)
    local = observations.get('guest', {})
    configured = (type(local) is dict and local.get('plan_id') == plan_id
                  and local.get('role') == role and local.get('configured') is True
                  and local.get('running') is True and local.get('tls', {}).get('valid') is True
                  and type(local.get('checked_at')) is int and 0 <= now - local['checked_at'] <= 60
                  and type(local.get('identity')) is str
                  and re.fullmatch('[0-9a-f]{64}', local['identity']) is not None)
    proof = observations.get('probe_evidence', {})
    external = (type(proof) is dict and proof.get('schema') == 1
                and proof.get('capability') == CAPABILITIES[role]
                and proof.get('state') == 'verified' and proof.get('plan_id') == plan_id
                and type(proof.get('checked_at')) is int
                and 0 <= now - proof['checked_at'] <= 900
                and bool(proof.get('probe_id')) and bool(proof.get('build_id'))
                and proof.get('dependencies', {}).get('plan') == plan_id)
    if external:
        from .probes import REQUIREMENTS
        external = all(proof.get('observations', {}).get(key) is True for key in REQUIREMENTS[CAPABILITIES[role]])
        bindings = {'role_identity': local.get('identity'), 'config': local.get('config_id'),
                    'policy': local.get('policy_id'), 'certificate': local.get('certificate_id')}
        external = external and all(type(value) is str and bool(value)
                    and proof.get('dependencies', {}).get(key) == value for key, value in bindings.items())
        settings = plan['roles'][role]
        targets = proof.get('targets', [])
        public_targets = [target for target in targets if type(target) is dict and target.get('expect') == 'public-tls']
        external = external and len(public_targets) == 1
        if external:
            target = public_targets[0]
            parsed = urlsplit(target.get('url', ''))
            external = (parsed.scheme == 'https' and parsed.hostname == settings['hostname']
                        and parsed.port in (None, 443) and target.get('expected_ipv4') == settings['public_ipv4']
                        and target.get('tls_sha256') == local.get('certificate_id'))
        if role == 'derp':
            external = external and proof.get('observations', {}).get('selected_region') == settings['region_id']
    if not plan['roles'][role]['selected']:
        state = 'not-selected'
    elif reasons:
        state = 'blocked'
    elif configured and external:
        state = 'verified'
    else:
        state = 'unknown'
    if plan['roles'][role]['selected'] and not reasons:
        if not configured:
            reasons.append('guest-configuration-unverified')
        if not external:
            reasons.append('independent-probe-required')
    return {'schema': 1, 'capability': CAPABILITIES[role], 'role': role, 'plan_id': plan_id,
            'state': state, 'prerequisites': not prerequisites(plan, role),
            'configured': configured, 'verified': state == 'verified', 'checked_at': now,
            'reasons': reasons, 'next_action': ('Repeat independent tests after dependency changes.'
                if state == 'verified' else 'Resolve: ' + ', '.join(reasons))}

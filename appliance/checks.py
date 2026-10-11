"""Pure, conservative evidence evaluation and public attachment metadata.

These functions evaluate collector records; they do not authenticate a supplied
JSON file or substitute for running the probes. Mutation gates collect their
own observations. Release evaluation is a prerequisite, not a publisher.
"""
from __future__ import annotations

import re
import time

from .contracts import identity, require

REQUIREMENTS = {
    'management': ('numeric_access', 'ingress_policy', 'independent_of_router'),
    'router': ('installed_root', 'disk_only_boot', 'config_matches', 'private_admin', 'no_physical_dhcp', 'ipv6_disabled'),
    'upstream': ('address_valid', 'route_present', 'no_overlap'),
    'dns': ('server_listener', 'query_answer'),
    'time': ('ntp_listener', 'ntp_response'),
    'https': ('listener_control', 'certificate_valid', 'request_succeeded'),
    'isolation': ('source_control', 'destination_control', 'denied_probe'),
    'enrollment': ('registered', 'identity_preserved', 'peer_control', 'peer_reachable'),
    'controller': ('public_tls', 'fresh_registration', 'policy_probe'),
    'relay': ('public_tls', 'stun_response', 'forced_relay', 'registration_control'),
}
DEPENDENCIES = {'host_boot', 'router_boot', 'config', 'policy', 'endpoint', 'role_identity'}
BASE_CASES = {'offline-install', 'erase-refusals', 'port-mapping', 'wan-exposure',
              'routed-policy', 'router-down-management', 'no-wan-boot', 'wan-return',
              'interrupted-resume', 'export-repair', 'physical-operator'}
ROLE_REQUIREMENTS = {
    'join-nat': ('owner-approved', 'controller-tls', 'no-inbound-mapping', 'identity-preserved',
                 'routes-disabled', 'authorized-https', 'denied-live-peer', 'local-management-independent'),
    'relay-path': ('direct-path-blocked', 'selected-region-used', 'relayed-https', 'fault-cleaned'),
    'controller-hosting': ('direct-public', 'owned-upstream-dnat', 'public-dns-tls', 'fresh-enrollment',
                           'allow-deny-policy', 'same-authority-restart', 'certificate-replacement'),
    'standalone-relay-hosting': ('routed-public-guest', 'no-nat', 'inbound-source-preserved',
                               'outbound-source-preserved', 'stun', 'selected-relay-flow',
                               'unknown-client-denied', 'verifier-outage-denied'),
    'both-hosting-roles': ('distinct-public-endpoints', 'local-verifier-flow', 'no-management-flow',
                         'independent-eligibility'),
    'role-identity-restart': ('host-restart', 'router-restart', 'guest-restart', 'wan-return',
                             'same-identities', 'no-reenrollment'),
    'private-role-export': ('consistent-state', 'restart-after-failure', 'independent-decryption',
                            'no-plaintext-published', 'restored-identities-inactive'),
    'full-operator': ('physical-usb-journey', 'independent-operator', 'join', 'both-hosting-roles',
                     'export-and-router-repair', 'resource-budgets-measured'),
}
ROLE_CASES = frozenset(ROLE_REQUIREMENTS)


def _identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) is not None


def evaluate(capability, observations, plan, build_id, *, now):
    require(capability in REQUIREMENTS, 'unknown-capability')
    require(type(observations) is dict and _identifier(build_id)
            and type(now) is int and now >= 0, 'evidence-input')
    dependencies = {'plan': identity(plan), 'build': build_id}
    raw = observations.get('dependencies', {})
    if type(raw) is dict:
        dependencies.update({key: value for key, value in raw.items()
                             if key in DEPENDENCIES and _identifier(value)})
    observed = {key: observations.get(key) is True for key in REQUIREMENTS[capability]}
    missing = [key for key, passed in observed.items() if not passed]
    # At least one live runtime identity is required, in addition to config pins.
    if not any(key in dependencies for key in ('host_boot', 'router_boot', 'role_identity')):
        missing.append('runtime-identity')
    state = 'blocked' if missing else 'verified'
    if observations.get('clock_trusted') is not True:
        state = 'unknown'
        missing.insert(0, 'trusted-clock')
    return {'schema': 1, 'capability': capability, 'state': state, 'checked_at': now,
            'plan_id': dependencies['plan'], 'build_id': build_id,
            'dependencies': dependencies, 'observations': observed,
            'next_action': 'Collect: ' + ', '.join(missing) if missing else 'Repeat after any dependency changes.'}


def current(evidence, dependency_ids, *, now, max_age_s=300):
    if (type(evidence) is not dict or type(dependency_ids) is not dict
            or type(now) is not int or type(max_age_s) is not int or max_age_s < 0
            or type(evidence.get('checked_at')) is not int):
        return False
    age = now - evidence['checked_at']
    return (evidence.get('schema') == 1 and evidence.get('dependencies') == dependency_ids
            and 0 <= age <= max_age_s and evidence.get('state') == 'verified'
            and dependency_ids.get('plan') == evidence.get('plan_id')
            and dependency_ids.get('build') == evidence.get('build_id'))


def attachment(plan):
    zones = {}
    for zone in ('infrastructure', 'workload', 'relay'):
        settings = plan.get('networks', {}).get(zone)
        if type(settings) is not dict:
            continue
        zones[zone] = {key: settings[key] for key in ('bridge', 'cidr', 'gateway', 'allocation') if key in settings}
        zones[zone].update(dns=settings.get('gateway'), time=settings.get('gateway'),
                           trust_zone=zone, access='Declared router policy; runtime verification required.')
    return {'schema': 1, 'site_id': plan['site_id'], 'plan_id': identity(plan),
            'zones': zones, 'enforcement': 'not-assessed', 'plugin_execution': False}


def base_release_allowed(results, *, physical, now=None):
    """All case assertions and evidence bytes must agree with one fresh run.

    Acceptance receipts have a 24-hour review window; five-minute capability
    freshness is deliberately not reused for a multi-hour destructive suite.
    This is an integrity prerequisite, not authenticity or release publication.
    """
    now = int(time.time()) if now is None else now
    if type(results) is not list or not results or type(physical) is not bool:
        return False
    if any(type(item) is not dict for item in results):
        return False
    required = BASE_CASES if physical else BASE_CASES - {'physical-operator'}
    names = [item.get('capability') for item in results]
    if any(type(name) is not str for name in names) or len(set(names)) != len(names) or set(names) != required:
        return False
    builds, plans, contexts = set(), set(), set()
    for item in results:
        build, plan = item.get('build_id'), item.get('plan_id')
        if not all(type(v) is str and re.fullmatch(r'[0-9a-f]{64}', v) for v in (build, plan)):
            return False
        if (item.get('test_only') is not False or item.get('source') != 'acceptance-runner'
                or item.get('method') != 'real-execution'
                or item.get('environment') not in ({'physical'} if physical else {'nested', 'physical'})
                or item.get('case_id') != item.get('capability')):
            return False
        from .acceptance import required_assertions
        from .acceptance_report import case_problems
        if case_problems(item, required_assertions(item['case_id']), now=now):
            return False
        builds.add(build)
        plans.add(plan)
        dependencies = item['dependencies']
        contexts.add(tuple(dependencies[key] for key in ('run', 'spec', 'source')))
    return len(builds) == len(plans) == len(contexts) == 1


def v1_release_allowed(base, roles, qualification, *, now=None):
    """Whole-product integrity prerequisite, never an authenticity/publish action.

    Software fixtures, a base-only run, or a site choosing not to host cannot
    qualify the supported hosting profiles as a product release.
    """
    from .acceptance_report import case_problems, _digest
    now = int(time.time()) if now is None else now
    if not base_release_allowed(base, physical=True, now=now): return False
    if (type(roles) is not list or len(roles) != len(ROLE_CASES) or
            any(type(item) is not dict or type(item.get('case_id')) is not str for item in roles) or
            {item['case_id'] for item in roles} != ROLE_CASES or type(qualification) is not dict):
        return False
    q = qualification
    if (q.get('schema') != 1 or q.get('test_only') is not False or not _identifier(q.get('physical_profile'))
            or not all(_digest(q.get(key)) for key in ('build_id', 'source_id', 'spec_id', 'lock_id'))):
        return False
    for item in base:
        if (item['build_id'] != q['build_id'] or item['dependencies']['source'] != q['source_id']
                or item['dependencies']['spec'] != q['spec_id']): return False
    endpoint = q.get('independent_endpoint')
    if (type(endpoint) is not dict or not all(_identifier(endpoint.get(key)) for key in
            ('id', 'host_id', 'admin_id', 'appliance_host_id', 'appliance_admin_id')) or
            not _digest(endpoint.get('key_sha256')) or
            endpoint['host_id'] == endpoint['appliance_host_id'] or
            endpoint['admin_id'] == endpoint['appliance_admin_id']): return False
    resources = q.get('resources')
    if type(resources) is not dict or set(resources) != {'host', 'router', 'probe', 'connector', 'headscale', 'derp'}:
        return False
    for budget in resources.values():
        if (type(budget) is not dict or budget.get('measured') is not True or
                any(type(budget.get(key)) is not int or budget[key] <= 0 for key in ('memory_mib', 'disk_bytes'))):
            return False
    for item in roles:
        if case_problems(item, ROLE_REQUIREMENTS[item['case_id']], now=now): return False
        deps = item['dependencies']
        if (any(deps.get(key) != q[key + '_id'] for key in ('build', 'source', 'spec', 'lock')) or
                deps.get('probe') != identity(endpoint)):
            return False
        if item['case_id'] == 'full-operator' and item.get('environment') != 'physical': return False
    return True

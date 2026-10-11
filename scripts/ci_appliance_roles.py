#!/usr/bin/env python3
"""Read-only role qualification preflight, or explicit independent measurements.

A measurement receipt is not a whole-product acceptance result. Unimplemented
wire-session/fault scenarios and machine-dependent cases remain NOT RUN.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appliance.contracts import ApplianceError, canonical, identity, load_json, require
from appliance.role_acceptance import preflight, run_role_probe
from appliance.runner import Runner
from appliance import state
from appliance.checks import ROLE_REQUIREMENTS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=('join', 'headscale', 'derp', 'all'), default='all')
    parser.add_argument('--lab-config', type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    args = parser.parse_args(argv)
    report = preflight(args.suite)
    for case in report['cases']:
        case['required_assertions'] = list(ROLE_REQUIREMENTS[case['case_id']])
    if args.execute:
        report['scope'] = 'independent-measurements'
        report['reasons'].remove('execution-not-requested')
        try:
            require(args.lab_config is not None, 'role-lab-config-required')
            config = load_json(args.lab_config)
            require(set(config) == {'schema', 'request', 'private_key', 'receipt_output', 'profile'} and
                    config['schema'] == 1, 'role-lab-config-invalid')
            request = load_json(Path(config['request']), limit=512 * 1024)
            selected = {'join': 'enrollment', 'headscale': 'controller', 'derp': 'relay'}
            require(args.suite == 'all' or request['capability'] == selected[args.suite], 'role-lab-suite-mismatch')
            receipt = run_role_probe(request, Path(config['private_key']), Runner(max_output_bytes=512 * 1024), config['profile'])
            state.write(Path(config['receipt_output']), receipt)
            report['receipt_id'] = identity(receipt)
            report['measurements'] = receipt['observations']
            report['reasons'].append('complete-role-acceptance-still-required')
        except (ApplianceError, KeyError, TypeError, OSError) as error:
            report['reasons'].append(error.code if isinstance(error, ApplianceError) else 'role-lab-config-invalid')
    if args.format == 'json':
        print(json.dumps(report, sort_keys=True))
    else:
        print('Network-role qualification: NOT RUN')
        for case in report['cases']:
            print(case['case_id'] + ': NOT RUN')
        print('Pending: ' + ', '.join(report['reasons']))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate a profile without connecting to servers; optionally emit safe metadata."""
import argparse
import json
from profile_config import load_profile, validate_profile, normalize_profile, expected_ownership

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('inventory')
    p.add_argument('--mode', choices=['independent','join','any'], default='any')
    p.add_argument('--structure-only', action='store_true')
    p.add_argument('--json', action='store_true')
    args=p.parse_args()
    try:
        data=load_profile(args.inventory)
        errors=validate_profile(data,check_files=not args.structure_only)
        if not errors:
            normalized=normalize_profile(data)
            if args.mode!='any' and normalized['mode']!=args.mode:
                errors=['Inventory mode does not match this deployment entry point']
        if errors:
            for error in errors: print('ERROR: '+error)
            return 1
        normalized['ownership']={n:expected_ownership(normalized,n) for n in normalized['roles']}
        print(json.dumps(normalized) if args.json else 'Profile validation passed'+(' (structure only)' if args.structure_only else ''))
        return 0
    except Exception:
        print('ERROR: Cannot validate profile; check input and local dependencies. Values omitted.')
        return 1

if __name__=='__main__': raise SystemExit(main())

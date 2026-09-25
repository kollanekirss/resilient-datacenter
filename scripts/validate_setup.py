#!/usr/bin/env python3
"""Validate setup inputs without connecting to targets."""
import argparse
import json
from profile_config import load_profile
from setup_contracts import validate_infrastructure, normalize_infrastructure, validate_local_manifest, local_ownership

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('file'); p.add_argument('--kind',choices=['infrastructure','local-node'],required=True); p.add_argument('--structure-only',action='store_true'); p.add_argument('--json',action='store_true'); a=p.parse_args()
    try:
        data=load_profile(a.file)
        errors=validate_infrastructure(data,check_files=not a.structure_only) if a.kind=='infrastructure' else validate_local_manifest(data)
        if errors:
            for e in errors: print('ERROR: '+e)
            return 1
        normalized=normalize_infrastructure(data) if a.kind=='infrastructure' else {'manifest':data,'ownership':local_ownership(data)}
        print(json.dumps(normalized) if a.json else 'Setup validation passed'+(' (structure only)' if a.structure_only else ''))
        return 0
    except Exception:
        print('ERROR: Cannot validate setup input; check file, dependencies and documented schema. Values omitted.')
        return 1
if __name__=='__main__': raise SystemExit(main())

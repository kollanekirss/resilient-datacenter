#!/usr/bin/python3
"""Fixed isolated entry point for the installed gateway runtime."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from gateway_runtime import main

if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise ValueError('Select one supported gateway runtime action')
        raise SystemExit(main(sys.argv[1]))
    except Exception as error:
        print('Gateway action failed ('+type(error).__name__+'). Review its local journal, pending transition, network identity and owned files; access must remain closed until repaired.',file=sys.stderr)
        raise SystemExit(1)

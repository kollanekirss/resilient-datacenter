#!/usr/bin/python3
"""Frozen root-managed service certificate renewal entry point."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from service_issuer import renew

if __name__=='__main__':
    try:renew()
    except Exception:
        print('Private-service certificate renewal failed. Inspect certificate status, provider access and the local issuer log. Existing application data was retained.')
        raise SystemExit(1)

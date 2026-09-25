#!/usr/bin/python3
"""Entry point copied into the private root-managed backup runtime."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from backup_schedule import run_scheduled
if __name__=='__main__':
    try: raise SystemExit(run_scheduled())
    except Exception:
        print('Scheduled backup prerequisites failed. Run backup status from the reviewed project and inspect the local administration files.')
        raise SystemExit(1)

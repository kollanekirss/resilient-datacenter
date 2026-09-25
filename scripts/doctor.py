"""Dependency-aware diagnostics. No installs, enrollment or privilege prompts."""
import json
from pathlib import Path
import subprocess
import sys
from local_checks import inspect_local_checks
from operation_results import Check, check, OUTCOMES
from setup_contracts import validate_local_manifest

PROBE_CODES=frozenset({'dns.resolve','tcp.connect','tls.verify','tls.expiry','probe.unavailable'})


def diagnose(manifest: dict, *, probe_runner=None) -> tuple[Check,...]:
    if validate_local_manifest(manifest):
        return (check('manifest.invalid','fail'),)
    try:
        local=inspect_local_checks(manifest,check_tls=False)
    except (OSError,ValueError,subprocess.SubprocessError):
        local=[check('client.inspect_denied','unknown')]
    results=[check(c.code,'not-applicable') if c.code=='platform.unsupported' else c for c in local]
    runner=probe_runner or subprocess.run
    try:
        output=runner([sys.executable,str(Path(__file__).with_name('diagnostic_probe.py')),
                       '--hostname',manifest['headscale_hostname']],
                      capture_output=True,text=True,timeout=15,check=True)
        if len(output.stdout)>8192: raise ValueError('invalid worker output')
        entries=json.loads(output.stdout)
        if not isinstance(entries,list) or not 1<=len(entries)<=5: raise ValueError('invalid worker output')
        for entry in entries:
            if (not isinstance(entry,dict) or set(entry)!={'code','outcome'} or
                not isinstance(entry['code'],str) or entry['code'] not in PROBE_CODES or
                not isinstance(entry['outcome'],str) or entry['outcome'] not in OUTCOMES):
                raise ValueError('invalid worker output')
        results.extend(check(e['code'],e['outcome']) for e in entries)
    except subprocess.TimeoutExpired:
        results.append(check('probe.timeout','unknown'))
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        results.append(check('probe.unavailable','unknown'))
    return tuple(results)

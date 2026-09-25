#!/usr/bin/env python3
"""Read-only local machine checks. Never installs, starts or resets a service."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from profile_config import load_profile
from setup_contracts import validate_local_manifest, local_ownership
from profile_state import inspect_peer
from operation_results import Check, check, message

MARKER=Path('/etc/server-connectivity-profile.json')
STATE=Path('/var/lib/tailscale')
RESERVED=['/etc/server-connectivity.managed','/etc/headscale','/var/lib/headscale','/etc/sc-derp','/var/lib/sc-derp','/var/lib/tailscale','/usr/bin/tailscale','/usr/local/bin/tailscale','/etc/systemd/system/tailscaled.service','/etc/sc-test']


def platform_errors(system: str, machine: str, os_release: dict, systemd: bool) -> list[str]:
    if system!='Linux' or machine!='x86_64' or os_release.get('ID')!='ubuntu' or os_release.get('VERSION_ID')!='24.04' or not systemd:
        return ['Local apply requires Ubuntu 24.04 amd64 with systemd. This computer can prepare configurations only.']
    return []


def ownership_errors(expected, actual, existing, persistent, daemon_active):
    if actual is None and (existing or persistent): return ['Existing unowned installation: migration requires review; no state was changed.']
    if actual is not None and actual!=expected: return ['Ownership/controller/node differs; migration requires review.']
    if persistent and not daemon_active: return ['Persistent node state exists but tailscaled is unavailable. Inspect/start the existing daemon through local administration, then rerun.']
    return []


def tls_errors(hostname, *, connect_address=None, context=None):
    try:
        with socket.create_connection(connect_address or (hostname,443),timeout=5) as raw:
            with (context or ssl.create_default_context()).wrap_socket(raw,server_hostname=hostname): pass
        return []
    except (OSError,ssl.SSLError):
        return ['Controller TLS/DNS connection failed. Check DNS, connectivity, certificate trust/hostname and the local clock; TLS verification was not bypassed.']


def inspect_local_checks(manifest, *, require_owned=False, check_tls=True) -> list[Check]:
    if validate_local_manifest(manifest): return [check('manifest.invalid','fail')]
    try:
        release=platform.freedesktop_os_release() if platform.system()=='Linux' else {}
    except OSError:
        return [check('platform.unsupported','fail')]
    if platform_errors(platform.system(),platform.machine(),release,Path('/run/systemd/system').is_dir()):
        return [check('platform.unsupported','fail')]
    if os.geteuid()!=0 and shutil.which('sudo') is None:
        return [check('tooling.sudo_missing','fail')]
    expected=local_ownership(manifest); actual=None
    if MARKER.is_symlink(): return [check('ownership.invalid','fail')]
    if MARKER.exists():
        try:
            stat=MARKER.stat()
            if stat.st_uid!=0 or stat.st_mode & 0o022:
                return [check('ownership.invalid','fail')]
            actual=json.loads(MARKER.read_text())
        except (OSError,ValueError): return [check('ownership.invalid','fail')]
    try:
        daemon=subprocess.run(['/bin/systemctl','is-active','tailscaled'],capture_output=True,text=True,timeout=10).returncode==0
    except (OSError,subprocess.SubprocessError):
        return [check('client.inspect_denied','unknown')]
    persistent=STATE.exists()
    if actual is None and (persistent or any(Path(p).exists() for p in RESERVED)):
        return [check('ownership.unowned','fail')]
    if actual is not None and actual!=expected: return [check('ownership.mismatch','fail')]
    if persistent and not daemon: return [check('client.unavailable','fail')]
    if require_owned and actual is None: return [check('ownership.missing','fail')]
    results=[check('platform.supported','pass'),check('ownership.valid','pass')]
    if daemon:
        try:
            def read(args):
                result=subprocess.run(['/usr/local/bin/tailscale',*args],capture_output=True,text=True,timeout=10,check=True)
                return json.loads(result.stdout)
            inspect_peer(read(['status','--json']),read(['debug','prefs']),manifest['headscale_hostname'],manifest['node_tag'])
        except (OSError,ValueError,TypeError,AttributeError,subprocess.SubprocessError):
            return [*results,check('client.inspect_denied','unknown')]
        results.append(check('client.verified','pass'))
    else:
        results.append(check('client.not_installed','not-applicable'))
    if check_tls:
        failed=bool(tls_errors(manifest['headscale_hostname']))
        results.append(check('controller.connection_failed' if failed else 'controller.verified','fail' if failed else 'pass'))
    return results


def check_local(manifest, *, require_owned=False, check_tls=True):
    return [message(c) for c in inspect_local_checks(manifest,require_owned=require_owned,check_tls=check_tls)
            if c.outcome in ('fail','unknown')]


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('manifest'); p.add_argument('--json',action='store_true'); a=p.parse_args()
    try:
        manifest=load_profile(a.manifest); errors=check_local(manifest)
        if errors:
            for e in errors: print('ERROR: '+e)
            return 1
        result={'manifest':manifest,'ownership':local_ownership(manifest),'checked_at_utc':datetime.now(timezone.utc).isoformat()}
        print(json.dumps(result) if a.json else 'Local read-only checks passed. Clock synchronization has not been independently verified.')
        return 0
    except Exception:
        print('ERROR: Cannot inspect this machine safely; check prerequisites and permissions. Private values omitted.')
        return 1
if __name__=='__main__': raise SystemExit(main())

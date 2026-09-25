"""Explicit, bounded enrollment. Temporary registration URLs are never returned in reports."""
import json
import os
import subprocess
import sys
from urllib.parse import urlsplit
from setup_contracts import validate_local_manifest
from profile_state import inspect_peer


def _inspect(manifest,runtime):
    status=runtime.read_status()
    result=inspect_peer(status,runtime.read_preferences(),manifest['headscale_hostname'],manifest['node_tag'])
    if result['status']=='enrolled' and status.get('Self',{}).get('HostName')!=manifest['node_name']:
        raise ValueError('Existing client hostname differs; inspect identity before proceeding')
    return status,result


def _display_pending(manifest,runtime,status):
    url=status.get('AuthURL')
    if not url: return False
    try:
        parsed=urlsplit(url)
        port=parsed.port
    except ValueError:
        raise ValueError('Malformed registration URL; verify through local administration') from None
    if parsed.scheme!='https' or parsed.hostname!=manifest['headscale_hostname'] or port not in (None,443) or parsed.username or parsed.password or len(url)>4096 or any(ord(c)<32 or ord(c)==127 for c in url):
        raise ValueError('Unexpected registration URL; verify it through local administration')
    runtime.display_registration_url(url)
    return True


def enrollment_action(manifest: dict, runtime, *, start_requested: bool) -> dict:
    if validate_local_manifest(manifest): raise ValueError('Invalid local manifest')
    status,result=_inspect(manifest,runtime)
    if result['status']=='enrolled' or not start_requested: return result
    if result['status']=='client_not_running': return result
    if _display_pending(manifest,runtime,status): return result
    if status.get('BackendState')=='NeedsMachineAuth': return result
    argv=['/usr/local/bin/tailscale','up','--login-server=https://'+manifest['headscale_hostname'],'--hostname='+manifest['node_name'],'--advertise-tags='+manifest['node_tag'],'--accept-dns=false','--accept-routes=false','--ssh=false','--timeout=20s']
    try:
        code=runtime.start_registration(argv)
    except KeyboardInterrupt:
        runtime.cancel_registration()
        return {'status':'cancelled','enrollment':'not-verified','state_preserved':True}
    status,result=_inspect(manifest,runtime)
    if result['status']!='enrolled':
        displayed=_display_pending(manifest,runtime,status)
        if code not in (None,0) and not displayed and status.get('BackendState')!='NeedsMachineAuth':
            raise ValueError('Registration did not complete or produce a pending approval. Inspect controller connectivity and local client state; do not reset identity.')
    return result


class NativeRuntime:
    def __init__(self): self.process=None
    def _prefix(self): return [] if os.geteuid()==0 else ['sudo','--']
    def _read(self,args):
        result=subprocess.run(self._prefix()+['/usr/local/bin/tailscale',*args],capture_output=True,text=True,check=True,timeout=15)
        return json.loads(result.stdout)
    def read_status(self): return self._read(['status','--json'])
    def read_preferences(self): return self._read(['debug','prefs'])
    def display_registration_url(self,url):
        if not sys.stdout.isatty(): raise ValueError('Registration display requires an interactive terminal; use status for noninteractive checks.')
        print('Pending registration (temporary; do not save in logs or public tickets):\n'+url)
        print('Verify the node with the controller administrator, obtain approval, then run local_node.py status or enroll again.')
    def start_registration(self,argv):
        if not all(stream.isatty() for stream in (sys.stdin,sys.stdout,sys.stderr)):
            raise ValueError('Enrollment requires an interactive terminal; do not redirect temporary registration information to logs.')
        # Inherit the terminal solely for the explicit user-requested registration display.
        print('Requesting enrollment. The controller administrator must approve it; this step waits up to 20 seconds.')
        self.process=subprocess.Popen(self._prefix()+argv)
        try: return self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.cancel_registration(); return 124
    def cancel_registration(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=5)

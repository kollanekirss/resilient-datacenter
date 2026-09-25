"""Separate, bounded, read-only operational evidence; no overall resilience badge."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile

DIMENSIONS=('network','applications','certificates','backup','recovery','partners')
COMMON={'unknown','blocked','not-configured','not-applicable','change-pending','restore-pending'}
STATES={
    'network':COMMON|{'enrolled','enrolled-controller-unreachable','awaiting-enrollment','stopped','service-running'},
    'applications':COMMON|{'service-listeners-verified','stopped'},
    'certificates':COMMON|{'certificate-valid','certificate-expiring','certificate-invalid','renewal-failed'},
    'backup':COMMON|{'backup-current','backup-overdue','backup-unreachable','backup-failed','backup-scope-missing','no-backup'},
    'recovery':COMMON|{'untested','service-verified','verified-on-prior-components','different-scope'},
    'partners':COMMON|{'partners-disabled','partners-suspended','transport-verified-exchange-untested','partner-review-required'},
}
NEXT={
    'network':'Inspect node status or doctor with its saved manifest. If access is denied, use your existing local administration permissions.',
    'applications':'Inspect chat or file service status on its own VM, then test login and an actual message or file operation.',
    'certificates':'Inspect the role-specific certificate or issuer status; renew with the reviewed issuer or replace with trusted current material.',
    'backup':'Inspect backup status and storage access. Take a new consistent snapshot if needed and verify independent recovery access.',
    'recovery':'Complete any pending restore first, then perform a fenced recovery exercise and test a real user operation.',
    'partners':'Review gateway or connector status, current bilateral approvals and a real partner exchange. Do not bypass a recovery review.',
}
TIMES={'expires_at','captured_at','completed_at','last_success_at'}
BOOLEANS={'controller_reachable','automatic_renewal','serving_verified'}
COUNTS={'backup_age_seconds','approved_peers'}


def sanitize(name,value):
    if not isinstance(value,dict) or value.get('state') not in STATES[name]:value={'state':'unknown'}
    result={'state':value['state'],'next_step':NEXT[name]}
    for key in BOOLEANS:
        if type(value.get(key)) is bool:result[key]=value[key]
    for key in COUNTS:
        if type(value.get(key)) is int and 0<=value[key]<2**53:result[key]=value[key]
    for key in TIMES:
        try:
            if isinstance(value.get(key),str) and len(value[key])<64 and datetime.fromisoformat(value[key]).tzinfo is not None:result[key]=value[key]
        except ValueError:pass
    if value.get('last_attempt') in ('failed','succeeded'):result['last_attempt']=value['last_attempt']
    if name in ('applications','recovery'):result['user_operation']='not-recorded'
    if name=='partners':result['federation_test']='not-recorded'
    return result


def supported():
    try:return platform.system()=='Linux' and platform.machine()=='x86_64' and 'ID=ubuntu' in Path('/etc/os-release').read_text() and 'VERSION_ID="24.04"' in Path('/etc/os-release').read_text()
    except OSError:return False


def run_probe(name):
    if name not in DIMENSIONS:raise ValueError('Unknown status dimension')
    command=[sys.executable,'-I','-B',str(Path(__file__).with_name('status_probe.py')),name]
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            process.wait(timeout=30)
            output.seek(0);raw=output.read(65537)
            if process.returncode or len(raw)>65536:raise ValueError('Status worker did not return bounded evidence')
            return json.loads(raw)
        finally:
            # Kill lingering descendants as well as a timed-out worker. No
            # background status probe may outlive this read-only request.
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5)


def collect(*,probe=None):
    runner=probe or (run_probe if supported() else lambda _:{'state':'unknown'})
    def one(name):
        try:return sanitize(name,runner(name))
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return sanitize(name,{'state':'unknown'})
    with ThreadPoolExecutor(max_workers=len(DIMENSIONS)) as pool:values=list(pool.map(one,DIMENSIONS))
    return {'checked_at':datetime.now(timezone.utc).isoformat(),'dimensions':dict(zip(DIMENSIONS,values)),
            'scope':'Read-only local evidence. Permissions, missing configuration or unavailable probes remain unknown; this is not an overall resilience certification.'}


def needs_attention(result):
    informational={'enrolled','service-running','service-listeners-verified','certificate-valid','backup-current','service-verified',
                   'not-applicable','partners-disabled','transport-verified-exchange-untested'}
    return any(item['state'] not in informational for item in result['dimensions'].values())


def render(result):
    lines=['Current evidence on this computer:']
    for name,item in result['dimensions'].items():
        lines.append(name.capitalize()+': '+item['state'].replace('-',' '))
        for key in ('backup_age_seconds','expires_at','completed_at','last_success_at','last_attempt','automatic_renewal','serving_verified','approved_peers','user_operation','federation_test'):
            if key in item:lines.append('  '+key.replace('_',' ')+': '+str(item[key]))
        lines.append('  Next: '+item['next_step'])
    return '\n'.join(lines)

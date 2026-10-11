"""Source-pinned disposable guest protocol, invoked only through a local TTY.

This is an acceptance harness, not an installed daemon or appliance API. Every
request must match a fresh QEMU SMBIOS UUID and the lab-only product marker.
It invokes the same installer, network, router, export and repair entry points
as the operator journey; it never substitutes result dictionaries for them.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import selectors
import signal
import subprocess
import sys
import time
import termios
from contextlib import contextmanager

from .contracts import ApplianceError, canonical, identity, require
from .runner import Runner
from . import state

PRIVATE=Path('/var/lib/rdc-appliance/private')
WORK=Path('/run/rdc-acceptance')
VARIANTS={'normal','duplicate-identity','changed-capacity','hot-remove','spanning-storage',
          'non-target-pve','cancel','invalid-media','boot-media-target'}
KINDS={
 'prepare':{'live','installed','routed'},
 'observe':{'disks','host','router','status','startup','interfaces','journal','clone'},
 'fault':{'erase-refusal','nic-order','replace-nic','wrong-cable','management-break','router-stop','wan-remove',
          'wan-overlap-first','wan-overlap-renew','interrupt','corrupt-management','corrupt-export','wrong-export-password'},
 'probe':{'management','wan-admin','zone-admin','cross-zone','dns','ntp','https','forwarding-state','physical-dhcp-ra','host-wan-addresses'},
 'reboot':{'host','router'},
 'recover':{'install','router-start','wan-return','explicit-transit','management-rollback','resume','export',
            'open-export','usb-management','isolated-clone','network-apply','network-confirm','router-setup','probe-setup'},
}


def validate_action(action,parameters):
    require(action in KINDS and type(parameters) is dict,'lab-action')
    key='profile' if action=='prepare' else 'target' if action=='reboot' else 'kind'
    require(parameters.get(key) in KINDS[action],'lab-action-kind')
    if 'variant' in parameters:require(parameters['variant'] in VARIANTS,'lab-variant')


def verify_guest(machine,*,root=Path('/')):
    try:
        require(re.fullmatch('[0-9a-f-]{36}',machine) is not None,'lab-machine-identity')
        require((root/'sys/class/dmi/id/product_uuid').read_text().strip().lower()==machine
                and (root/'sys/class/dmi/id/product_name').read_text().strip()=='RDC Disposable Acceptance',
                'lab-disposable-guest-required')
    except OSError:raise ApplianceError('lab-disposable-guest-required') from None


def _run(argv,*,stdin=b'',timeout=120,check=True):
    if check:
        result=Runner(max_output_bytes=2*1024*1024).run(argv,stdin=stdin,timeout_s=timeout)
        return {'argv':argv,'returncode':result.returncode,'stdout':result.stdout.decode(errors='replace'),
                'stderr':result.stderr.decode(errors='replace')}
    require(type(stdin) is bytes and len(stdin)<=65536 and Path(argv[0]).is_absolute(),'lab-command')
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        start_new_session=True,close_fds=True,shell=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/root'})
    output={'stdout':bytearray(),'stderr':bytearray()};deadline=time.monotonic()+timeout
    try:
        process.stdin.write(stdin);process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream,name in ((process.stdout,'stdout'),(process.stderr,'stderr')):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                require(time.monotonic()<deadline,'lab-command-timeout')
                for key,_ in selector.select(.1):
                    chunk=os.read(key.fd,65536)
                    if not chunk:selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(sum(map(len,output.values()))<=2*1024*1024,'lab-command-output-limit')
        code=process.wait(timeout=max(.1,deadline-time.monotonic()))
        return {'argv':argv,'returncode':code,**{k:bytes(v).decode(errors='replace') for k,v in output.items()}}
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait();process.stdout.close();process.stderr.close()


def _plan():return state.read(PRIVATE/'site.json') if (PRIVATE/'site.json').exists() else state.read(WORK/'plan.json')


def live_mode():return 'rdc.appliance=1' in Path('/proc/cmdline').read_text().split()

def _release():
    from .installer.entry import PAYLOAD
    from .installer.payload import verify_install_payload
    return state.read(PRIVATE.parent/'release.lock.json') if (PRIVATE.parent/'release.lock.json').exists() else verify_install_payload(PAYLOAD)[0]


def dependencies():
    plan=_plan()
    result={'host_boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'config':identity(plan)}
    for key,path in (('policy',PRIVATE/'router/policy.json'),('role_identity',PRIVATE/'roles.json')):
        if path.exists():result[key]=identity(state.read(path))
    if (PRIVATE/'vms'/f"{plan['vms']['router']['vmid']}.json").exists():
        try:
            from .proxmox import observe_vm
            observed=observe_vm(plan['vms']['router']['vmid'],Runner())
            result['router_boot']=observed['boot_id'] or 'stopped'
        except ApplianceError:result['router_boot']='unavailable'
    return result


def initialize(parameters):
    from .plan import validate_site
    plan=validate_site(parameters['plan'],_release())
    require(plan['target']['serial']=='RDC-LAB-TARGET','lab-target-marker')
    require(plan['ports']['management']['permanent_mac']=='52:54:00:77:00:01'
            and plan['ports']['wan']['permanent_mac']=='52:54:00:77:00:02','lab-port-marker')
    WORK.mkdir(mode=0o700,exist_ok=True)
    state.write(WORK/'plan.json',plan)
    # Credentials are created per private run and never included in evidence.
    secret=parameters['credentials']
    require(type(secret) is dict and re.fullmatch(r'\$6\$[^\n\0]{10,300}',secret['password_hash'])
            and secret['ssh_public'].startswith('ssh-ed25519 '),'lab-credentials')
    state.write(WORK/'credentials.json',secret)
    if 'ca_pem' in parameters:
        require(parameters['ca_pem'].startswith('-----BEGIN CERTIFICATE-----'),'lab-ca')
        state.write(WORK/'tls.json',{'ca_pem':parameters['ca_pem']})
    if parameters.get('rename_ports'):
        from .host_network import collect_ports,resolve_ports
        require(live_mode(),'lab-live-rename-only')
        current=resolve_ports(plan,collect_ports(Path('/'),Runner()))
        for role,name in (('management','labportb'),('wan','labporta')):
            _run(['/usr/sbin/ip','link','set','dev',current[role],'down'])
            _run(['/usr/sbin/ip','link','set','dev',current[role],'name',name])
    return {'plan_id':identity(plan),'inventory':inventory()}


def inventory():
    if not live_mode():
        return {'mode':'installed','boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'blockdevices':json.loads(_run(['/usr/bin/lsblk','--json','--bytes','--paths',
                    '--output','PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN'])['stdout'])['blockdevices']}
    from .installer.inventory import inventory as collect
    return collect(Runner(),plan=_plan())


def prepare_variant(variant):
    require(variant in VARIANTS,'lab-variant')
    observed=inventory()
    if observed.get('mode')=='installed':
        require(variant=='normal','lab-installed-disk-variant');return {'variant':variant,'inventory':observed}
    disks=observed['disks']
    targets=[d for d in disks if d['identity']['serial']=='RDC-LAB-TARGET']
    canaries=[d for d in disks if d['identity']['serial']=='RDC-LAB-CANARY']
    if variant in ('non-target-pve','spanning-storage'):
        require(len(targets)==len(canaries)==1,'lab-disk-identity')
        selected=[canaries[0]['path']] if variant=='non-target-pve' else [targets[0]['path'],canaries[0]['path']]
        for path in selected:_run(['/usr/sbin/pvcreate','--yes',path])
        _run(['/usr/sbin/vgcreate','pve',*selected])
        _run(['/usr/sbin/lvcreate','-L','64M','-n','root','pve'])
        _run(['/usr/sbin/mkfs.ext4','-F','/dev/pve/root'])
    return {'variant':variant,'inventory':inventory()}


def _acceptance_resource_sample(memory,filesystem):
    try:
        values={line.split(':',1)[0]:int(line.split(':',1)[1].split()[0]) for line in memory.splitlines() if ':' in line}
        used=values['MemTotal']-values['MemAvailable']
        if used<0: return None
        disk=None if filesystem is None else (filesystem[0]-filesystem[1])*filesystem[2]
        return {'at_milliseconds':int(time.monotonic()*1000),'memory_used_mib':(used+1023)//1024,'disk_used_bytes':disk}
    except (KeyError,ValueError,IndexError,TypeError): return None


def install(parameters):
    from .installer.live import install_site
    from .installer.entry import PAYLOAD
    from .installer.inventory import record_port_confirmation
    import threading
    plan=copy.deepcopy(_plan());observed=inventory();variant=parameters.get('variant','normal')
    for role in ('management','wan'):record_port_confirmation(plan,role)
    confirmation=identity(plan)
    if variant=='cancel':confirmation='cancel'
    if variant=='boot-media-target':
        plan['target']['by_id']=observed['boot_media_ids'][0];confirmation=identity(plan)
    payload=PAYLOAD;shadow=False
    if variant=='invalid-media':
        invalid=WORK/'invalid-payload';invalid.mkdir(mode=0o700,exist_ok=True)
        state.write(invalid/'release.lock.json',{**_release(),'schema':0})
        _run(['/usr/bin/mount','--bind',str(invalid),str(PAYLOAD)])
        _run(['/usr/bin/mount','-o','remount,bind,ro',str(PAYLOAD)]);shadow=True
    samples=[];stop=threading.Event()
    def measure():
        while not stop.is_set():
            try:
                fs=None
                # Only count the installed target after it has its own mount.
                if os.path.ismount('/target'):
                    statv=os.statvfs('/target');fs=(statv.f_blocks,statv.f_bfree,statv.f_frsize)
                sample=_acceptance_resource_sample(Path('/proc/meminfo').read_text(),fs)
                if sample is not None: samples.append(sample)
            except OSError: pass
            stop.wait(1)
    captured={};delegate=Runner(max_output_bytes=16*1024*1024)
    class InstallObserver:
        def run(self,argv,*,stdin=b'',timeout_s=30):
            if argv==['/usr/bin/proxmox-chroot','cleanup','--filesystem','ext4']:
                root=Path('/target');marker=root/PRIVATE.relative_to('/')/'staged.json'
                if marker.is_file():
                    staged=state.read(marker)
                    require(staged.get('complete') is True and staged.get('target')==plan['target']
                            and staged.get('plan_id')==identity(plan),'lab-staging-identity')
                    captured['staged']=staged
                    credentials=state.read(WORK/'credentials.json')
                    (root/'root/.ssh').mkdir(mode=0o700,exist_ok=True)
                    (root/'root/.ssh/authorized_keys').write_text(credentials['ssh_public']+'\n')
                    (root/'root/.ssh/authorized_keys').chmod(0o600)
                    durable=root/'var/lib/rdc-appliance/lab';durable.mkdir(mode=0o700,exist_ok=True)
                    state.write(durable/'credentials.json',credentials)
                    if (WORK/'tls.json').exists():state.write(durable/'tls.json',state.read(WORK/'tls.json'))
                    delegate.run(['/usr/bin/systemctl','--root','/target','enable','serial-getty@ttyS0.service'])
            return delegate.run(argv,stdin=stdin,timeout_s=timeout_s)
    worker=threading.Thread(target=measure,daemon=True);worker.start()
    try:
        result=install_site(plan,payload,confirmation,InstallObserver(),
            password_hash=state.read(WORK/'credentials.json')['password_hash'],consent_boot_id=observed['boot_id'])
        require('staged' in captured,'lab-staging-unobserved')
        return {'returncode':0,'result':result,'inventory':observed,'staged':captured['staged'],
                'resource_samples':samples,'sample_interval_seconds':1,
                'planned_vm_allocations':{name:{key:vm[key] for key in ('memory_mib','vcpus','disk_gib')}
                    for name,vm in plan['vms'].items()},'reserved_host_budget':_release()['budgets']['host']}
    except ApplianceError as error:return {'returncode':2,'code':error.code,'inventory':observed}
    finally:
        stop.set();worker.join(timeout=5)
        if shadow:_run(['/usr/bin/umount',str(PAYLOAD)])


def observe(kind,parameters=None):
    parameters=parameters or {}
    plan=_plan();runner=Runner()
    if kind=='host':
        from .host_network import collect_host
        return collect_host(plan,Path('/'),runner)
    if kind=='router':
        from .router import collect_router
        from .proxmox import observe_vm
        vm=observe_vm(plan['vms']['router']['vmid'],runner)
        runtime=collect_router(plan,runner) if vm['running'] else None
        return {'vm':vm,'runtime':runtime,'config_sha256':identity(vm['config']),
                'identity_sha256':identity({'vmid':vm['vmid'],'nics':vm['nics'],
                    'ownership':vm['config'].get('description')})}
    if kind=='status':
        from .operations import installed_status
        return installed_status(plan,state.read(PRIVATE/'staged.json'),runner)
    if kind=='interfaces':
        return {'addresses':json.loads(_run(['/usr/sbin/ip','-json','address','show'])['stdout']),
                'routes':json.loads(_run(['/usr/sbin/ip','-json','route','show','table','all'])['stdout']),
                'links':json.loads(_run(['/usr/sbin/ip','-json','-details','link','show'])['stdout'])}
    if kind=='startup':
        from .host_network import collect_ports
        installed=not live_mode()
        result={'root':_run(['/usr/bin/findmnt','--json','--target','/','--output','SOURCE,FSTYPE,TARGET']),
                'cmdline':Path('/proc/cmdline').read_text().strip(),
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'staged':state.read(PRIVATE/'staged.json') if (PRIVATE/'staged.json').is_file() else None,
                'session':{'euid':os.geteuid(),'tty':os.isatty(0)},
                'interfaces':observe('interfaces'),'ports':collect_ports(Path('/'),runner)}
        if installed:
            result['services']=_run(['/usr/bin/systemctl','show','rdc-first-boot.service','rdc-host-policy.service',
                    'rdc-router-start.service','rdc-menu.service','ssh.service','pveproxy.service',
                    '--property=Id,LoadState,ActiveState,SubState,ExecMainStatus,ActiveEnterTimestampMonotonic'])
            result['journal']=_run(['/usr/bin/journalctl','-b','--no-pager','-o','json','-u','rdc-first-boot.service',
                    '-u','rdc-host-policy.service','-u','rdc-router-start.service'])
            # Harmless actual menu entry/exit through the authenticated serial
            # session; this executes the product menu instead of inspecting text.
            result['menu']=_run(['/usr/local/sbin/rdc-appliance','--json','menu'],stdin=b'q\n')
        if parameters.get('include_host_key'):
            raw=Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
            require(len(raw)>=2 and raw[0]=='ssh-ed25519','lab-host-key')
            result['host_public_key']=' '.join(raw[:2])
        return result
    if kind=='journal':
        if parameters.get('stage'):
            from .lab_faults import observe_operation
            return observe_operation(plan,PRIVATE,parameters['stage'],runner)
        result={}
        for path in sorted(PRIVATE.rglob('*.json')):
            if any(part in ('operations','network','vms','router','probe','recovery') for part in path.relative_to(PRIVATE).parts):
                value=state.read(path)
                result[str(path.relative_to(PRIVATE))]=_redact(value)
        return {'records':result}
    if kind=='clone':
        from .router_recovery import _raw_vm
        return _raw_vm(state.read(PRIVATE/'lab-clone.json')['vmid'],runner)
    if kind=='disks':return {'inventory':inventory(),'lsblk':_run(['/usr/bin/lsblk','--json','--bytes','--paths'])}
    raise ApplianceError('lab-observation-kind')


def _redact(value):
    secret=('password','secret','private_key','config_xml','challenge','known_hosts','host_public_key','export_credential')
    if type(value) is dict:return {k:('[redacted]' if any(w in k for w in secret) else _redact(v)) for k,v in value.items()}
    if type(value) is list:return [_redact(v) for v in value]
    return value


def _credentials():return state.read(PRIVATE.parent/'lab/credentials.json')


def inspect_target_readonly(root,runner):
    from .repair import _resolve_disk
    from .installer.adapters.pve import installed_root,ROOT_DEVICE
    staged=state.read(root/'var/lib/rdc-appliance/private/staged.json')
    require(staged.get('complete') is True,'repair-target-unowned')
    disk=_resolve_disk(staged['target'],runner);recorded=staged['root']
    actual=installed_root(runner,disk)
    require(actual=={**{key:recorded.get(key) for key in ('device','lv_uuid','pv_uuid')},'disk_path':disk},'repair-root-identity')
    mounts=json.loads(runner.run(['/usr/bin/findmnt','--json','--mountpoint',str(root),
        '--output','SOURCE,FSTYPE,OPTIONS,UUID']).stdout).get('filesystems',[])
    require(len(mounts)==1 and mounts[0].get('source')==ROOT_DEVICE and mounts[0].get('fstype')=='ext4'
        and 'ro' in mounts[0].get('options','').split(',')
        and {'noload','norecovery'}&set(mounts[0].get('options','').split(','))
        and mounts[0].get('uuid')==recorded['filesystem_uuid'],'lab-readonly-repair-mount')
    return {'state':'inspected','target':staged['target'],'root':recorded,'mount':mounts[0]}


@contextmanager
def export_credential(parameters):
    raw=parameters.get('export_credential')
    require(type(raw) is str and re.fullmatch(r'[A-Za-z0-9_=-]{40,100}\n',raw),'lab-export-credential')
    directory=PRIVATE.parent/'lab';path=directory/('credential-'+secrets.token_hex(16))
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw.encode())
    try:yield path,hashlib.sha256(raw.encode()).hexdigest()
    finally:path.unlink()


def recover(kind,parameters):
    plan=_plan();runner=Runner()
    if kind=='install':return install(parameters)
    if kind=='network-apply':
        from .rollback import apply_host
        tx=apply_host(plan,Path('/'),runner,now=int(time.monotonic()))
        record=state.read(PRIVATE/'network/pending.json')
        # The challenge is returned only on the private protocol, never written
        # to an action evidence record by the outer driver.
        return {'transaction_id':tx,'challenge':record['challenge']}
    if kind=='network-confirm':
        from .rollback import confirm_management
        confirm_management(parameters['transaction_id'],parameters['challenge'],root=Path('/'),runner=runner,now=int(time.monotonic()))
        return {'state':'confirmed','session_remote':os.environ.get('SSH_CONNECTION','').split()[0]}
    if kind=='router-setup':
        from .lab_router import setup_router
        from . import router
        result=setup_router(plan,_release(),runner,PRIVATE,_credentials())
        attestation=router.attest_console(plan,result['checks'],'CONNECT MANAGEMENT '+str(plan['vms']['router']['vmid']),runner)
        router.enable_router_management(plan,attestation,runner,PRIVATE)
        if parameters.get('bootstrap_only'):return result
        router.enable_wan(plan,None,runner,PRIVATE)
        deadline=time.monotonic()+120
        while True:
            fresh=router.collect_router(plan,runner)
            try:router._upstream(plan,fresh);break
            except ApplianceError:
                require(time.monotonic()<deadline,'lab-upstream-timeout');time.sleep(1)
        router.apply_router_policy(plan,'transit',runner,PRIVATE)
        return result
    if kind=='probe-setup':
        from .lab_probe_guest import setup_probe
        return setup_probe(plan,_release(),runner,PRIVATE,_credentials(),attach=not parameters.get('bootstrap_only',False))
    if kind=='router-start':
        from .startup import start_local
        return {'results':start_local(plan,runner,state=PRIVATE)}
    if kind in ('wan-return','explicit-transit'):
        from .router import apply_router_policy,enable_wan,collect_router
        if kind=='wan-return':
            fresh=collect_router(plan,runner)
            if fresh['stage']=='bootstrap':enable_wan(plan,fresh,runner,PRIVATE)
            return collect_router(plan,runner)
        result=apply_router_policy(plan,'transit',runner,PRIVATE)
        from .lab_probe_guest import attach_probe
        attach_probe(plan,runner,PRIVATE,_credentials())
        return result
    if kind=='management-rollback':
        record=state.read(PRIVATE/'network/pending.json');started=int(time.monotonic())
        # Observe the independently scheduled timer. Do not invoke its recovery
        # function here, which would hide an absent/broken timer service.
        deadline=time.monotonic()+150
        while record['phase']=='pending':
            require(time.monotonic()<deadline,'lab-rollback-timer-timeout');time.sleep(1)
            record=state.read(PRIVATE/'network/pending.json')
        return {'phase':record['phase'],'transaction_id':record['transaction_id'],
                'elapsed_seconds':int(time.monotonic())-started,'timer':_run(['/usr/bin/systemctl','show','rdc-network-rollback.timer','--property=ActiveState,LastTriggerUSecMonotonic'])}
    if kind=='resume':
        from .lab_faults import resume_operation
        return resume_operation(plan,PRIVATE,parameters['stage'],runner)
    if kind=='export':
        from .router import export_router
        from .export import collect_base,seal
        output=PRIVATE.parent/'lab/export';xml=PRIVATE.parent/'lab/router.xml';xml.write_bytes(export_router(plan,runner));xml.chmod(0o600)
        files=collect_base(plan,PRIVATE,xml)
        with export_credential(parameters) as (password,digest):
            result=seal(files,output,password,runner,binary=PRIVATE.parent/'media/restic',release=_release())
        result.update(credential_sha256=digest,guest_credential_removed=not password.exists())
        return result
    if kind=='open-export':
        from .export import inspect_export
        with export_credential(parameters) as (password,digest):
            result=inspect_export(PRIVATE.parent/'lab/export',password,PRIVATE.parent/'lab/opened',runner,
                binary=PRIVATE.parent/'media/restic',release=_release())
        result['component_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (PRIVATE.parent/'lab/opened').iterdir()}
        result.update(credential_sha256=digest,guest_credential_removed=not password.exists())
        return result
    if kind=='usb-management':
        from .repair import discover_target,repair_host
        # The selected original appliance target is the sole mounted root.
        _run(['/usr/sbin/vgchange','-ay','pve'])
        Path('/target').mkdir(exist_ok=True)
        inspect_only=parameters.get('mode')=='inspect-only'
        _run(['/usr/bin/mount','-t','ext4',*(['-o','ro,noload'] if inspect_only else []),'/dev/pve/root','/target'])
        from .repair import _observe_target
        if inspect_only:
            try:return inspect_target_readonly(Path('/target'),runner)
            finally:_run(['/usr/bin/umount','/target'])
        before=_observe_target(Path('/target'),runner)
        target=discover_target(runner)
        target['confirmed']=True
        result=repair_host(target,Path('/target/var/lib/rdc-appliance/lab/opened'),runner)
        after=_observe_target(Path('/target'),runner)
        result.update(target_before={k:before[k] for k in ('target','root')},target_after={k:after[k] for k in ('target','root')})
        _run(['/usr/bin/umount','/target'])
        return result
    if kind=='isolated-clone':
        from .router_recovery import restore_router_isolated
        staged=state.read(PRIVATE/'staged.json');vmid=plan['vms']['router']['vmid']+10000
        state.write(PRIVATE/'lab-clone.json',{'vmid':vmid})
        _run(['/usr/sbin/qm','stop',str(plan['vms']['router']['vmid'])])
        return restore_router_isolated(plan,PRIVATE.parent/'lab/opened',vmid,runner,PRIVATE,
            dvd=PRIVATE.parent/'media/opnsense-dvd',work=PRIVATE.parent/'lab/clone',release=_release(),build=state.read(PRIVATE.parent/'build.json'))
    raise ApplianceError('lab-recovery-kind')


def fault(kind,parameters):
    plan=_plan();runner=Runner()
    if kind=='nic-order':
        directory=Path('/etc/systemd/network');directory.mkdir(exist_ok=True)
        names={}
        for role,name in (('management','labportb'),('wan','labporta')):
            path=directory/('05-rdc-lab-'+role+'.link')
            raw='[Match]\nPermanentMACAddress='+plan['ports'][role]['permanent_mac']+'\n[Link]\nNamePolicy=\nName='+name+'\n'
            require(not path.exists(),'lab-naming-override-exists')
            path.write_text(raw);names[role]={'name':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        return {'overrides':names}
    if kind=='erase-refusal':return install(parameters)
    if kind=='router-stop':return _run(['/usr/sbin/qm','stop',str(plan['vms']['router']['vmid'])])
    if kind in ('management-break','corrupt-management'):
        from .rollback import apply_host
        if kind=='management-break':
            if parameters.get('mode')=='kill':
                from .lab_faults import interrupt_operation
                interrupt_operation(plan,_release(),PRIVATE,'network-after-reload',runner)
                tx=state.read(PRIVATE/'network/pending.json')['transaction_id']
            else:tx=apply_host(plan,Path('/'),runner,now=int(time.monotonic()))
            _run(['/usr/sbin/ip','address','del',plan['networks']['management']['host_ip']+'/'+plan['networks']['management']['cidr'].split('/')[1],
                  'dev',plan['networks']['management']['bridge']])
            return {'transaction_id':tx,'injected':'management-address-removed'}
        Path('/etc/network/interfaces').write_text('auto lo\niface lo inet loopback\n')
        return {'injected':'management-configuration-removed'}
    if kind in ('corrupt-export','wrong-export-password'):
        from .export import inspect_export
        directory=PRIVATE.parent/'lab';suffix=secrets.token_hex(8)
        source=directory/'export';output=directory/('refused-'+suffix)
        if kind=='corrupt-export':
            destination=directory/('corrupt-'+suffix);shutil.copytree(source,destination);source=destination
            files=[p for p in (source/'repository/data').rglob('*') if p.is_file()]
            require(files,'lab-export-missing');path=files[-1];raw=bytearray(path.read_bytes())
            require(raw,'lab-export-empty');raw[-1]^=1;path.chmod(0o600);path.write_bytes(raw)
        credential_parameters=parameters if kind=='corrupt-export' else {'export_credential':secrets.token_urlsafe(40)+'\n'}
        with export_credential(credential_parameters) as (password,_):
            try:
                result=inspect_export(source,password,output,runner,binary=PRIVATE.parent/'media/restic',release=_release())
                return {'returncode':0,'result':result}
            except ApplianceError as error:return {'returncode':2,'code':error.code}
    if kind=='interrupt':
        if parameters['stage']=='firstboot-marker':
            root=Path('/target')
            _run(['/usr/sbin/vgchange','-ay','pve']);root.mkdir(exist_ok=True)
            _run(['/usr/bin/mount','-t','ext4','/dev/pve/root',str(root)])
            marker=root/'var/lib/rdc-appliance/private/staged.json';before=hashlib.sha256(marker.read_bytes()).hexdigest();marker.unlink()
            _run(['/usr/bin/sync']);_run(['/usr/bin/umount',str(root)])
            return {'removed_marker_sha256':before}
        from .lab_faults import interrupt_operation
        return interrupt_operation(plan,_release(),PRIVATE,parameters['stage'],runner)
    raise ApplianceError('lab-driver-side-fault-required')


def execute(action,parameters):
    validate_action(action,parameters)
    if action=='prepare':
        result=initialize(parameters)
        result.update(prepare_variant(parameters.get('variant','normal')))
        return result
    if action=='observe':return observe(parameters['kind'],parameters)
    if action=='recover':return recover(parameters['kind'],parameters)
    if action=='fault':return fault(parameters['kind'],parameters)
    if action=='reboot':
        if parameters['target']=='router':return _run(['/usr/sbin/qm','reboot',str(_plan()['vms']['router']['vmid'])])
        return _run(['/usr/bin/systemctl','reboot'])
    if action=='probe':
        from .lab_probe_guest import guest_probe,forwarding_state
        if parameters['kind']=='forwarding-state':return forwarding_state(_plan(),parameters,Runner(),PRIVATE)
        return guest_probe(_plan(),parameters,Runner(),PRIVATE)
    raise ApplianceError('lab-action')


def serve(*,once=False):
    require(os.geteuid()==0 and os.isatty(0),'lab-console-required')
    configure_protocol_terminal(0)
    last=0;bound=None
    print('RDC-LAB-READY',flush=True)
    while True:
        line=sys.stdin.buffer.readline(2*1024*1024)
        if not line:return
        try:
            require(line.endswith(b'\n') and len(line)<2*1024*1024,'lab-frame-limit')
            request=json.loads(base64.b64decode(line.strip(),validate=True))
            require(request['schema']==1 and type(request['sequence']) is int and request['sequence']>last
                    and re.fullmatch('[0-9a-f]{64}',request['token']),'lab-request')
            verify_guest(request['machine'])
            if bound is not None:require(bound==request['token'],'lab-request-binding')
            bound=request['token'];last=request['sequence']
            data=execute(request['action'],request['parameters'])
            response={'schema':1,'sequence':last,'token':bound,'data':data,'dependencies':dependencies(),'checked_at':int(time.time())}
        except (ApplianceError,OSError,ValueError,KeyError) as error:
            response={'schema':1,'sequence':last,'token':bound,'data':{'returncode':2,'code':error.code if isinstance(error,ApplianceError) else 'lab-guest-io'},
                      'dependencies':{},'checked_at':int(time.time())}
        print('RDC-LAB-RESULT '+base64.b64encode(canonical(response)).decode(),flush=True)
        if once:return


def configure_protocol_terminal(fd):
    # Linux canonical input silently truncates a frame at 4096 bytes. Keep
    # newline framing in Python and let the terminal deliver arbitrary chunks.
    attrs=termios.tcgetattr(fd)
    attrs[3]&=~(termios.ICANON|termios.ECHO)
    attrs[6][termios.VMIN]=1;attrs[6][termios.VTIME]=0
    termios.tcsetattr(fd,termios.TCSANOW,attrs)


if __name__=='__main__':serve(once='--once' in sys.argv[1:])

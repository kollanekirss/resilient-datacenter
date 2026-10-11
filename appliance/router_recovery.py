"""Isolated, non-activating OPNsense configuration recovery into a new VM.

The original router is held stopped under PVE's own config flock while its disk
is copied. A new VM uses a fresh empty bridge and disconnected links from first
allocation. Only the copy receives the exported XML. No installed guest agent, working
router network, or preconfigured serial console is assumed.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import tempfile
import time

from . import proxmox, state
from .contracts import ApplianceError, canonical, identity, integer, require
from .export import COMPONENTS, ROLE_COMPONENTS, _private_bytes
from .media import verify_file
from .plan import validate_release, validate_site
from .router_config import audit_router, parse_xml, zone_interfaces

QM = proxmox.QM
GENISOIMAGE = '/usr/bin/genisoimage'
IP = '/usr/sbin/ip'
PREFIX = b'RDC-RECOVERY '
MAX_TRANSCRIPT = 1024 * 1024


@contextmanager
def source_lock(vmid, directory=Path('/var/lock/qemu-server')):
    """Block PVE start/update while allowing its stopped-volume shared copy lock."""
    integer(vmid, 100, 999999999)
    directory = Path(directory).resolve(strict=True)
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        state._directory_info(os.fstat(dfd), private=False)
        require(os.fstat(dfd).st_uid == os.geteuid(), 'recovery-lock-owner')
        fd = os.open(f'lock-{vmid}.conf', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=dfd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and not info.st_mode & 0o022, 'recovery-lock-unsafe')
        try: fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError: raise ApplianceError('recovery-source-busy') from None
        yield
        current = os.stat(f'lock-{vmid}.conf', dir_fd=dfd, follow_symlinks=False)
        require((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino), 'recovery-lock-changed')
    finally:
        if fd is not None: os.close(fd)
        os.close(dfd)


def _bound_export(plan, export, release, build, private):
    validate_release(release, production=True); validate_site(plan, release)
    export = Path(export)
    with state._directory_fd(export): pass
    roles = {name: role for name, role in ROLE_COMPONENTS.items() if plan['roles'][role]['selected']}
    require({p.name for p in export.iterdir()} == COMPONENTS | set(roles), 'recovery-export-components')
    require(state.read(export/'site.json') == plan, 'recovery-export-plan')
    require(state.read(export/'release.lock.json') == release, 'recovery-export-release')
    require(state.read(export/'build.json') == build, 'recovery-export-build')
    # Validate archived identities without extracting or activating them. Router
    # repair has authority only over its newly allocated, disconnected clone.
    from .role_export import unpack_role
    for name, role in roles.items():
        manifest, _ = unpack_role(_private_bytes(export/name), role=role)
        require(manifest.get('plan_id') == identity(plan), 'recovery-export-role-plan')
    source = proxmox.vm_spec(plan, 'router')
    receipt = proxmox._receipt(source['vmid'], private)
    exported = state.read(export/'vms.json').get(str(source['vmid']))
    require(type(exported) is dict and not exported.get('pending') and not exported.get('iso')
            and exported.get('spec') == source and receipt['spec']['ownership'] == source['ownership']
            and exported.get('disk_volume') == receipt.get('disk_volume'), 'recovery-export-router')
    xml = _private_bytes(export/'router.xml', 512 * 1024)
    doc = parse_xml(xml)
    require(doc.findtext('rdcappliance/plan_id') == identity(plan), 'recovery-export-policy')
    zones = zone_interfaces(plan)
    mapping = {n['mac']:doc.findtext('interfaces/'+zones[n['zone']]+'/if') for n in source['nics']}
    problems = audit_router(plan, xml, {'stage':doc.findtext('rdcappliance/stage'), 'interface_map':mapping})
    require(not any(p.startswith('router-config-') or p in ('router-unmanaged-config','router-authorized-key')
                    for p in problems), 'recovery-export-policy')
    return source, receipt, xml


def _raw_vm(vmid, runner, *, current_only=False):
    cfg = proxmox._properties(proxmox._run(runner,[QM,'config',str(vmid),'--current','1']))
    effective = proxmox._properties(proxmox._run(runner,[QM,'config',str(vmid)]))
    require(current_only or cfg == effective, 'recovery-pending-drift')
    raw = proxmox._run(runner,[QM,'status',str(vmid),'--verbose','1'])
    status = proxmox._properties('\n'.join(line for line in raw.splitlines() if re.match(r'^(?:status|pid|qmpstatus):',line)))
    require(status.get('status') in ('running','stopped') and status.get('qmpstatus',status['status']) in ('running','stopped'), 'recovery-vm-status')
    return {'config':cfg, 'running':status['status']=='running', 'pid':status.get('pid')}


def _clone_options(source, vmid, nonce):
    return {'name':f'rdc-recovery-{vmid}', 'description':'rdc-recovery-v1:'+nonce,
            'cores':str(source['vcpus']), 'sockets':'1', 'memory':str(source['memory_mib']),
            'balloon':'0','onboot':'0','ostype':'other','scsihw':'virtio-scsi-single',
            'boot':'order=scsi0','serial0':'socket',
            **{f'net{n["index"]}':'virtio='+n['mac']+',bridge=rdcr'+str(vmid)+',firewall=1,link_down=1' for n in source['nics']}}


def _bridge_rows(runner, kind='link'):
    try: rows=json.loads(proxmox._run(runner,[IP,'-json',*(['-details'] if kind=='link' else []),kind,'show']))
    except ValueError: raise ApplianceError('recovery-bridge-observation') from None
    require(type(rows) is list and all(type(r) is dict for r in rows),'recovery-bridge-observation')
    return rows


def _bridge_check(record,runner,*,empty=False,absent=False):
    name=record['bridge']; rows=_bridge_rows(runner)
    found=[r for r in rows if r.get('ifname')==name]
    if absent:
        require(not found,'recovery-bridge-in-use'); return
    require(len(found)==1 and found[0].get('ifalias')==record['options']['description']
            and found[0].get('linkinfo',{}).get('info_kind')=='bridge'
            and not found[0].get('master') and 'UP' not in found[0].get('flags',[]),'recovery-bridge-isolation')
    allowed={f'fwpr{record["clone_vmid"]}p{n}' for n in range(len([k for k in record['options'] if k.startswith('net')]))}
    members={r.get('ifname') for r in rows if r.get('master') in (name,found[0].get('ifindex')) and r is not found[0] and r.get('master') is not None}
    require(not members if empty else members<=allowed,'recovery-bridge-members')
    addresses=_bridge_rows(runner,'address')
    require(all(not r.get('addr_info') for r in addresses if r.get('ifname')==name or r.get('ifname') in members),'recovery-bridge-addresses')


def _create_bridge(record,runner,path):
    _bridge_check(record,runner,absent=True)
    record['bridge_cleanup']='needs-inspection'; record['bridge_intent']='create'; state.write(path,record)
    proxmox._run(runner,[IP,'link','add','name',record['bridge'],'alias',record['options']['description'],'type','bridge'])
    _bridge_check(record,runner,empty=True)
    record['bridge_intent']=None; state.write(path,record)


def _remove_bridge(record,runner,path):
    rows=_bridge_rows(runner)
    if any(r.get('ifname')==record['bridge'] for r in rows):
        _bridge_check(record,runner,empty=True)
        record['bridge_intent']='remove'; state.write(path,record)
        proxmox._run(runner,[IP,'link','delete','dev',record['bridge']])
        _bridge_check(record,runner,absent=True)
    record['bridge_cleanup']='removed'; record['bridge_intent']=None; state.write(path,record)


def _clone_owned(record, observed, *, isolation=True):
    cfg = observed['config']; wanted = record['options']
    require(cfg.get('description') == wanted['description'] and cfg.get('name') == wanted['name'], 'recovery-clone-unowned')
    disk = cfg.get('scsi0','').split(',')
    require(bool(re.fullmatch(re.escape(record['storage'])+':vm-'+str(record['clone_vmid'])+r'-disk-[0-9]+',disk[0]))
            and (not record.get('disk_volume') or disk[0]==record['disk_volume']), 'recovery-clone-disk')
    if not isolation: return
    require(set(disk[1:]) == {'size='+str(record['disk_gib'])+'G','serial='+record['serial']}, 'recovery-clone-disk')
    for key,value in wanted.items():
        expected = record.get('boot','order=scsi0') if key=='boot' else value
        require(cfg.get(key)==expected, 'recovery-clone-config')
    require(not any(cfg.get(k) for k in ('args','hookscript','cicustom','lock','template')), 'recovery-clone-config')
    devices={k for k in cfg if re.fullmatch(r'(?:net|scsi|sata|ide|virtio|unused|hostpci|usb|efidisk|tpmstate|serial)[0-9]+',k)}
    allowed={'scsi0','serial0',*(k for k in wanted if re.fullmatch(r'net[0-9]+',k))}
    if record.get('media'):
        allowed.add('ide2'); require(cfg.get('ide2')==record['media']+',media=cdrom', 'recovery-clone-media')
    require(devices==allowed, 'recovery-clone-device')


def _path(private,vmid): return Path(private)/'router-recovery'/(str(vmid)+'.json')


def _mutate(record,kind,argv,runner,path,*,running=False,timeout=180):
    record['sequence'] += 1
    record['pending']={'kind':kind,'sequence':record['sequence'],'argv_sha256':identity({'argv':argv})}
    state.write(path,record)
    proxmox._run(runner,argv,timeout=timeout)
    observed=_raw_vm(record['clone_vmid'],runner); _clone_owned(record,observed)
    require(observed['running'] is running,'recovery-running-outcome')
    record['disk_volume']=observed['config']['scsi0'].split(',')[0]
    record['pending']=None
    state.write(path,record)
    return observed


def _proof(value,record,stage):
    require(type(value) is dict and set(value)=={'schema','nonce','stage','config_sha256','version','root_kind','root_device','hook_removed'}, 'recovery-guest-proof')
    require(value['schema']==1 and value['nonce']==record['nonce'] and value['stage']==stage
            and value['config_sha256']==record['config_sha256'] and value['version']=='26.7'
            and value['root_kind']==('installed-disk' if stage=='verify' else 'recovery-media')
            and value['root_device']=='/dev/da0p3' and value['hook_removed'] is (stage=='verify'), 'recovery-guest-proof')
    return {key:value[key] for key in ('stage','config_sha256','version','root_kind','root_device','hook_removed')}


def _cleanup(record,runner,path):
    """Stop only the newly allocated owned VM; never delete disks on ambiguity."""
    record['cleanup']='needs-inspection'; state.write(path,record)
    resources=proxmox._json(runner,'/cluster/resources','--type','vm')
    if not any(row.get('vmid')==record['clone_vmid'] for row in resources):
        record['cleanup']='no-vm-observed'; state.write(path,record); return
    observed=_raw_vm(record['clone_vmid'],runner,current_only=True); _clone_owned(record,observed,isolation=False)
    if observed['running']:
        record['cleanup_intent']='stop-owned-clone'; state.write(path,record)
        proxmox._run(runner,[QM,'stop',str(record['clone_vmid']),'--timeout','30'],timeout=45)
        observed=_raw_vm(record['clone_vmid'],runner,current_only=True); _clone_owned(record,observed,isolation=False)
    require(not observed['running'],'recovery-cleanup-running')
    record['cleanup']='stopped'; record['cleanup_intent']=None; state.write(path,record)


def restore_router_isolated(plan, inspected_export, clone_vmid, runner, private, *, dvd, work,
                            release, build, console_factory=None,
                            lock_directory=Path('/var/lock/qemu-server')):
    """Prove reimport in a stopped, bridge-free new clone. Never activate it.

    `inspected_export` is the private directory returned by inspect_export.
    `dvd` is the pinned expanded OPNsense DVD; `work` must be a new private path.
    The caller enforces local privileged execution and explicit new-VMID intent.
    """
    integer(clone_vmid,100,999999999)
    require(clone_vmid not in {v['vmid'] for v in plan['vms'].values()},'recovery-new-vmid')
    source,source_receipt,xml=_bound_export(plan,inspected_export,release,build,private)
    path=_path(private,clone_vmid)
    with state.lock(path.parent):
        require(not path.exists(),'recovery-needs-inspection')
        with source_lock(source['vmid'],lock_directory):
            observed=proxmox.observe_vm(source['vmid'],runner); proxmox._owned(source,observed,source_receipt)
            require(not observed['running'] and not observed['iso_present'],'recovery-source-must-be-stopped')
            before=identity(observed['config'])
            resources=proxmox._json(runner,'/cluster/resources','--type','vm')
            require(not any(r.get('vmid')==clone_vmid for r in resources),'recovery-vmid-in-use')
            node=proxmox._name(proxmox._run(runner,['/usr/bin/hostname','-s']).strip())
            require(any(r.get('vmid')==source['vmid'] and r.get('node')==node and r.get('type')=='qemu' for r in resources),'recovery-source-node')
            base='/nodes/'+node+'/storage/'+source['storage']
            storage=proxmox._json(runner,base+'/status')
            require(storage.get('active')==1 and storage.get('enabled')==1 and storage.get('type')=='lvmthin'
                    and 'images' in storage.get('content','').split(',') and type(storage.get('avail')) is int
                    and storage['avail']>=(source['disk_gib']+2)*1024**3,'recovery-storage')
            require(proxmox._json(runner,base+'/content','--content','images','--vmid',str(clone_vmid))==[],'recovery-unowned-disk')
            work=Path(work).absolute()
            require(work.resolve()==work and not work.exists(),'recovery-work-new')
            with state._directory_fd(work.parent): pass
            work.mkdir(mode=0o700)
            nonce=secrets.token_hex(32); serial='RDC'+nonce[:16]
            iso=work/'recovery.iso'
            try: image=build_recovery_iso(plan,xml,nonce,Path(dvd),iso,runner,release)
            except BaseException:
                if iso.exists(): iso.unlink()
                raise
            record={'schema':1,'phase':'recovering','clone_vmid':clone_vmid,'source_vmid':source['vmid'],
                'source_config_id':before,'plan_id':identity(plan),'release_id':identity(release),'build_id':identity(build),
                'config_sha256':hashlib.sha256(xml).hexdigest(),'nonce':nonce,'serial':serial,
                'storage':source['storage'],'disk_gib':source['disk_gib'],'sequence':0,'pending':None,
                'options':_clone_options(source,clone_vmid,nonce),'proofs':[], 'media':str(iso),
                'bridge':'rdcr'+str(clone_vmid),'bridge_cleanup':'not-created',
                'media_path':str(iso),'boot':'order=ide2;scsi0','media_sha256':image['sha256'],'cleanup':'not-started'}
            state.write(path,record)
            failed=None
            try:
                _create_bridge(record,runner,path)
                options={**record['options'],'boot':record['boot'],'ide2':str(iso)+',media=cdrom',
                    'scsi0':source['storage']+':0,import-from='+observed['disk_volume']+',serial='+serial}
                argv=[QM,'create',str(clone_vmid)]
                for key,value in options.items(): argv += ['--'+key,value]
                _mutate(record,'create-isolated-copy',argv,runner,path,timeout=3600)
                after=proxmox.observe_vm(source['vmid'],runner); proxmox._owned(source,after,source_receipt)
                require(not after['running'] and identity(after['config'])==before,'recovery-source-changed')
                # The source flock stays held across both boots as well, making
                # its unchanged/stopped state part of the final proof.
                for stage in ('import','verify'):
                    if stage=='verify':
                        record['media']=None; record['boot']='order=scsi0'
                        _mutate(record,'detach-recovery-media',[QM,'set',str(clone_vmid),'--delete','ide2','--boot','order=scsi0'],runner,path)
                    _clone_owned(record,_raw_vm(clone_vmid,runner))
                    _bridge_check(record,runner,empty=True)
                    _mutate(record,'start-'+stage,[QM,'start',str(clone_vmid)],runner,path,running=True)
                    console=(console_factory or SerialConsole)(clone_vmid)
                    try: proof=console.exchange(nonce,stage,timeout_s=300)
                    finally: console.close()
                    _bridge_check(record,runner)
                    record['proofs'].append(_proof(proof,record,stage)); state.write(path,record)
                    _clone_owned(record,_raw_vm(clone_vmid,runner))
                    _mutate(record,'stop-'+stage,[QM,'stop',str(clone_vmid),'--timeout','30'],runner,path,timeout=45)
                record['phase']='complete'
            except BaseException as error:
                failed=error; record['phase']='failed'
                record['failure']=error.code if isinstance(error,ApplianceError) else 'recovery-interrupted'
            finally:
                try:
                    _cleanup(record,runner,path)
                    _remove_bridge(record,runner,path)
                except BaseException:
                    record['phase']='failed'; record['cleanup']='needs-inspection'; state.write(path,record)
                    if failed is None: failed=ApplianceError('recovery-cleanup-needs-inspection')
                # A stopped clone may retain a dangling CD reference after an
                # interrupted operation. Removing the private ISO still cannot
                # attach or start anything and eliminates its plaintext secrets.
                if record['cleanup'] in ('stopped','no-vm-observed') and iso.exists():
                    iso.unlink()
            if failed is not None: raise failed
            return _public(record)


def _public(record):
    complete=(record['phase']=='complete' and record['cleanup']=='stopped'
              and record.get('bridge_cleanup')=='removed' and len(record['proofs'])==2)
    return {'schema':1,'state':'verified' if complete else 'incomplete','clone_vmid':record['clone_vmid'],
            'source_vmid':record['source_vmid'],'clone_stopped':record['cleanup']=='stopped',
            'activation':'forbidden','network':'isolated-bridge-all-links-down',
            'bridge_removed':record.get('bridge_cleanup')=='removed','proofs':record['proofs'],
            'hardware_qualification':'not-run'}


def reconcile_router_recovery(clone_vmid,runner,private):
    """Observe an existing attempt only. Never replay import or start a guest."""
    integer(clone_vmid,100,999999999)
    record=state.read(_path(private,clone_vmid))
    require(record.get('clone_vmid')==clone_vmid,'recovery-receipt')
    observed=_raw_vm(clone_vmid,runner)
    # Unknown detach/create outcome: inspect only the two closed boot profiles.
    view=dict(record,media=observed['config'].get('ide2','').removesuffix(',media=cdrom') or None,
              boot=observed['config'].get('boot'))
    require(view['boot'] in ('order=scsi0','order=ide2;scsi0'),'recovery-clone-config')
    if view['media']:
        require(view['media']==record.get('media_path'), 'recovery-clone-media')
    _clone_owned(view,observed)
    require(not observed['running'],'recovery-cleanup-needs-inspection')
    if any(r.get('ifname')==record['bridge'] for r in _bridge_rows(runner)):
        _bridge_check(record,runner,empty=True)
        record=dict(record,bridge_cleanup='present')
    else: record=dict(record,bridge_cleanup='removed')
    record=dict(record,cleanup='stopped')
    return _public(record)


class SerialConsole:
    """Bounded root-local QEMU UART socket; emits no command or credential logs."""
    def __init__(self,vmid,*,socket_directory=Path('/var/run/qemu-server')):
        integer(vmid,100,999999999)
        self.path=Path(socket_directory)/f'{vmid}.serial0'; self.connection=None

    def exchange(self,nonce,stage,*,timeout_s=300):
        require(type(nonce) is str and re.fullmatch(r'[a-f0-9]{64}',nonce) and stage in ('import','verify'),'recovery-serial-request')
        require(type(timeout_s) is int and 1<=timeout_s<=600,'recovery-serial-timeout')
        deadline=time.monotonic()+timeout_s
        while True:
            try:
                before=self.path.lstat()
                require(stat.S_ISSOCK(before.st_mode) and before.st_uid==os.geteuid(),'recovery-serial-socket')
                connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.settimeout(min(1,max(0.001,deadline-time.monotonic())))
                connection.connect(str(self.path))
                self.connection=connection
                break
            except (FileNotFoundError,ConnectionRefusedError,socket.timeout):
                if 'connection' in locals(): connection.close()
                require(time.monotonic()<deadline,'recovery-serial-timeout'); time.sleep(0.05)
        output=bytearray(); cursor=0; requested=False
        ready=('RDC-READY '+stage+' '+nonce).encode()
        while time.monotonic()<deadline:
            try: chunk=connection.recv(4096)
            except socket.timeout: continue
            require(bool(chunk),'recovery-serial-disconnected')
            output.extend(chunk); require(len(output)<=MAX_TRANSCRIPT,'recovery-serial-size')
            while b'\n' in output[cursor:]:
                end=output.index(b'\n',cursor)
                line=bytes(output[cursor:end]).rstrip(b'\r'); cursor=end+1
                if line==ready:
                    connection.sendall(('RDC1 '+nonce+' '+stage+'\n').encode()); requested=True
                if not line.startswith(PREFIX): continue
                require(requested,'recovery-serial-unsolicited')
                try: value=json.loads(line[len(PREFIX):])
                except (ValueError,UnicodeError): raise ApplianceError('recovery-serial-proof') from None
                require(type(value) is dict,'recovery-serial-proof')
                return value
        raise ApplianceError('recovery-serial-timeout')

    def close(self):
        if self.connection is not None: self.connection.close(); self.connection=None


@contextmanager
def mounted_dvd(image, mountpoint, runner):
    """Mount only a verified regular image at a newly created private directory."""
    mountpoint.mkdir(mode=0o700)
    mounted=False
    try:
        runner.run(['/usr/bin/mount','-t','iso9660','-o','loop,ro,nosuid,nodev,noexec',
                    str(image),str(mountpoint)],timeout_s=30)
        mounted=True
        yield mountpoint
    finally:
        # A timeout can leave a successful mount. Unmounting our brand-new
        # directory is safe even then, and never targets a pre-existing mount.
        try: runner.run(['/usr/bin/umount',str(mountpoint)],timeout_s=30)
        except ApplianceError:
            if mounted: raise ApplianceError('recovery-media-unmount') from None


def remaster_dvd(dvd,output,payload,runner,release,*,originals=None):
    """Private BIOS DVD for the V1 SeaBIOS VM, using PVE's genisoimage package.

    This is not a USB/UEFI image builder. The pinned Proxmox qemu-server package
    depends on genisoimage, so this path needs no extra download on the host.
    """
    validate_release(release,production=True)
    records=[r for r in release['components'] if r['id']=='opnsense-dvd']
    require(len(records)==1 and records[0]['version']=='26.7','recovery-media-version')
    dvd=Path(dvd).absolute(); verify_file(dvd,records[0].get('expanded',records[0]))
    output=Path(output).absolute()
    require(output.resolve()==output and not output.exists(),'recovery-media-path')
    with state._directory_fd(output.parent): pass
    require(type(payload) is dict and payload and sum(len(v) for v in payload.values())<=2*1024*1024,
            'recovery-media-payload')
    require(all(type(k) is str and k.startswith(('/etc/rc','/rdc-recovery/','/rdc-lab/'))
                and '..' not in Path(k).parts and type(v) is bytes for k,v in payload.items()),'recovery-media-payload')
    require(originals is None or originals=={'/rdc-lab/original-rc':'/etc/rc'},'recovery-media-originals')
    payload=dict(payload)
    try:
        with tempfile.TemporaryDirectory(prefix='.rdc-recovery-',dir=output.parent) as temporary:
            root=Path(temporary); tree=root/'tree'
            with mounted_dvd(dvd,root/'source',runner) as mounted:
                for target,source in (originals or {}).items():
                    source=mounted/source.lstrip('/')
                    require(source.is_file() and not source.is_symlink() and source.stat().st_size<=65536,'recovery-media-originals')
                    payload[target]=source.read_bytes()
                shutil.copytree(mounted,tree,symlinks=True)
            for target,content in payload.items():
                path=tree/target.lstrip('/')
                for part in [*reversed(path.parents),path]:
                    if part==tree or tree in part.parents:
                        require(not part.is_symlink(),'recovery-media-symlink')
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(content); path.chmod(0o700 if target.endswith(('/rc','/verify','/install')) else 0o600)
            boot=tree/'boot/cdboot'
            require(boot.is_file() and not boot.is_symlink(),'recovery-media-boot')
            runner.run([GENISOIMAGE,'-quiet','-R','-iso-level','3','-V','OPNSENSE_INSTALL',
                        '-b','boot/cdboot','-no-emul-boot','-boot-load-size','4','-o',str(output),str(tree)],timeout_s=600)
            require(output.is_file() and not output.is_symlink(),'recovery-media-output'); output.chmod(0o600)
            with mounted_dvd(output,root/'readback',runner) as mounted:
                for target,content in payload.items():
                    path=mounted/target.lstrip('/')
                    require(path.is_file() and not path.is_symlink() and path.stat().st_size==len(content)
                            and path.read_bytes()==content,'recovery-media-readback')
        digest=hashlib.sha256()
        with output.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
        return {'sha256':digest.hexdigest(),'size_bytes':output.stat().st_size}
    except BaseException:
        if output.exists(): output.unlink()
        raise


def build_recovery_iso(plan,xml,nonce,dvd,output,runner,release):
    """Remaster only private pinned media, with no site secrets on shared USB."""
    return remaster_dvd(dvd,output,recovery_payload(plan,xml,nonce),runner,release)


def recovery_payload(plan,xml,nonce):
    require(type(nonce) is str and re.fullmatch(r'[0-9a-f]{64}',nonce),'recovery-nonce')
    require(parse_xml(xml).findtext('rdcappliance/plan_id')==identity(plan),'recovery-export-policy')
    digest=hashlib.sha256(xml).hexdigest(); serial='RDC'+nonce[:16]
    common='''#!/bin/sh
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077
trap 'sync; shutdown -p now' EXIT HUP INT TERM
[ -c /dev/cuau0 ]
stty -f /dev/cuau0 115200 cs8 -parenb -cstopb raw -echo
exec 3<>/dev/cuau0
'''
    def handshake(stage):
        request='RDC1 '+nonce+' '+stage
        return ('attempt=0; request=\nwhile [ "$attempt" -lt 300 ]; do\n'
                + "printf '%s\\n' 'RDC-READY "+stage+' '+nonce+"' >&3\n"
                + 'request=$(timeout 1 dd bs=1 count='+str(len(request)+1)+' 2>/dev/null <&3) || request=\n'
                + '[ "$request" != "'+request+'" ] || break\nattempt=$((attempt+1))\ndone\n'
                + '[ "$request" = "'+request+'" ]\n')
    proof={'schema':1,'nonce':nonce,'stage':'import','config_sha256':digest,'version':'26.7',
           'root_kind':'recovery-media','root_device':'/dev/da0p3','hook_removed':False}
    # A new VM contains only scsi0 and the recovery CD. No host disk passthrough
    # is supported. Exact GPT-UFS layout and serial prevent guessing partitions.
    live=common+handshake('import')+'''
mount -t tmpfs -o mode=0700 tmpfs /tmp
mounted=0
finish() { [ "$mounted" = 0 ] || umount /tmp/rdc-target; sync; shutdown -p now; }
trap finish EXIT HUP INT TERM
[ "$(sysctl -n kern.disks | tr ' ' '\\n' | sort | tr '\\n' ' ')" = 'cd0 da0 ' ]
[ "$(camcontrol inquiry da0 -S)" = 'SERIAL' ]
[ "$(fstyp /dev/da0p3)" = ufs ]
fsck_ufs -n /dev/da0p3
mkdir /tmp/rdc-target
mount -t ufs -o rw /dev/da0p3 /tmp/rdc-target
mounted=1
[ -f /tmp/rdc-target/usr/local/opnsense/version/core ]
[ -f /tmp/rdc-target/conf/config.xml ]
[ ! -L /tmp/rdc-target/conf ]
[ ! -L /tmp/rdc-target/conf/config.xml ]
[ ! -e /tmp/rdc-target/usr/local/etc/rc.syshook.d/start/99-rdc-recovery ]
[ "$(sha256 -q /rdc-recovery/config.xml)" = 'DIGEST' ]
install -m 0600 /rdc-recovery/config.xml /tmp/rdc-target/conf/config.xml
install -m 0700 /rdc-recovery/verify /tmp/rdc-target/usr/local/etc/rc.syshook.d/start/99-rdc-recovery
[ "$(sha256 -q /tmp/rdc-target/conf/config.xml)" = 'DIGEST' ]
sync
umount /tmp/rdc-target
mounted=0
printf '%s\\n' 'PROOF' >&3
'''.replace('SERIAL',serial).replace('DIGEST',digest).replace('PROOF',(PREFIX+canonical(proof)).decode())
    # OPNsense calls start hooks after rc.bootup has loaded the recovered XML.
    # Remove this one-shot code before reporting success; it has no credentials.
    verify=common+handshake('verify')+'''
trap 'sync; shutdown -p now' EXIT HUP INT TERM
[ "$(sysctl -n kern.disks | tr ' ' '\\n' | sort | tr '\\n' ' ')" = 'da0 ' ]
[ "$(camcontrol inquiry da0 -S)" = 'SERIAL' ]
[ "$(mount -p | awk '$2 == "/" {print $3}')" = ufs ]
[ "$(sha256 -q /conf/config.xml)" = 'DIGEST' ]
rm /usr/local/etc/rc.syshook.d/start/99-rdc-recovery
sync
/usr/local/bin/php -r '
$v = json_decode(file_get_contents("/usr/local/opnsense/version/core"), true);
if (($v["product_version"] ?? "") !== "26.7") exit(1);
$p = json_decode(base64_decode("PROOF_BASE64"), true);
echo "RDC-RECOVERY ", json_encode($p, JSON_UNESCAPED_SLASHES), "\\n";
' >&3
'''.replace('SERIAL',serial).replace('DIGEST',digest)
    import base64
    verified=dict(proof,stage='verify',root_kind='installed-disk',hook_removed=True)
    verify=verify.replace('PROOF_BASE64',base64.b64encode(canonical(verified)).decode())
    return {'/etc/rc':live.encode(),'/rdc-recovery/config.xml':xml,'/rdc-recovery/verify':verify.encode()}

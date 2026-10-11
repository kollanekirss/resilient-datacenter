"""Automatic OPNsense provisioning inside the disposable acceptance PVE only.

A private copy of the pinned DVD invokes its own official installer. The VM is
fresh, all links stay disconnected, and a nonce-bound serial observation of the
installed guest supplies the console checks. This never qualifies hardware.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from . import proxmox, router, state
from .contracts import ApplianceError, canonical, identity, require
from .plan import validate_release, validate_site
from .router_config import _key, audit_router, parse_xml
from .router_recovery import SerialConsole, remaster_dvd


def _require_disposable(plan):
    require(os.geteuid()==0 and plan['target']['serial']=='RDC-LAB-TARGET'
            and plan['ports']['management']['permanent_mac']=='52:54:00:77:00:01'
            and plan['ports']['wan']['permanent_mac']=='52:54:00:77:00:02','lab-router-disposable-only')
    try:product=Path('/sys/class/dmi/id/product_name').read_text().strip()
    except OSError:raise ApplianceError('lab-router-disposable-only') from None
    require(product=='RDC Disposable Acceptance','lab-router-disposable-only')


def _bcrypt(password):
    # Debian's libcrypt is already installed. No package fetch or external
    # process argv/stdout ever contains the plaintext acceptance password.
    require(type(password) is str and 20<=len(password.encode())<=72 and '\0' not in password,'lab-router-password')
    alphabet='./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    salt='$2y$12$'+''.join(secrets.choice(alphabet) for _ in range(21))+secrets.choice('.Oeu')
    try:
        library=ctypes.CDLL('libcrypt.so.1');function=library.crypt
        function.argtypes=(ctypes.c_char_p,ctypes.c_char_p);function.restype=ctypes.c_char_p
        result=function(password.encode(),salt.encode())
    except (OSError,AttributeError):raise ApplianceError('lab-router-bcrypt-unavailable') from None
    require(result is not None,'lab-router-bcrypt-unavailable')
    value=result.decode('ascii')
    require(re.fullmatch(r'\$2y\$12\$[./A-Za-z0-9]{53}',value),'lab-router-bcrypt-unavailable')
    return value


def _keypair(path,runner):
    require(not path.exists() and not Path(str(path)+'.pub').exists(),'lab-router-key-exists')
    proxmox._run(runner,['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(path)])
    require(router._private_file(str(path)),'lab-router-private-key')
    public=' '.join(Path(str(path)+'.pub').read_text().strip().split()[:2])
    return _key(public)


def _handshake(nonce,stage):
    request='RDC1 '+nonce+' '+stage
    return ("attempt=0; request=\nwhile [ \"$attempt\" -lt 300 ]; do\n"
            +"printf '%s\\n' 'RDC-READY "+stage+' '+nonce+"' >&3\n"
            +'request=$(timeout 1 dd bs=1 count='+str(len(request)+1)+' 2>/dev/null <&3) || request=\n'
            +'[ "$request" != "'+request+'" ] || break\nattempt=$((attempt+1))\ndone\n'
            +'[ "$request" = "'+request+'" ]\n')


def installer_payload(plan,files,nonce):
    require(re.fullmatch('[0-9a-f]{64}',nonce),'lab-router-nonce')
    digest=hashlib.sha256(files['bootstrap.xml']).hexdigest()
    proof={'schema':1,'nonce':nonce,'stage':'import','plan_id':identity(plan),'config_sha256':digest}
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
    install=common+_handshake(nonce,'import')+'''
[ "$(sysctl -n kern.disks | tr ' ' '\\n' | sort | tr '\\n' ' ')" = 'cd0 da0 ' ]
[ "$(diskinfo -v da0 | awk '/mediasize in bytes/ {print $1}')" = 'DISK_BYTES' ]
# Refuse a partitioned target; this media never repairs or reinstalls a disk.
if gpart show da0 >/dev/null 2>&1; then exit 1; fi
mount -t tmpfs -o mode=1777 tmpfs /tmp
for i in boot conf etc home root usr var; do
    mkdir -p /tmp/.media/$i
    mount_unionfs /tmp/.media/$i /$i
done
# The official copier validates the unmodified source against its mtree.
# Restore rc before copying; the executing shell already read this script.
install -m 0644 /rdc-lab/original-rc /etc/rc
/sbin/ldconfig -elf /usr/lib /usr/local/lib /lib
/etc/rc.d/ldconfig start
mkdir -p /tmp/rdc-bin
cat > /tmp/rdc-bin/bsddialog <<'DIALOG'
#!/bin/sh
for arg in "$@"; do [ "$arg" != --mixedgauge ] || exit 0; done
# Every error/continue prompt aborts, never silently continues.
exit 1
DIALOG
chmod 0700 /tmp/rdc-bin/bsddialog
PATH=/tmp/rdc-bin:$PATH
export PATH
BSDINSTALL_CHROOT=/tmp/rdc-target
BSDINSTALL_TMPETC=/tmp/bsdinstall_etc
BSDINSTALL_TMPBOOT=/tmp/bsdinstall_boot
PATH_FSTAB=$BSDINSTALL_TMPETC/fstab
export BSDINSTALL_CHROOT BSDINSTALL_TMPETC BSDINSTALL_TMPBOOT PATH_FSTAB
mkdir -p "$BSDINSTALL_CHROOT" "$BSDINSTALL_TMPETC" "$BSDINSTALL_TMPBOOT"
mounted=0
finish() { [ "$mounted" = 0 ] || bsdinstall umount; sync; shutdown -p now; }
trap finish EXIT HUP INT TERM
bsdinstall scriptedpart da0 gpt '{' 260M efi, 512K freebsd-boot, auto freebsd-ufs / '}'
gpart bootcode -b /boot/pmbr -p /boot/gptboot -i 2 da0
bsdinstall mount
mounted=1
bsdinstall opnsense-install
bsdinstall bootconfig
bsdinstall entropy
target=$BSDINSTALL_CHROOT
[ "$(fstyp /dev/da0p3)" = ufs ]
[ "$(sha256 -q /rdc-lab/bootstrap.xml)" = 'DIGEST' ]
mkdir -p "$target/conf/rdc-appliance/operations" "$target/conf/rdc-lab" "$target/usr/local/etc/ssh/sshd_config.d"
chmod 0700 "$target/conf/rdc-appliance" "$target/conf/rdc-appliance/operations" "$target/conf/rdc-lab"
for item in bootstrap.xml transit.xml manifest.json helper.php; do
    install -m 0600 /rdc-lab/$item "$target/conf/rdc-appliance/$item"
done
install -m 0600 /rdc-lab/bootstrap.xml "$target/conf/config.xml"
install -m 0600 /rdc-lab/rdcappliance.inc "$target/usr/local/etc/inc/plugins.inc.d/rdcappliance.inc"
install -m 0600 /rdc-lab/00-rdc-appliance.conf "$target/usr/local/etc/ssh/sshd_config.d/00-rdc-appliance.conf"
install -m 0600 /rdc-lab/request.json "$target/conf/rdc-lab/request.json"
install -m 0600 /rdc-lab/report.php "$target/conf/rdc-lab/report.php"
install -m 0700 /rdc-lab/verify "$target/usr/local/etc/rc.syshook.d/start/99-rdc-lab"
[ "$(sha256 -q "$target/conf/config.xml")" = 'DIGEST' ]
sync
bsdinstall umount
mounted=0
printf '%s\\n' 'PROOF' >&3
'''.replace('DISK_BYTES',str(proxmox.vm_spec(plan,'router')['disk_gib']*1024**3)).replace('DIGEST',digest).replace('PROOF','RDC-RECOVERY '+canonical(proof).decode())
    verify=common+_handshake(nonce,'verify')+'''
[ "$(sysctl -n kern.disks | tr ' ' '\\n' | sort | tr '\\n' ' ')" = 'da0 ' ]
[ "$(mount -p | awk '$2 == "/" {print $3}')" = ufs ]
SSH_ORIGINAL_COMMAND=rdc-router /usr/local/bin/php /conf/rdc-appliance/helper.php < /conf/rdc-lab/request.json > /conf/rdc-lab/runtime.json
rm /usr/local/etc/rc.syshook.d/start/99-rdc-lab
/usr/local/bin/php /conf/rdc-lab/report.php > /conf/rdc-lab/report.json
rm /conf/rdc-lab/request.json /conf/rdc-lab/runtime.json /conf/rdc-lab/report.php
sync
cat /conf/rdc-lab/report.json >&3
rm /conf/rdc-lab/report.json
rmdir /conf/rdc-lab
# Successful inspection leaves the guest up for the separate management gate.
trap - EXIT HUP INT TERM
'''
    report='''<?php
$p = json_decode(base64_decode('PROOF'), true, 16, JSON_THROW_ON_ERROR);
$r = json_decode(file_get_contents('/conf/rdc-lab/runtime.json'), true, 32, JSON_THROW_ON_ERROR);
if (($r['nonce'] ?? '') !== 'REQUEST_NONCE' || file_exists('/usr/local/etc/rc.syshook.d/start/99-rdc-lab')) exit(1);
$key = preg_split('/\\s+/', trim(file_get_contents('/conf/sshd/ssh_host_ed25519_key.pub')));
if (count($key) < 2 || $key[0] !== 'ssh-ed25519') exit(1);
$p['stage'] = 'verify'; $p['runtime'] = $r;
$p['host_public_key'] = $key[0] . ' ' . $key[1]; $p['hook_removed'] = true;
echo 'RDC-RECOVERY ', json_encode($p, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\\n";
'''.replace('PROOF',base64.b64encode(canonical(proof)).decode()).replace('REQUEST_NONCE',nonce[:32])
    return {'/etc/rc':b'#!/bin/sh\nexec /bin/sh /rdc-lab/install\n','/rdc-lab/install':install.encode(),'/rdc-lab/verify':verify.encode(),'/rdc-lab/report.php':report.encode(),
            '/rdc-lab/request.json':canonical({'action':'inspect','plan_id':identity(plan),'nonce':nonce[:32]}),
            **{'/rdc-lab/'+name:content for name,content in files.items()}}


def _proof(plan,value,nonce,stage,files,credentials):
    base={'schema':1,'nonce':nonce,'stage':stage,'plan_id':identity(plan),
          'config_sha256':hashlib.sha256(files['bootstrap.xml']).hexdigest()}
    require(type(value) is dict and all(value.get(k)==v for k,v in base.items()),'lab-router-console-proof')
    if stage=='import':
        require(set(value)==set(base),'lab-router-console-proof');return None
    require(set(value)==set(base)|{'runtime','host_public_key','hook_removed'} and value['hook_removed'] is True,'lab-router-console-proof')
    runtime=value['runtime']
    require(type(runtime) is dict and type(runtime.get('config_xml')) is str,'lab-router-runtime')
    xml=runtime['config_xml'].encode()
    require(not audit_router(plan,xml,runtime),'lab-router-console-checks')
    require(runtime.get('vmid')==plan['vms']['router']['vmid'] and runtime.get('boot_id')
            and runtime.get('stage')=='bootstrap' and runtime.get('interface_map')==credentials['interface_map']
            and parse_xml(xml).findtext('system/user/password')==credentials['root_password_hash'],'lab-router-console-binding')
    return _key(value['host_public_key'])


def _stop_owned(spec,runner,private):
    # A lost command reply may leave a pending receipt. Observe its exact target
    # without replaying or clearing that journal before stopping this lab VM.
    receipt=state.read(proxmox._path(private,spec['vmid']))
    view=receipt.get('desired',{}).get('receipt',receipt)
    observed=proxmox.observe_vm(spec['vmid'],runner);proxmox._owned(spec,observed,view)
    if observed['running']:
        path=Path(private)/'lab-router'/'setup.json';record=state.read(path)
        record['stop_sequence']=record.get('stop_sequence',0)+1
        record['stop_intent']={'config_id':identity(observed['config']),'boot_id':observed['boot_id']}
        state.write(path,record)
        proxmox._run(runner,[proxmox.QM,'stop',str(spec['vmid'])],timeout=180)
        after=proxmox.observe_vm(spec['vmid'],runner);proxmox._owned(spec,after,view)
        require(not after['running'],'lab-router-stop-outcome')
        record['stop_intent']=None;state.write(path,record)


def setup_router(plan,release,runner,private,credentials):
    """Install once into a fresh lab VM and leave all four/five links down.

    Caller alone decides when to consume checks in router.attest_console and
    then open management/WAN/transit gates. A failed setup is never replayed.
    """
    _require_disposable(plan);validate_release(release,production=True);validate_site(plan,release)
    private=Path(private);spec=proxmox.vm_spec(plan,'router');work=private/'lab-router'
    with state.lock(work):
        path=work/'setup.json'
        require(not path.exists() and not proxmox._path(private,spec['vmid']).exists(),'lab-router-setup-needs-inspection')
        require(not router.CHANNEL.exists(),'lab-router-channel-exists')
        nonce=secrets.token_hex(32);iso=work/'router-install.iso'
        record={'schema':1,'plan_id':identity(plan),'vmid':spec['vmid'],'state':'incomplete','phase':'prepare','cleanup':'not-needed'}
        state.write(path,record)
        try:
            password=_bcrypt(credentials['password']);keypath=work/'helper_ed25519'
            public=_keypair(keypath,runner)
            bootstrap={'root_password_hash':password,'management_public_key':public,
                'interface_map':{n['mac']:'vtnet'+str(n['index']) for n in spec['nics']}}
            files=router.bootstrap_files(plan,bootstrap)
            remaster_dvd(private.parent/'media/opnsense-dvd',iso,installer_payload(plan,files,nonce),runner,release,
                         originals={'/rdc-lab/original-rc':'/etc/rc'})
            record.update(phase='allocate',cleanup='needs-inspection');state.write(path,record)
            proxmox.ensure_vm(spec,runner,private)
            receipt=proxmox._receipt(spec['vmid'],private)
            proxmox._mutate(receipt,'vm-attach-lab-iso',[proxmox.QM,'set',str(spec['vmid']),'--ide2',str(iso)+',media=cdrom',
                '--serial0','socket','--boot','order=ide2;scsi0'],runner,private,updates={'iso':str(iso),'phase':'media-attached'})
            record['phase']='install';state.write(path,record)
            proxmox.start_installer(spec['vmid'],runner,private)
            console=SerialConsole(spec['vmid'])
            try:imported=console.exchange(nonce,'import',timeout_s=600)
            finally:console.close()
            _proof(plan,imported,nonce,'import',files,bootstrap)
            _stop_owned(spec,runner,private)
            record['phase']='verify-disk';state.write(path,record)
            proxmox.disk_boot(spec['vmid'],runner,private)
            console=SerialConsole(spec['vmid'])
            try:verified=console.exchange(nonce,'verify',timeout_s=600)
            finally:console.close()
            hostkey=_proof(plan,verified,nonce,'verify',files,bootstrap)
            _,observed=router._vm(plan,runner)
            require(all(not n['connected'] for n in observed['nics'].values()),'lab-router-isolation')
            known=work/'known_hosts'
            with state._directory_fd(work) as dfd:
                state._write_at(dfd,known.name,(plan['networks']['management']['gateway']+' '+hostkey+'\n').encode())
            record['phase']='pin-channel';state.write(path,record)
            state.write(router.CHANNEL,{'schema':1,'plan_id':identity(plan),'address':plan['networks']['management']['gateway'],
                'private_key':str(keypath),'known_hosts':str(known),'host_public_key':hostkey,
                'helper_sha256':hashlib.sha256(files['helper.php']).hexdigest()})
            router._channel(plan)
            state.write(work/'console-proof.json',verified)
            # These checks follow the complete real runtime/config audit above;
            # no saved fixture is accepted as a console observation.
            result={'schema':1,'state':'bootstrap-verified','checks':{name:True for name in router.CONSOLE_CHECKS},
                    'plan_id':identity(plan),'vmid':spec['vmid'],'guest_boot_id':verified['runtime']['boot_id'],
                    'vm_boot_id':observed['boot_id'],'hardware_qualification':'not-run'}
            record.update(state='complete',phase='bootstrap-verified',cleanup='running-isolated');state.write(path,record)
            return result
        except BaseException:
            record['state']='incomplete'
            if record['cleanup']!='not-needed':
                record['cleanup_intent']='stop-owned';state.write(path,record)
                try:_stop_owned(spec,runner,private);record['cleanup']='stopped'
                except (ApplianceError,OSError):record['cleanup']='needs-inspection'
            state.write(path,record)
            raise
        finally:
            if iso.exists():iso.unlink()


def router_certificate(plan,runner,private):
    """Read the currently referenced HTTPS certificate over the pinned channel."""
    observation=router.collect_router(plan,runner)
    require(not observation['checks'],'lab-router-certificate-policy')
    doc=parse_xml(observation['config_xml'].encode());reference=doc.findtext('system/webgui/ssl-certref')
    matches=[cert for cert in doc.findall('cert') if cert.findtext('refid')==reference]
    require(reference and len(matches)==1,'lab-router-certificate')
    try:pem=base64.b64decode(matches[0].findtext('crt',''),validate=True).decode('ascii')
    except (ValueError,UnicodeError):raise ApplianceError('lab-router-certificate') from None
    require(len(pem)<=65536 and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+\n-----END CERTIFICATE-----\s*',pem),'lab-router-certificate')
    return pem

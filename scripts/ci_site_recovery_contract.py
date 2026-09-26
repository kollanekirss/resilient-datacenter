"""Pure contracts for a disposable combined recovery fixture."""
from pathlib import Path,PurePosixPath
import tarfile
from ci_home_vm import qemu_command

ROLES={'chat':('rs-chat','52:54:00:76:40:10',22222),'files':('rs-files','52:54:00:76:40:11',22223)}


def guest_command(folder,port,role):
    if role not in ROLES or port!=ROLES[role][2]:raise ValueError('Use fixed fixture roles and consoles')
    tap,mac,_=ROLES[role]
    return qemu_command(folder,port,offline=True)+['-netdev','tap,id=kit,ifname='+tap+',script=no,downscript=no',
                                                  '-device','virtio-net-pci,netdev=kit,mac='+mac]


def require_fenced(guests):
    if set(guests)!=set(ROLES) or any(g.process is None or g.process.poll() is None for g in guests.values()):
        raise ValueError('Every original QEMU process must be confirmed stopped before replacement')


def archive_member(member,destination):
    name=PurePosixPath(member.name)
    if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ValueError('Unsafe native snapshot archive entry')
    try:filtered=tarfile.data_filter(member,destination)
    except tarfile.FilterError:raise ValueError('Unsafe native snapshot link') from None
    if not all(type(v) is int and 0<=v<2**31 for v in (member.uid,member.gid)):raise ValueError('Invalid snapshot ownership')
    if member.mode & ~0o777:raise ValueError('Special snapshot permissions are unsupported')
    filtered.uid=member.uid;filtered.gid=member.gid;filtered.mode=member.mode
    return filtered


def extract(archive,target):
    target=Path(target)
    if target.exists() or target.is_symlink():raise ValueError('Snapshot staging already exists')
    target.mkdir(mode=0o700)
    with tarfile.open(archive) as stream:stream.extractall(target,filter=archive_member)


def evidence(seconds,ages):
    if seconds<0 or set(ages)!=set(ROLES) or any(v<0 for v in ages.values()):raise ValueError('Invalid recovery measurements')
    return {'state':'combined-linux-recovery-passed','recovery_seconds':round(seconds,2),'backup_age_at_failure_seconds':ages,
            'routing':'linux-fixture','opnsense':'not-tested','proxmox':'not-tested','physical_relocation':'not-tested',
            'os_installation':'preinstalled-pinned-ubuntu-image','utc_accuracy':'not-tested',
            'known_later_writes_absent':{'chat_messages':1,'file_versions':1},
            'notice':'Synthetic measured exercise, not a general availability or data-loss guarantee.'}

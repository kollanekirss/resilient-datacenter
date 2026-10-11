"""Immutable guest binding and private operation state; never stores requests."""
from pathlib import Path
import re
from .. import state as records
from ..contracts import fields, identity, integer, require

ROLES=frozenset(('connector','headscale','derp'))


def initialize(state, seed, machine_id):
    fields(seed,{'schema','plan_id','role','vmid'})
    require(seed['schema']==1 and seed['role'] in ROLES,'guest-binding')
    require(type(seed['plan_id']) is str and re.fullmatch(r'[0-9a-f]{64}',seed['plan_id']),'guest-binding')
    integer(seed['vmid'],100,999999999)
    require(type(machine_id) is str and re.fullmatch(r'[0-9a-f]{32}',machine_id) and machine_id!='0'*32,'guest-machine-identity')
    path=Path(state)/'binding.json';value={**seed,'machine_id':machine_id}
    with records.lock(Path(state)/'binding-lock'):
        if path.exists():
            current=records.read(path)
            require(current.get('machine_id')==machine_id,'guest-machine-identity-changed')
            require(current==value,'guest-binding')
        else:records.write(path,value)
    return value


def binding(state, request):
    record=records.read(Path(state)/'binding.json')
    require(record.get('schema')==1 and record.get('role')==request['role']
            and record.get('plan_id')==request['plan_id'],'guest-binding')
    return record


def bind_authority(state, role, authority):
    require(role in ROLES and type(authority) is dict,'guest-authority')
    path=Path(state)/role/'authority-binding.json';value={'schema':1,'identity':identity(authority)}
    with records.lock(Path(state)/'authority-lock'):
        if path.exists():require(records.read(path)==value,'guest-authority-change')
        else:records.write(path,value)
    return value


def inspect_runtime(state,runner):
    """Observe only fixed OS properties; callers compare against their plan."""
    import json
    from ..contracts import ApplianceError
    def output(argv):
        result=runner.run(argv,timeout_s=30)
        require(result.returncode==0 and len(result.stdout)<=256*1024,'guest-runtime-output')
        return result.stdout.decode('utf-8').strip()
    def number(path):
        value=output(['/usr/bin/cat',path]);require(value in ('0','1'),'guest-runtime-sysctl');return value=='1'
    try:
        addresses=json.loads(output(['/usr/sbin/ip','-j','address','show']))
        routes=json.loads(output(['/usr/sbin/ip','-j','-4','route','show','table','main']))
    except (ValueError,UnicodeError,RecursionError):raise ApplianceError('guest-runtime-network') from None
    require(type(addresses) is list and type(routes) is list,'guest-runtime-network')
    ssh=output(['/usr/bin/systemctl','show','--property=ActiveState','--property=UnitFileState','ssh.service','ssh.socket'])
    blocks=[dict(line.split('=',1) for line in block.splitlines() if '=' in line) for block in ssh.split('\n\n')]
    disabled_by_kernel='ipv6.disable=1' in output(['/usr/bin/cat','/proc/cmdline']).split()
    return {'image':records.read(Path(state)/'image.json'),'addresses':addresses,'routes':routes,
            'forwarding':number('/proc/sys/net/ipv4/ip_forward'),
            'ipv6_disabled':disabled_by_kernel or (number('/proc/sys/net/ipv6/conf/all/disable_ipv6') and number('/proc/sys/net/ipv6/conf/default/disable_ipv6')),
            'ssh_masked':len(blocks)==2 and all(b.get('ActiveState') in ('inactive','failed') and b.get('UnitFileState')=='masked' for b in blocks)}

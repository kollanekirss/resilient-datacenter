"""Verify staged bytes and recover local configuration before networking."""
from __future__ import annotations

import os
from pathlib import Path
import time

from appliance.contracts import ApplianceError, identity, load_json, require
from appliance.media import verify_file
from appliance.state import read, write
from .payload import owned_path


def network_dependencies() -> dict[str, bytes]:
    dependency = b'[Unit]\nRequires=rdc-first-boot.service\nAfter=rdc-first-boot.service\n'
    # Requires + After prevents start after a failed verifier (ordering alone
    # does not). The same guard covers direct service starts.
    return {'etc/systemd/system/' + name + '.service.d/10-rdc-first-boot.conf':dependency
            for name in ('networking','ssh','pveproxy','pvedaemon','pve-guests')}


def verify_staging(root: Path) -> dict:
    marker = owned_path(root,'var/lib/rdc-appliance/private/staged.json')
    require(marker.is_file(),'staging-incomplete')
    receipt = read(marker)
    require(set(receipt) == {'schema','complete','plan_id','build_id','target','root','files'}
            and receipt['schema'] == 1 and receipt['complete'] is True
            and type(receipt['files']) is list and 0 < len(receipt['files']) <= 512,'staging-incomplete')
    names = set()
    for item in receipt['files']:
        require(type(item) is dict and set(item) == {'relative_path','component'},'staging-receipt')
        relative = item['relative_path']
        path = owned_path(root,relative)
        require(relative.startswith(('usr/lib/rdc-appliance/','var/lib/rdc-appliance/media/',
                   'etc/systemd/system/')) or relative in ('var/lib/rdc-appliance/release.lock.json',
                   'var/lib/rdc-appliance/build.json','usr/local/sbin/rdc-appliance'), 'staging-path')
        require(relative not in names,'staging-duplicate')
        names.add(relative); verify_file(path,item['component'])
    require({'var/lib/rdc-appliance/media/opnsense-dvd','var/lib/rdc-appliance/media/probe-image',
             'var/lib/rdc-appliance/media/restic','var/lib/rdc-appliance/release.lock.json',
             'var/lib/rdc-appliance/build.json','etc/systemd/system/rdc-first-boot.service'} <= names,'staging-incomplete')
    build = load_json(owned_path(root,'var/lib/rdc-appliance/build.json'))
    release = load_json(owned_path(root,'var/lib/rdc-appliance/release.lock.json'))
    require(identity(build) == receipt['build_id'] and identity(release) == build.get('release_identity'), 'staging-build-mismatch')
    return receipt


def first_boot(root: Path, runner) -> None:
    receipt = verify_staging(root)
    from appliance.files import atomic_write
    from appliance.host_network import render_host, resolve_ports
    from appliance.rollback import recover_pending
    from appliance.plan import validate_site
    from .inventory import port_observations
    private = owned_path(root,'var/lib/rdc-appliance/private')
    recover_pending(root,runner,now=int(time.monotonic()),boot=True)
    plan = read(private / 'site.json')
    release = load_json(owned_path(root,'var/lib/rdc-appliance/release.lock.json'))
    validate_site(plan,release)
    initialized = private / 'first-boot.json'
    ports = resolve_ports(plan,port_observations(runner,root=root))
    if not initialized.exists():
        require(identity(plan) == receipt['plan_id'],'staging-plan-mismatch')
        for path,raw in render_host(plan,ports,management_only=True).items():
            require(not path.startswith('/etc/pve/'),'early-pve-dependency')
            atomic_write(root,path,raw)
        write(initialized,{'schema':1,'build_id':receipt['build_id'],'initial_plan_id':receipt['plan_id'],
                           'resolved_ports':ports})
    else:
        initialized_state = read(initialized)
        require(initialized_state.get('build_id') == receipt['build_id'],'first-boot-build-mismatch')
        good_path = private / 'network/known-good.json'
        saved_ports = read(good_path).get('resolved_ports') if good_path.exists() else initialized_state.get('resolved_ports')
        require(ports == saved_ports,'port-name-changed')
    # Apply the early guard before any management listener is allowed to start.
    # Later PVE activation is deliberately outside this pre-network service.
    runner.run(['/usr/sbin/sysctl','--ignore','--load','/etc/sysctl.d/90-rdc-appliance.conf'])
    runner.run(['/usr/sbin/nft','--check','--file','/etc/rdc-appliance/host-guard.nft'])
    runner.run(['/usr/sbin/nft','--file','/etc/rdc-appliance/host-guard.nft'])


if __name__ == '__main__':
    from appliance.runner import Runner
    try:
        require(os.geteuid() == 0,'root-required')
        first_boot(Path('/'),Runner())
    except (ApplianceError,OSError):
        # Never expose private stage receipts or command output in boot logs.
        raise SystemExit('Appliance startup stopped; use local repair.')

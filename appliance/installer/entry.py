"""Local live-media menu. No timed selection and no automatic retry."""
from __future__ import annotations

import getpass
import ipaddress
import json
import os
from pathlib import Path
import secrets

from appliance.contracts import ApplianceError, identity, load_json, require
from appliance.plan import validate_site
from appliance.runner import Runner
from appliance.state import write
from .inventory import inventory, port_observations, record_port_confirmation
from .live import install_site, live_environment
from .payload import verify_install_payload

PAYLOAD = Path('/cdrom/rdc-appliance')


def initialize(runner) -> tuple[dict,dict]:
    require(os.geteuid() == 0,'live-environment-required')
    cmdline = Path('/proc/cmdline').read_text().split()
    pid1 = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require('rdc.appliance=1' in cmdline and 'ipv6.disable=1' in cmdline
            and any(p in pid1 for p in (b'/sbin/unconfigured.sh',b'/usr/sbin/unconfigured.sh')), 'live-environment-required')
    release,build = verify_install_payload(PAYLOAD)
    for port in port_observations(runner):
        runner.run(['/usr/sbin/ip','link','set','dev',port['name'],'down'])
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    write(Path('/run/rdc-appliance/live.json'),{'schema':1,'boot_id':boot_id,'build_id':identity(build)})
    return release,build


def _choice(prompt, count):
    raw = input(prompt).strip()
    require(raw.isdigit() and 1 <= int(raw) <= count,'selection-cancelled')
    return int(raw)-1


def _mac():
    return '02:' + ':'.join(f'{b:02x}' for b in secrets.token_bytes(5))


def create_plan(release: dict, observed: dict) -> dict:
    """Prompt for physical identities and local networks; return a public plan."""
    disks = [d for d in observed['disks'] if d['identity']['by_id'] not in observed['boot_media_ids']
             and d['path'] not in observed['boot_media_ids'] and not d.get('removable')]
    require(bool(disks),'no-install-target')
    print('Internal disks (installation erases every partition on the selected disk):')
    for index,disk in enumerate(disks,1):
        print(index,json.dumps({'identity':disk['identity'],'partitions':disk.get('partitions',[])},sort_keys=True))
    disk = disks[_choice('Select disk number, or Enter to cancel: ',len(disks))]
    ports = observed['port_observations']; require(len(ports) >= 2,'two-wired-ports-required')
    print('Wired ports:')
    for index,port in enumerate(ports,1):
        print(index,json.dumps({k:port[k] for k in ('name','permanent_mac','pci_path','driver')},sort_keys=True))
    management = ports[_choice('Management port number: ',len(ports))]
    wan = ports[_choice('Internet/upstream port number: ',len(ports))]
    require(management['name'] != wan['name'],'duplicate-port')
    name = input('Appliance name [appliance]: ').strip() or 'appliance'
    zones = {}
    for role,bridge,default in (('management','vmbr0','10.77.0.0/24'),
              ('infrastructure','vmbr2','10.77.1.0/24'),('workload','vmbr3','10.77.2.0/24')):
        subnet = ipaddress.IPv4Network(input(f'{role} subnet [{default}]: ').strip() or default,strict=True)
        require(subnet.num_addresses >= 16,'subnet-too-small')
        zones[role] = {'bridge':bridge,'cidr':str(subnet),'gateway':str(subnet.network_address+1),
                       'allocation':'reservation' if role=='workload' else 'static'}
        if role == 'management':
            zones[role].update(host_ip=str(subnet.network_address+2),admin_ip=str(subnet.network_address+3))
    upstream = {'mode':'dhcp','cidrs':[]}
    upstream['cidrs'] = input('Known upstream IPv4 subnets, comma separated (blank if unknown): ').replace(' ','').split(',')
    upstream['cidrs'] = [c for c in upstream['cidrs'] if c]
    mode = input('Upstream mode [dhcp], or static: ').strip() or 'dhcp'
    require(mode in ('dhcp','static'),'upstream-mode')
    if mode == 'static':
        upstream.update(mode='static',address=input('Upstream address/prefix: ').strip(),
            gateway=input('Upstream gateway: ').strip(),dns=input('Upstream DNS addresses, comma separated: ').replace(' ','').split(','))
        prefix = str(ipaddress.IPv4Interface(upstream['address']).network)
        if prefix not in upstream['cidrs']: upstream['cidrs'].append(prefix)
    plan = {'schema':1,'site_id':name,'revision':1,'release_id':release['release_id'],
            'target':disk['identity'],'ports':{role:{k:p[k] for k in ('permanent_mac','pci_path','driver')}
                for role,p in (('management',management),('wan',wan))},
            'networks':zones,'upstream':upstream,'overlay_cidrs':['100.64.0.0/10'],
            'roles':{r:{'selected':False} for r in ('connector','headscale','derp')},'vms':{}}
    for role,vmid,attachments in (('router',101,('management','wan','infrastructure','workload')),('probe',102,('workload',))):
        plan['vms'][role] = {'role':role,'vmid':vmid,'name':name+'-'+role,'storage':'local-lvm',
            **release['budgets'][role],'nics':[{'zone':zone,'mac':_mac(),'connected':False} for zone in attachments]}
    plan['vms']['probe']['nics'][0]['address'] = str(ipaddress.IPv4Network(zones['workload']['cidr']).network_address+10)
    return validate_site(plan,release)


def repair_console() -> None:
    """Give the present operator a TTY; never execute a generated shell script.

    This explicitly selected local root console is also available after a failed
    installation. Exiting it returns to the menu, which keeps the erase latch.
    """
    require(live_environment(),'live-environment-required')
    require(os.isatty(0) and os.isatty(1),'repair-console-tty')
    print('Local USB recovery console. No disk was mounted or changed by opening it.')
    print('Inspect disks first. Mount only the existing appliance root at /target.')
    print('Use rdc-appliance repair inspect before restore-management.')
    print('Type exit to return to the menu. No installer starts automatically.')
    env = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'HOME':'/root','TERM':os.environ.get('TERM','linux'),
           'PYTHONPATH':'/usr/lib/rdc-appliance','PYTHONNOUSERSITE':'1',
           'HISTFILE':'/dev/null','PS1':'USB recovery (local root) # '}
    os.spawnve(os.P_WAIT,'/bin/bash',['/bin/bash','--noprofile','--norc','-i'],env)


def main() -> int:
    os.umask(0o077)
    runner = Runner(max_output_bytes=16 * 1024 * 1024)
    initialized = False
    try:
        release,_ = initialize(runner)
        initialized = True
        print('Two-port appliance installer — UNQUALIFIED CANDIDATE')
        while True:
            pending = Path('/run/rdc-appliance/install-started.json').exists()
            print('1 Install' + (' (disabled: installation already attempted)' if pending else ''))
            print('2 Repair / inspect then local console\n3 Exit setup to local console')
            selection = input('Select (no default): ').strip()
            if selection == '3':
                repair_console()
                continue
            if selection == '2':
                try:
                    observed = inventory(runner)
                    print(json.dumps({'disks':observed['disks'],'ports':observed['port_observations']},indent=2))
                except (ApplianceError,OSError,ValueError):
                    print('Automatic read-only inspection unavailable; inspect from the console.')
                repair_console()
                continue
            if selection != '1':
                print('No action selected.')
                continue
            if pending:
                print('Installation cannot be retried this boot. Select Repair for local inspection.')
                continue
            observed = inventory(runner)
            break
        supplied = input('Existing local plan path, or Enter for setup: ').strip()
        plan = validate_site(load_json(Path(supplied)),release) if supplied else create_plan(release,observed)
        print(json.dumps(plan,indent=2,sort_keys=True))
        for role in ('management','wan'):
            print(role + ' port: ' + json.dumps(plan['ports'][role],sort_keys=True))
            require(input(f'Check the physical port/cable, then type {role}: ').strip() == role,'port-identification-incomplete')
            record_port_confirmation(plan,role)
        require(input('Type UNQUALIFIED to acknowledge deferred boot/hardware testing: ').strip() == 'UNQUALIFIED',
                'qualification-build-required')
        typed = plan['target']['serial'] or plan['target']['wwn']
        require(input('ALL DATA on the selected disk will be erased. Type its serial/WWN: ').strip() == typed,'erase-not-confirmed')
        plan_id = identity(plan)
        print('Current plan: ' + plan_id)
        require(input('Type the complete current plan hash to confirm: ').strip() == plan_id,'erase-not-confirmed')
        password = getpass.getpass('New local root password (at least 12 characters): ')
        require(len(password) >= 12 and '\n' not in password and '\0' not in password,'password-policy')
        require(getpass.getpass('Repeat password: ') == password,'password-mismatch')
        hashed = runner.run(['/usr/bin/openssl','passwd','-6','-stdin'],stdin=(password+'\n').encode()).stdout.decode('ascii').strip()
        del password
        result = install_site(plan,PAYLOAD,plan_id,runner,password_hash=hashed,consent_boot_id=observed['boot_id'])
        print(json.dumps(result,indent=2))
        print('Installation is staged. Shut down, remove USB, and start the internal disk.')
        print('Management host: ' + plan['networks']['management']['host_ip'])
        print('Administrator computer: ' + plan['networks']['management']['admin_ip'] + ' on ' + plan['networks']['management']['cidr'])
        print('Verify the management certificate at the local installed console before first login.')
        repair_console()
        return 0
    except (ApplianceError,OSError,ValueError,EOFError,KeyboardInterrupt) as error:
        print('Stopped: ' + (error.code if isinstance(error,ApplianceError) else 'local-setup-cancelled-or-unavailable'))
        print('No automatic retry. An interrupted install requires local inspection.')
        if initialized:
            repair_console()
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

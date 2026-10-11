"""Executable, conservative base acceptance scenarios.

The driver owns disposable machines and emits *raw* command, disk, packet and
collector records. This module owns sequences and predicates; a driver cannot
supply a PASS bit. Every observation is bound to a fresh action in the current
run. External JSON is not an activation or release credential.

``run_case(case_id, driver, context)`` calls ``driver.execute_action(action,
parameters)``. Envelopes contain sequence, checked_at, dependencies, data and
actual evidence files. Fixed dependency keys are plan/build/spec/source/run;
runtime keys are collected from guests. Test drivers must set synthetic=True.
Observation data schemas are kept beside their consuming predicates below.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import struct
import time

from .contracts import ApplianceError, canonical, identity, require
from .host_network import audit_host, resolve_ports

REFUSALS = ('duplicate-identity','changed-capacity','hot-remove','spanning-storage',
            'non-target-pve','cancel','invalid-media','boot-media-target')
INTERRUPTIONS = ('install-staging','network-before-reload','network-after-reload',
                 'vm-create-response','vm-start-response','router-policy-response',
                 'router-link-response','repair-files')
PHYSICAL_CHECKLIST = (
    'independent-operator','written-guide-only','firmware-and-nic-identities',
    'usb-size-and-checksum','intentional-target-selection','cable-labels',
    'numeric-management-and-certificate','usb-removed-cold-boot',
    'usb-retained-no-reinstall','physical-wan-capture','console-rollback',
    'power-loss-recovery','encrypted-export-recovery','measured-resource-budgets',
)
_BASE = {
    'boot-menu-cancel': ('closed-grub-menu-observed','installer-menu-observed','blank-selection-keeps-menu',
        'explicit-recovery-console-observed','console-exit-returns-menu','target-unchanged','canary-unchanged',
        'readonly-inputs-unchanged','source-identity-unchanged'),
    'offline-install': ('install-completed','offline-no-fetch','canary-disk-unchanged',
        'usb-removed-disk-boot','usb-retained-no-reinstall','firstboot-failure-closed',
        'repair-disks-unchanged','resource-budgets-recorded'),
    'erase-refusals': tuple(v+'-'+x for v in REFUSALS for x in ('refused','disks-unchanged')),
    'port-mapping': ('stable-port-identity','reversed-enumeration','changed-nic-refused',
        'wrong-cable-refused','remote-management-confirmed','expired-management-rollback',
        'killed-management-rollback','cold-management-rollback','host-no-forwarding','host-no-nat'),
    'wan-exposure': ('early-host-wan-addresses','installed-host-wan-addresses','host-admin-denied',
        'router-admin-denied','physical-dhcp-absent','physical-ra-absent','ipv6-disabled'),
    'routed-policy': ('dns-management','dns-infrastructure','dns-workload',
        'ntp-management','ntp-infrastructure','ntp-workload','https-infrastructure','https-workload',
        'host-updates','management-admin','workload-host-admin-denied','workload-router-admin-denied',
        'infrastructure-router-admin-denied','workload-infrastructure-denied',
        'infrastructure-workload-denied','workload-management-denied'),
    'router-down-management': ('router-stopped','numeric-management','local-menu','transit-denied'),
    'no-wan-boot': ('new-host-boot','numeric-management','local-menu','local-dns','local-ntp','transit-denied'),
    'wan-return': ('first-overlap-denied','return-needs-fresh-gate','nonoverlap-transit',
        'renewal-overlap-denied','existing-state-withdrawn','management-preserved',
        'fresh-dns','fresh-ntp','fresh-https','router-reboot-withdraws-transit'),
    'interrupted-resume': tuple(stage+'-'+x for stage in INTERRUPTIONS for x in ('no-replay','settled')),
    'export-repair': ('encrypted-export','independent-password-restore','wrong-password-refused',
        'corrupt-export-refused','numeric-management-repaired','canary-disk-unchanged',
        'repair-target-preserved','clone-installed-boot','clone-config-imported',
        'clone-links-isolated','clone-stopped','original-router-unchanged'),
    'physical-operator': PHYSICAL_CHECKLIST,
}


def required_assertions(case_id):
    require(case_id in _BASE,'acceptance-case-unknown')
    return _BASE[case_id] + (() if case_id in ('physical-operator','boot-menu-cancel') else ('fresh-observations',))


def _digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def _identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value) is not None


def _command(value):
    return (type(value) is dict and type(value.get('returncode')) is int
            and type(value.get('stdout')) is str and type(value.get('stderr')) is str)


def _success(value):
    return (type(value) is dict and type(value.get('returncode')) is int and value['returncode']==0
            and (_command(value) or type(value.get('result')) is dict))


def _json_command(value):
    if type(value) is dict and type(value.get('returncode')) is int and type(value.get('result')) is dict:
        return value['result']
    if not _command(value): return {}
    try:
        data=json.loads(value['stdout'])
        return data if type(data) is dict else {}
    except (ValueError,TypeError): return {}


def _refused(value, codes):
    return (type(value) is dict and type(value.get('returncode')) is int and value['returncode'] != 0
            and _json_command(value).get('error') in codes)


def probe_result(raw, *, nonce, allowed, tls=False):
    """Require live controls at both ends, tied to this exact probe challenge.

    A control command's complete stdout is the challenge returned by its live
    listener. The attempted route is a separate command. DNS/NTP wire parsers
    below additionally validate protocol replies; TLS verifies the peer cert.
    """
    if type(raw) is not dict or raw.get('nonce') != nonce or type(allowed) is not bool:
        return False
    for key in ('source_control','destination_control'):
        item=raw.get(key)
        if not _success(item) or item['stdout'].strip() != nonce: return False
    attempt=raw.get('attempt')
    if not _command(attempt): return False
    try:
        ipaddress.ip_address(raw['source']); ipaddress.ip_address(raw['destination'])
        if type(raw['port']) is not int or not 1 <= raw['port'] <= 65535: return False
    except (ValueError,TypeError,KeyError): return False
    if allowed:
        if not _success(attempt) or attempt['stdout'].strip() != nonce: return False
        if tls:
            cert=raw.get('tls',{})
            if (type(cert) is not dict or type(cert.get('verify_returncode')) is not int
                    or cert['verify_returncode'] != 0 or not _digest(cert.get('peer_certificate_sha256'))): return False
        return True
    return (attempt['returncode'] in (7,28,110,111,124) and not attempt['stdout'].strip()
            and raw.get('connected') is False and raw.get('error') in ('timeout','connection-refused'))


def admin_probe_result(raw,*,nonce,targets,allowed):
    if type(raw) is not dict or raw.get('nonce')!=nonce: return False
    checks=raw.get('admin_checks')
    if type(checks) is not list or len(checks)!=len(targets): return False
    if any(type(c) is not dict for c in checks) or {c.get('target') for c in checks}!=targets: return False
    def live(value,pin):
        return (type(value) is dict and value.get('nonce')==nonce and value.get('connected') is True
                and value.get('error') is None and value.get('protocol')=='https'
                and value.get('certificate_valid') is True and value.get('certificate_sha256')==pin
                and type(value.get('http_status')) is int and 100<=value['http_status']<=599)
    for item in checks:
        pin=item.get('expected_certificate_sha256');source=item.get('source_control');dest=item.get('destination_control')
        if not _digest(pin) or not _success(source) or source.get('stdout','').strip()!=nonce or not live(dest,pin): return False
        attempt=item.get('attempt')
        if allowed:
            if not live(attempt,pin): return False
        elif (type(attempt) is not dict or attempt.get('nonce')!=nonce or attempt.get('connected') is not False
                or attempt.get('error') not in ('timeout','connection-refused')): return False
        if attempt.get('destination')!=dest.get('destination') or attempt.get('port')!=dest.get('port'): return False
    return True


def _disk_boot(raw,context):
    root=_json_command(raw.get('root'))
    filesystems=root.get('filesystems');staged=raw.get('staged')
    return (type(filesystems) is list and len(filesystems)==1 and type(filesystems[0]) is dict
            and filesystems[0].get('fstype')=='ext4' and filesystems[0].get('target')=='/'
            and filesystems[0].get('source') in ('/dev/mapper/pve-root','/dev/pve/root')
            and type(raw.get('cmdline')) is str and 'rdc.appliance=1' not in raw['cmdline'].split()
            and type(staged) is dict and staged.get('complete') is True
            and staged.get('plan_id')==context['plan_id'] and staged.get('build_id')==context['build_id'])


def _local_menu(raw):
    session=raw.get('session',{});menu=raw.get('menu')
    return (type(session) is dict and session.get('euid')==0 and session.get('tty') is True
            and _success(menu) and 'Choose an action:' in menu.get('stdout','')
            and re.search(r'"state"\s*:\s*"exited"',menu['stdout']) is not None)


def _usb_boot(raw):
    serial=raw.get('serial_menu');cmdline=raw.get('cmdline')
    filesystems=_json_command(raw.get('root')).get('filesystems')
    return (type(serial) is str and 'Select (no default): ' in serial and 'No action selected.' in serial
            and type(cmdline) is str and 'rdc.appliance=1' in cmdline.split()
            and type(filesystems) is list and len(filesystems)==1 and type(filesystems[0]) is dict
            and filesystems[0].get('target')=='/' and filesystems[0].get('fstype') in ('overlay','squashfs','tmpfs'))


def _units(raw):
    command=raw.get('services')
    if not _success(command):return {}
    units={}
    for group in command['stdout'].split('\n\n'):
        values=dict(line.split('=',1) for line in group.splitlines() if '=' in line)
        if 'Id' in values:units[values['Id']]=values
    return units


def _firstboot_closed(raw,plan):
    units=_units(raw);first=units.get('rdc-first-boot.service',{})
    interfaces=raw.get('interfaces',{});links=interfaces.get('links') if type(interfaces) is dict else None
    if type(links) is not list or any(type(link) is not dict for link in links):return False
    wan=plan['ports']['wan']['permanent_mac']
    external={n['bridge'] for role,n in plan['networks'].items() if role!='management'}|{'vmbr1'}
    relevant=[link for link in links if link.get('address')==wan or link.get('ifname') in external]
    return (first.get('ExecMainStatus') not in (None,'0') and first.get('ActiveState')=='failed'
            and any(link.get('address')==wan for link in relevant)
            and all(type(link.get('flags')) is list and 'UP' not in link['flags'] for link in relevant)
            and all(units.get(name,{}).get('ActiveState') in ('inactive','failed') for name in ('ssh.service','pveproxy.service')))


def _pending(raw):
    result=_json_command(raw) if 'returncode' in raw else raw
    if result.get('phase') in ('pending','confirmed','rolled-back'):
        tx=result.get('transaction_id')
        return result if type(tx) is str and re.fullmatch(r'[0-9a-f]{48}|[0-9a-f]{64}',tx) else {}
    records=result.get('records',{})
    return records.get('network/pending.json',{}) if type(records) is dict else {}


def _network_confirmed(raw,journal):
    receipt=_pending(raw);observed=_pending(journal)
    return (_success(raw) and receipt.get('phase')=='confirmed' and observed.get('phase')=='confirmed'
            and receipt.get('transaction_id')==observed.get('transaction_id'))


def _wrong_cable_refused(raw):
    receipt=_json_command(raw);ssh=receipt.get('ssh',{})
    return (_refused(raw,{'management-session-required'}) and receipt.get('phase')=='pending'
            and type(ssh) is dict and type(ssh.get('returncode')) is int and ssh['returncode']!=0)


def _independent_credential(sealed,opened):
    return (all(type(raw) is dict and raw.get('credential_source')=='independently-held'
                and raw.get('guest_credential_removed') is True and _digest(raw.get('credential_sha256'))
                for raw in (sealed,opened))
            and sealed['credential_sha256']==opened['credential_sha256'])


def dns_result(query_hex,response_hex,*,name,address):
    """Use the same bounded A-record parser as the executing wire client."""
    try:
        from .lab_probe import parse_dns
        parsed=parse_dns(bytes.fromhex(response_hex),bytes.fromhex(query_hex))
        return parsed['question']==name.lower().rstrip('.') and parsed['addresses']==[str(ipaddress.IPv4Address(address))]
    except (ValueError,TypeError,KeyError,UnicodeError,struct.error): return False


def ntp_result(query_hex,response_hex):
    """Prove a responding NTP service; this deliberately does not certify UTC."""
    try:
        query=bytes.fromhex(query_hex); response=bytes.fromhex(response_hex)
        return (len(query)==48 and 48<=len(response)<=512 and query[0]&7==3
            and response[0]&7==4 and 3<=((response[0]>>3)&7)<=4
            and 1<=response[1]<=16
            and query[40:48]!=b'\0'*8 and response[24:32]==query[40:48]
            and response[40:48]!=b'\0'*8)
    except (ValueError,TypeError,IndexError): return False


def _disks(raw):
    disks=raw.get('sha256') if type(raw) is dict else None
    return disks if (type(disks) is dict and {'target','canary'} <= set(disks)
                     and all(_identifier(k) and _digest(v) for k,v in disks.items())) else None


def _same_disks(before,after,*,canary_only=False):
    a,b=_disks(before),_disks(after)
    if a is None or b is None or set(a)!=set(b): return False
    names=set(a)-{'target'} if canary_only else set(a)
    return bool(names) and all(a[name]==b[name] for name in names)


def _wan_address_samples(raw,plan):
    """Raw sampled ip-address output plus complete capture interval bounds."""
    if type(raw) is not dict: return False
    samples=raw.get('samples'); span=raw.get('capture_interval')
    if (type(samples) is not list or len(samples)<2 or type(span) is not list or len(span)!=2
            or not all(type(v) in (int,float) for v in span) or not span[0]<span[1]): return False
    previous=span[0]
    for sample in samples:
        if type(sample) is not dict or not previous<=sample.get('at',-1)<=span[1]: return False
        previous=sample['at']; interfaces=sample.get('interfaces')
        if type(interfaces) is not dict or not {'wan','wan_bridge'}<=set(interfaces): return False
        if any(interfaces[key] != [] for key in ('wan','wan_bridge')): return False
    capture=_capture(raw,plan)
    start,boot,end=raw.get('capture_started_at'),raw.get('boot_started_at'),raw.get('capture_ended_at')
    return (samples[0]['at']==span[0] and samples[-1]['at']==span[1]
            and all(type(v) is int for v in (start,boot,end)) and start<=boot<=span[0]<=span[1]<=end
            and capture is not None and capture['malformed']==0 and capture['frames']>0
            and capture['host_dhcp']==capture['host_ipv6']==0
            and not any(p['zone']=='wan' and p['source_mac'] in {port['permanent_mac'] for port in plan['ports'].values()}
                        and p.get('source_ip') not in (None,'0.0.0.0') for p in capture['packets']))


class _Session:
    def __init__(self,case,driver,context,clock):
        self.case,self.driver,self.context,self.clock=case,driver,context,clock
        self.sequence=0; self.evidence={}; self.observations=[]; self.reasons=[]
        self.assertions={name:False for name in required_assertions(case)}
        self.dependencies={key:context[source] for key,source in (
            ('plan','plan_id'),('build','build_id'),('spec','spec_id'),('source','source_id'),('run','run_id'))}
        self.fixed=dict(self.dependencies); self.started=False
    def call(self,action,**parameters):
        start=int(self.clock()); self.started=True
        raw=self.driver.execute_action(action,parameters)
        end=int(self.clock())
        require(type(raw) is dict,'acceptance-observation-missing')
        seq=raw.get('sequence'); checked=raw.get('checked_at'); deps=raw.get('dependencies')
        require(type(seq) is int and seq>self.sequence,'acceptance-observation-sequence')
        require(type(checked) is int and start<=checked<=end and 0<=end-checked<=30,
                'acceptance-observation-stale')
        require(type(deps) is dict and all(deps.get(k)==v for k,v in self.fixed.items())
                and _identifier(deps.get('host_boot'))
                and all(_identifier(k) and _identifier(v) for k,v in deps.items()),
                'acceptance-observation-dependencies')
        data=raw.get('data'); require(type(data) is dict and 'passed' not in data,'acceptance-raw-observation-required')
        evidence=raw.get('evidence'); require(type(evidence) is list and evidence,'acceptance-evidence-missing')
        for item in evidence:
            require(type(item) is dict and set(item)=={'path','sha256'} and type(item['path']) is str
                    and item['path'].startswith('/') and _digest(item['sha256']),'acceptance-evidence-invalid')
            require(item['path'] not in self.evidence or self.evidence[item['path']]==item['sha256'],
                    'acceptance-evidence-replaced')
            self.evidence[item['path']]=item['sha256']
        self.sequence=seq; self.dependencies=dict(deps)
        self.observations.append({'sequence':seq,'action':action,'parameters':parameters,
            'checked_at':checked,'dependencies':dict(deps),'data_sha256':hashlib.sha256(canonical(data)).hexdigest()})
        return data
    def check(self,name,value):
        require(name in self.assertions,'acceptance-unexpected-assertion')
        self.assertions[name]=value is True
    def prepare(self,profile,variant='normal',**parameters):
        return self.call('prepare',profile=profile,variant=variant,**parameters)
    def observe(self,kind,**parameters): return self.call('observe',kind=kind,**parameters)
    def probe(self,name,kind,*,allowed=True,tls=False,**parameters):
        nonce=secrets.token_hex(16)
        raw=self.call('probe',kind=kind,nonce=nonce,**parameters)
        if kind in ('management','wan-admin','zone-admin'):
            target=parameters.get('target','host');targets={'host','router'} if target=='both' else {target}
            valid=admin_probe_result(raw,nonce=nonce,targets=targets,allowed=allowed)
        else:valid=probe_result(raw,nonce=nonce,allowed=allowed,tls=tls)
        self.check(name,valid); return raw
    def service(self,name,kind,zone,*,local=False):
        nonce=secrets.token_hex(16)
        query_name=(self.context['plan']['vms']['probe']['name']+'.internal') if local else nonce+'.lab.invalid'
        options={'query_name':query_name} if kind=='dns' else {}
        raw=self.call('probe',kind=kind,zone=zone,nonce=nonce,**options)
        controls=probe_result(raw,nonce=nonce,allowed=True)
        if kind=='dns':
            expected=(self.context['plan']['vms']['probe']['nics'][0]['address'] if local else
                      str(ipaddress.IPv4Network(self.context['plan']['upstream']['cidrs'][0]).network_address+1))
            valid=dns_result(raw.get('query_hex'),raw.get('response_hex'),name=query_name,address=expected)
        else:
            query=raw.get('query_hex','')
            valid=ntp_result(query,raw.get('response_hex')) and query[80:96]==hashlib.sha256(nonce.encode()).digest()[:8].hex()
        self.check(name,controls and valid)
    def command(self,action,kind,**parameters): return self.call(action,kind=kind,**parameters)


def _boot(s):
    s.prepare('live');before=s.observe('disks');startup=s.observe('startup');after=s.observe('disks')
    serial=startup.get('serial_menu','');serial=serial if type(serial) is str else ''
    s.check('closed-grub-menu-observed','Appliance local setup (serial console)' in serial)
    s.check('installer-menu-observed','Select (no default): ' in serial)
    blank=serial.find('No action selected.')
    s.check('blank-selection-keeps-menu',blank>=0 and 'Select (no default): ' in serial[blank:])
    recovery=serial.find('USB recovery (local root) # ')
    s.check('explicit-recovery-console-observed',recovery>=0 and 'Local USB recovery console.' in serial[:recovery])
    s.check('console-exit-returns-menu',recovery>=0 and 'exit' in serial[recovery:]
            and 'Select (no default): ' in serial[recovery:])
    first,last=_disks(before),_disks(after)
    for role in ('target','canary'):
        s.check(role+'-unchanged',first is not None and last is not None and first.get(role)==last.get(role))
    pins=after.get('readonly_inputs',{})
    s.check('readonly-inputs-unchanged',type(pins) is dict and set(pins)=={'installer','target','canary','uefi_code','uefi_vars'}
            and all(type(pin) is dict and _digest(pin.get('initial')) and pin.get('initial')==pin.get('final') for pin in pins.values()))
    s.check('source-identity-unchanged',startup.get('source_identity')==s.context['source_id'])


def _erase(s):
    codes={
        'duplicate-identity':{'target-identity-ambiguous','target-identity-changed-or-ambiguous'},
        'changed-capacity':{'target-identity-changed','target-identity-changed-or-ambiguous'},
        'hot-remove':{'target-identity-missing','target-identity-changed-or-ambiguous'},
        'spanning-storage':{'storage-conflict','unsafe-storage-layout','non-target-storage-conflict'},
        'non-target-pve':{'storage-conflict','unsafe-storage-layout','non-target-storage-conflict'},
        'cancel':{'erase-not-confirmed','selection-cancelled'},
        'invalid-media':{'payload-invalid','artifact-digest-mismatch','payload-file-mismatch','unsupported-schema'},
        'boot-media-target':{'target-is-boot-media'},
    }
    for variant in REFUSALS:
        s.prepare('live',variant); before=s.observe('disks')
        response=s.command('fault','erase-refusal',variant=variant)
        after=s.observe('disks')
        s.check(variant+'-refused',_refused(response,codes[variant]))
        s.check(variant+'-disks-unchanged',_same_disks(before,after))


def _offline(s):
    s.prepare('live'); before=s.observe('disks')
    disconnected=s.command('fault','wan-remove')
    installed=s.command('recover','install');receipt=_json_command(installed)
    staged=installed.get('staged',{});inventory=installed.get('inventory',{})
    s.check('install-completed',_success(installed) and receipt.get('state')=='staged'
            and receipt.get('plan_id')==s.context['plan_id'] and type(staged) is dict
            and staged.get('complete') is True and staged.get('target')==s.context['plan']['target']
            and staged.get('plan_id')==s.context['plan_id'] and staged.get('build_id')==receipt.get('build_id'))
    s.check('offline-no-fetch',disconnected.get('link')=='down'
            and type(inventory) is dict and inventory.get('addresses',{}).get('wan')==[]
            and _success(installed) and receipt.get('state')=='staged')
    s.check('canary-disk-unchanged',_same_disks(before,s.observe('disks'),canary_only=True))
    old=s.dependencies['host_boot']; s.call('reboot',target='host',usb='absent')
    boot=s.observe('startup')
    s.check('usb-removed-disk-boot',s.dependencies['host_boot']!=old and _disk_boot(boot,s.context))
    s.call('reboot',target='host',usb='present'); kept=s.observe('startup')
    s.check('usb-retained-no-reinstall',_usb_boot(kept))
    hashes=s.observe('disks'); repair=s.command('recover','usb-management',mode='inspect-only')
    s.check('repair-disks-unchanged',_success(repair) and _same_disks(hashes,s.observe('disks')))
    s.command('fault','interrupt',stage='firstboot-marker'); s.call('reboot',target='host',usb='absent')
    s.check('firstboot-failure-closed',_firstboot_closed(s.observe('startup'),s.context['plan']))
    samples=installed.get('resource_samples',[])
    s.check('resource-budgets-recorded',type(samples) is list and len(samples)>=2
            and all(type(item) is dict and type(item.get('memory_used_mib')) is int and item['memory_used_mib']>0 for item in samples)
            and any(type(item.get('disk_used_bytes')) is int and item['disk_used_bytes']>0 for item in samples)
            and installed.get('sample_interval_seconds')==1
            and installed.get('planned_vm_allocations')=={name:{key:vm[key] for key in ('memory_mib','vcpus','disk_gib')}
                for name,vm in s.context['plan']['vms'].items()}
            and type(installed.get('reserved_host_budget')) is dict)


def _ports(s):
    s.prepare('routed'); host=s.observe('host'); plan=s.context['plan']
    s.check('stable-port-identity',not audit_host(plan,host))
    s.check('host-no-forwarding',host.get('forwarding') is False)
    s.check('host-no-nat',host.get('nat_active') is False)
    previous=host.get('resolved_ports')
    s.command('recover','export');s.command('recover','open-export',credential='independently-held')
    s.command('fault','nic-order'); s.call('reboot',target='host',usb='absent')
    stopped=s.observe('startup')
    s.call('reboot',target='host',usb='present')
    repaired=s.command('recover','usb-management',mode='restore');repair=_json_command(repaired)
    s.call('reboot',target='host',usb='absent')
    confirmed=s.command('recover','management-rollback',mode='confirm')
    reordered=s.observe('host')
    try:
        mapped=resolve_ports(plan,stopped.get('ports'))
        identity_ok=(not audit_host(plan,reordered) and mapped==reordered.get('resolved_ports')
                     and resolve_ports(plan,reordered.get('ports'))==mapped)
        renamed=previous!=mapped
    except (ApplianceError,TypeError,KeyError): identity_ok=renamed=False
    s.check('reversed-enumeration',identity_ok and renamed and _firstboot_closed(stopped,plan)
            and _success(repaired) and repair.get('state')=='configured' and repair.get('network_activated') is False)
    s.check('remote-management-confirmed',_network_confirmed(confirmed,s.observe('journal')))
    for mode,name in (('expire','expired'),('kill','killed'),('cold-reboot','cold')):
        s.command('fault','management-break',mode=mode)
        restored=s.command('recover','management-rollback',mode=mode)
        value=_pending(restored)
        s.check(name+'-management-rollback',_success(restored) and value.get('phase')=='rolled-back'
                and not audit_host(plan,s.observe('host')))

    s.check('changed-nic-refused',_refused(s.command('fault','replace-nic'),{'port-identity-unresolved','port-identity-changed','port-identity-ambiguous','port-remapping-required'}))
    s.prepare('live');s.prepare('installed')
    wrong=s.command('fault','wrong-cable')
    s.check('wrong-cable-refused',_wrong_cable_refused(wrong))


def _exposure(s):
    s.prepare('live')
    s.check('early-host-wan-addresses',_wan_address_samples(s.call('probe',kind='host-wan-addresses',phase='live'),s.context['plan']))
    s.command('recover','install'); s.prepare('routed')
    s.check('installed-host-wan-addresses',_wan_address_samples(s.call('probe',kind='host-wan-addresses',phase='installed'),s.context['plan']))
    s.probe('host-admin-denied','wan-admin',target='host',allowed=False)
    s.probe('router-admin-denied','wan-admin',target='router',allowed=False)
    wire=s.call('probe',kind='physical-dhcp-ra',nonce=secrets.token_hex(16))
    dhcp_absent,ra_absent=physical_capture(wire,s.context['plan'])
    s.check('physical-dhcp-absent',dhcp_absent)
    s.check('physical-ra-absent',ra_absent)
    host=s.observe('host'); router=s.observe('router')
    s.check('ipv6-disabled',host.get('ipv6_disabled') is True and router.get('runtime',{}).get('ipv6_enabled') is False
            and router.get('runtime',{}).get('ra_interfaces')==[])


def _capture(raw,plan):
    from .lab_probe import parse_frames
    if type(raw) is not dict or type(raw.get('frames')) is not list:return None
    hosts=[p['permanent_mac'] for p in plan['ports'].values()]
    routers=[n['mac'] for n in plan['vms']['router']['nics']]
    try:
        frames=[frame for frame in raw['frames'] if type(frame) is dict and frame.get('zone') in ('management','wan')]
        if len(frames)!=len(raw['frames']):return None
        return parse_frames(frames,host_macs=hosts,router_macs=routers)
    except (ValueError,TypeError,KeyError):return None


def physical_capture(raw,plan):
    """Both physical taps need live controls; malformed/empty captures fail."""
    capture=_capture(raw,plan);controls=raw.get('control_macs',[])
    owned={p['permanent_mac'] for p in plan['ports'].values()}|{n['mac'] for n in plan['vms']['router']['nics']}
    duration=raw.get('capture_seconds')
    if (capture is None or capture['malformed'] or type(duration) not in (int,float) or duration<10
            or type(controls) is not list or not controls or any(not isinstance(c,str) or c in owned for c in controls)):
        return False,False
    packets=capture['packets']
    for zone in ('wan','management'):
        if not (any(p['zone']==zone and p['source_mac'] in controls and p.get('dhcp_type')==2 for p in packets)
                and any(p['zone']==zone and p['source_mac'] in controls and p.get('ra') is True for p in packets)):
            return False,False
    return capture['router_dhcp_server']==0, capture['router_ra']==0


def _routed(s):
    s.prepare('routed')
    for kind in ('dns','ntp'):
        for zone in ('management','infrastructure','workload'): s.service(kind+'-'+zone,kind,zone)
    for zone in ('infrastructure','workload'): s.probe('https-'+zone,'https',zone=zone,tls=True)
    s.probe('host-updates','https',zone='host',tls=True)
    s.probe('management-admin','management',target='both')
    for zone,target in (('workload','host'),('workload','router'),('infrastructure','router')):
        s.probe(zone+'-'+target+'-admin-denied','zone-admin',zone=zone,target=target,allowed=False)
    for source,destination in (('workload','infrastructure'),('infrastructure','workload'),('workload','management')):
        s.probe(source+'-'+destination+'-denied','cross-zone',source=source,destination=destination,allowed=False)


def _router_down(s):
    s.prepare('routed'); s.command('fault','router-stop'); observed=s.observe('router')
    s.check('router-stopped',observed.get('vm',{}).get('running') is False and observed.get('vm',{}).get('boot_id') is None)
    s.probe('numeric-management','management',target='host',numeric=True)
    menu=s.observe('startup'); s.check('local-menu',_local_menu(menu))
    s.probe('transit-denied','https',zone='workload',allowed=False)


def _no_wan(s):
    s.prepare('routed'); s.command('fault','wan-remove'); before=s.dependencies['host_boot']
    s.call('reboot',target='host',usb='absent'); after=s.observe('startup')
    s.check('new-host-boot',before!=s.dependencies['host_boot'] and _disk_boot(after,s.context))
    s.probe('numeric-management','management',target='host',numeric=True)
    s.check('local-menu',_local_menu(after))
    s.service('local-dns','dns','management',local=True); s.service('local-ntp','ntp','management')
    s.probe('transit-denied','https',zone='workload',allowed=False)


def _wan_return(s):
    s.prepare('routed',bootstrap_only=True); s.command('fault','wan-overlap-first')
    s.probe('first-overlap-denied','https',zone='workload',allowed=False)
    s.command('recover','wan-return')
    s.probe('return-needs-fresh-gate','https',zone='workload',allowed=False)
    s.command('recover','explicit-transit')
    s.probe('nonoverlap-transit','https',zone='workload',tls=True)
    open_nonce=secrets.token_hex(16)
    established=s.call('probe',kind='forwarding-state',operation='open',nonce=open_nonce)
    s.command('fault','wan-overlap-renew')
    s.probe('renewal-overlap-denied','https',zone='workload',allowed=False)
    check_nonce=secrets.token_hex(16)
    stale=s.call('probe',kind='forwarding-state',operation='check',connection=established.get('connection'),nonce=check_nonce)
    s.check('existing-state-withdrawn',_success(established.get('before')) and established.get('before',{}).get('stdout')==open_nonce and established.get('nonce')==open_nonce
            and type(established.get('connection')) is str and stale.get('connection')==established['connection']
            and _command(stale.get('after')) and stale['after']['returncode'] in (1,7,28,110,111,124)
            and stale['after']['stdout']=='' and stale.get('pf_state_matches')==[]
            and _success(stale.get('control')) and stale['control']['stdout']==check_nonce and stale.get('nonce')==check_nonce)
    s.probe('management-preserved','management',target='both',numeric=True)
    s.command('recover','wan-return'); s.command('recover','explicit-transit')
    s.service('fresh-dns','dns','workload'); s.service('fresh-ntp','ntp','workload')
    s.probe('fresh-https','https',zone='workload',tls=True)
    old=s.dependencies.get('router_boot'); s.call('reboot',target='router',usb='absent')
    raw=s.probe('router-reboot-withdraws-transit','https',zone='workload',allowed=False)
    s.check('router-reboot-withdraws-transit',s.assertions['router-reboot-withdraws-transit']
            and old is not None and s.dependencies.get('router_boot') not in (None,old))


def _interrupted(s):
    for stage in INTERRUPTIONS:
        s.prepare('live')
        if stage!='install-staging':s.prepare('routed')
        if stage=='repair-files':
            s.command('recover','export');s.command('recover','open-export',credential='independently-held')
            s.call('reboot',target='host',usb='present')
        s.command('fault','interrupt',stage=stage)
        before=s.observe('journal',stage=stage)
        result=s.command('recover','resume',stage=stage)
        after=s.observe('journal',stage=stage)
        counts=before.get('mutation_counts'); current=after.get('mutation_counts')
        s.check(stage+'-no-replay',type(counts) is dict and bool(counts) and counts==current
                and all(type(v) is int and v>=0 for v in counts.values())
                and before.get('operation_id')==after.get('operation_id') and _digest(before.get('operation_id')))
        outcome=_json_command(result)
        # Some interruptions intentionally require operator inspection. A
        # correctly retained pending state is a settled *safety* result only
        # with exact current observation and a bounded, explicit next action.
        s.check(stage+'-settled',outcome.get('state') in ('reconciled','recovered','inspection-required')
                and after.get('phase') in ('complete','recovered','pending')
                and _digest(after.get('observed_resource_sha256'))
                and (outcome['state']!='inspection-required' or type(outcome.get('next_action')) is str and bool(outcome['next_action'])))


def _export_repair(s):
    from .export import COMPONENTS
    s.prepare('routed'); initial=s.observe('disks')
    exported=s.command('recover','export');manifest=_json_command(exported)
    s.check('encrypted-export',_success(exported) and manifest.get('state')=='sealed'
            and _digest(manifest.get('ciphertext_sha256')) and _digest(manifest.get('snapshot_id'))
            and manifest.get('restored_bytes')=='verified')
    opened=s.command('recover','open-export',credential='independently-held');recovered=_json_command(opened)
    components=opened.get('component_sha256',{})
    s.check('independent-password-restore',_success(opened) and recovered.get('state')=='inspected'
            and set(recovered.get('files',[]))==COMPONENTS and recovered.get('services')=='not-started'
            and type(components) is dict and set(components)==COMPONENTS and all(_digest(v) for v in components.values())
            and _independent_credential(exported,opened))
    s.check('wrong-password-refused',_refused(s.command('fault','wrong-export-password'),{'restic-command-failed','export-decryption-failed','export-command-failed'}))
    s.check('corrupt-export-refused',_refused(s.command('fault','corrupt-export'),{'export-ciphertext-mismatch','export-ciphertext-changed','export-manifest-mismatch','restic-command-failed','export-command-failed'}))
    s.command('fault','corrupt-management'); s.call('reboot',target='host',usb='present')
    repair=s.command('recover','usb-management',mode='restore');value=_json_command(repair)
    before=repair.get('target_before',{});after=repair.get('target_after',{})
    s.check('repair-target-preserved',_success(repair) and value.get('state')=='configured'
            and value.get('network_activated') is False and type(before) is dict and before==after
            and before.get('target')==s.context['plan']['target'] and type(before.get('root')) is dict
            and all(type(before['root'].get(key)) is str and before['root'][key] for key in ('filesystem_uuid','pv_uuid','lv_uuid')))
    s.call('reboot',target='host',usb='absent')
    s.probe('numeric-management-repaired','management',target='host',numeric=True)
    # Recovery intentionally copies a stopped source; observe after that
    # deliberate shutdown so its original configuration remains comparable.
    s.command('fault','router-stop');original=s.observe('router')
    clone=s.command('recover','isolated-clone');receipt=_json_command(clone)
    actual=s.observe('clone');after=s.observe('router');proofs=receipt.get('proofs',[])
    complete=(type(proofs) is list and len(proofs)==2 and all(type(p) is dict for p in proofs)
              and {p.get('stage') for p in proofs}=={'import','verify'})
    verify=next((p for p in proofs if type(p) is dict and p.get('stage')=='verify'),{})
    s.check('clone-installed-boot',_success(clone) and complete and verify.get('root_kind')=='installed-disk'
            and verify.get('version')=='26.7' and verify.get('hook_removed') is True
            and actual.get('config',{}).get('boot')=='order=scsi0' and 'ide2' not in actual.get('config',{}))
    s.check('clone-config-imported',complete and _digest(components.get('router.xml'))
            and all(p.get('config_sha256')==components['router.xml'] for p in proofs))
    config=actual.get('config',{});links={key:value for key,value in config.items() if re.fullmatch(r'net[0-9]+',key)}
    bridge='rdcr'+str(receipt.get('clone_vmid'))
    s.check('clone-links-isolated',receipt.get('network')=='isolated-bridge-all-links-down'
            and receipt.get('bridge_removed') is True and bool(links)
            and all(type(value) is str and ('bridge='+bridge) in value.split(',')
                    and 'link_down=1' in value.split(',') and 'firewall=1' in value.split(',') for value in links.values()))
    s.check('clone-stopped',actual.get('running') is False and actual.get('pid') is None
            and config.get('onboot')=='0' and receipt.get('activation')=='forbidden' and receipt.get('clone_stopped') is True)
    s.check('original-router-unchanged',_digest(original.get('config_sha256'))
            and original.get('config_sha256')==after.get('config_sha256')
            and original.get('identity_sha256')==after.get('identity_sha256')
            and _digest(original.get('identity_sha256')) and after.get('vm',{}).get('running') is False)
    s.check('canary-disk-unchanged',_same_disks(initial,s.observe('disks'),canary_only=True))


_CASES={'boot-menu-cancel':_boot,'offline-install':_offline,'erase-refusals':_erase,'port-mapping':_ports,
        'wan-exposure':_exposure,'routed-policy':_routed,'router-down-management':_router_down,
        'no-wan-boot':_no_wan,'wan-return':_wan_return,'interrupted-resume':_interrupted,
        'export-repair':_export_repair}


def run_case(case_id,driver,context,*,clock=time.time):
    """Run all subordinate exercises; a missing observation is always failure.

    Physical operator evidence is intentionally not synthesised. Machine tests
    emit test_only according to the real boundary; synthetic tests remain NOT
    RUN even when their local assertions pass.
    """
    require(case_id in _BASE,'acceptance-case-unknown')
    require(type(context) is dict and all(_digest(context.get(k)) for k in ('plan_id','build_id','spec_id','source_id'))
            and _digest(context.get('run_id')) and type(context.get('plan')) is dict
            and identity(context['plan'])==context['plan_id'],'acceptance-context-invalid')
    s=_Session(case_id,driver,context,clock)
    synthetic=getattr(driver,'synthetic',True) is not False
    if case_id=='physical-operator': s.reasons.append('physical-operator-required')
    else:
        try:
            _CASES[case_id](s)
            if 'fresh-observations' in s.assertions:s.check('fresh-observations',bool(s.observations))
        except ApplianceError as error: s.reasons.append(error.code)
        except (OSError,ValueError,TypeError,KeyError,TimeoutError,RuntimeError): s.reasons.append('acceptance-driver-failed')
    failed=[name for name,passed in s.assertions.items() if not passed]
    if failed: s.reasons.extend('assertion-failed:'+name for name in failed)
    if synthetic: s.reasons.append('synthetic-driver-boundary')
    physical=case_id=='physical-operator'
    launched=getattr(driver,'launched',False) is True
    state='unknown' if synthetic or physical or not launched else ('failed' if failed or s.reasons else 'verified')
    return {'schema':1,'capability':case_id,'case_id':case_id,'state':state,
        'status':'PASS' if state=='verified' else ('FAIL' if state=='failed' else 'NOT RUN'),
        'checked_at':int(clock()),'plan_id':context['plan_id'],'build_id':context['build_id'],
        'spec_id':context['spec_id'],'dependencies':s.dependencies,'source':'acceptance-runner',
        'method':'unit-fixture' if synthetic else 'real-execution','test_only':synthetic,
        'environment':'physical' if physical else 'nested',
        'assertions':[{'name':name,'passed':passed} for name,passed in s.assertions.items()],
        'observations':s.observations,'evidence':[{'path':p,'sha256':h} for p,h in sorted(s.evidence.items())],
        'reasons':list(dict.fromkeys(s.reasons)),'qualification':'NOT RUN'}

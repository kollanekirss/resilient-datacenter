"""Journaled host changes with an independent deadline and explicit recovery.

All times are monotonic seconds within one boot. A new boot always restores
an unconfirmed transaction. The journal records observations, never promises
that a mocked command or a rendered configuration was effective on hardware.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import time

from .contracts import ApplianceError, identity, require
from . import files, state
from .host_network import (GUARD, SYSCTL, audit_host, collect_host, collect_ports,
                           execution_target, guard_active, render_host, resolve_ports, safe_management_files)

DIRECTORY = 'var/lib/rdc-appliance/private/network'
DEADLINE_SECONDS = 120


def _directory(root):
    return Path(root) / DIRECTORY


def _optional(directory, name):
    path = directory / name
    # lstat preserves symlink/dangling-file failures for the secure reader.
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    record = state.read(path)
    if name == 'pending.json':
        expected = {'schema','transaction_id','phase','created','deadline','boot_id','challenge',
                    'plan','before_plan','resolved_ports','before_profile','before','desired','original_digests'}
        require(set(record) == expected and record['schema'] == 1
                and record['phase'] in ('pending','confirmed','rolled-back')
                and type(record['created']) is int and type(record['deadline']) is int
                and 0 <= record['created'] <= record['deadline'] < 2**53
                and record['deadline'] - record['created'] in (0,DEADLINE_SECONDS)
                and record['before_profile'] in ('management-only','full')
                and type(record['transaction_id']) is str
                and re.fullmatch(r'[0-9a-f]{48}|[0-9a-f]{64}',record['transaction_id'])
                and type(record['boot_id']) is str and re.fullmatch(r'[a-zA-Z0-9-]{1,80}',record['boot_id'])
                and type(record['challenge']) is str and 1 <= len(record['challenge']) <= 128,
                'network-state-invalid')
        desired = _decode(record,'desired')
        _decode(record,'before')
        require(type(record['original_digests']) is dict and set(record['original_digests']) == set(desired)
                and all(v is None or type(v) is str and re.fullmatch('[0-9a-f]{64}',v)
                        for v in record['original_digests'].values()),'network-state-invalid')
    elif name == 'known-good.json':
        require(set(record) == {'schema','plan','resolved_ports','profile','files'} and record['schema'] == 1
                and record['profile'] in ('management-only','full'),'network-state-invalid')
        _decode(record,'files')
    return record


def _boot(root, value):
    if value is None:
        try:
            value = (Path(root) / 'proc/sys/kernel/random/boot_id').read_text().strip()
        except OSError:
            raise ApplianceError('boot-identity-missing') from None
    require(type(value) is str and re.fullmatch(r'[a-zA-Z0-9-]{1,80}', value), 'boot-identity-invalid')
    return value


def _now(value):
    require(type(value) is int and 0 <= value < 2**53, 'monotonic-time-invalid')
    return value


def _clock(root, value):
    _now(value)
    return int(time.monotonic()) if root == Path('/') else value


def _encode(values):
    return {path:base64.b64encode(raw).decode('ascii') for path,raw in values.items()}


def _decode(record, field):
    try:
        expected = set(render_host(record['plan'], record['resolved_ports']))
        require(type(record[field]) is dict and set(record[field]) == expected, 'network-state-invalid')
        result = {path:base64.b64decode(raw, validate=True) for path,raw in record[field].items()}
        require(all(len(raw) <= files.LIMIT for raw in result.values()), 'network-state-invalid')
        return result
    except (ValueError, TypeError, KeyError):
        raise ApplianceError('network-state-invalid') from None


def _digest(raw):
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _owned(directory, profile, values):
    state.write(directory / 'owned.json', {'schema':1, 'profile':profile,
                                        'files':{path:_digest(raw) for path,raw in values.items()}})


def _known(directory, plan, ports, profile, values):
    state.write(directory / 'known-good.json', {'schema':1, 'plan':plan, 'resolved_ports':ports,
                                              'profile':profile, 'files':_encode(values)})


def _check_current(root, record):
    before, desired = _decode(record, 'before'), _decode(record, 'desired')
    for path in desired:
        actual = _digest(files.read_optional(root, path))
        allowed = {_digest(before[path]), _digest(desired[path]), record['original_digests'][path]}
        require(actual in allowed, 'network-owned-file-changed')


def _publish(root, values):
    for path in sorted(values):
        files.atomic_write(root, path, values[path])


def _runtime(root, runner, values, *, full):
    runner.run(['/usr/sbin/nft', '--check', '--file', '-'], stdin=values[GUARD], timeout_s=5)
    runner.run(['/usr/sbin/nft', '--file', '-'], stdin=values[GUARD], timeout_s=5)
    runner.run(['/usr/sbin/sysctl', '--ignore', '--load', SYSCTL], timeout_s=5)
    if not full:
        # A compiled PVE local_network exception can still name the failed new
        # subnet. Keep the strict independent guard, remove that stale layer.
        runner.run(['/usr/bin/systemctl','stop','pve-firewall.service'],timeout_s=10)
        text = values['/etc/network/interfaces'].decode()
        for name in re.findall(r'^iface (vmbr[1-4]) inet manual$', text, re.M):
            runner.run(['/usr/sbin/ifdown', '--force', name], timeout_s=10)
    runner.run(['/usr/sbin/ifreload', '-a'], timeout_s=25)
    if full:
        runner.run(['/usr/bin/systemctl', 'restart', 'rdc-host-policy.service'], timeout_s=25)


def apply_host(plan, root, runner, *, now, resolved_ports=None, boot_id=None):
    root = execution_target(root, runner)
    now = _clock(root, now)
    boot_id = _boot(root, boot_id)
    if resolved_ports is None or root == Path('/'):
        fresh = resolve_ports(plan, collect_ports(root, runner))
        require(resolved_ports is None or resolved_ports == fresh, 'port-identity-unresolved')
        resolved_ports = fresh
    desired = render_host(plan, resolved_ports)
    fallback = safe_management_files(plan, resolved_ports)
    directory = _directory(root)
    with state.lock(directory):
        old_pending = _optional(directory, 'pending.json')
        require(old_pending is None or old_pending.get('phase') in ('confirmed','rolled-back'), 'network-change-pending')
        inventory = _optional(directory, 'owned.json')
        good = _optional(directory, 'known-good.json')
        actual = {path:files.read_optional(root, path) for path in desired}
        if inventory is None:
            require(good is None, 'network-state-invalid')
            require(all(raw is None or raw == fallback[path] for path,raw in actual.items()), 'network-file-unowned')
            before = fallback
            before_profile = 'management-only'
            _known(directory, plan, resolved_ports, before_profile, before)
        else:
            require(good is not None and inventory.get('files') == {p:_digest(v) for p,v in actual.items()}, 'network-owned-file-changed')
            before = _decode(good, 'files')
            require(before == actual, 'network-known-good-mismatch')
            require(good['plan']['site_id'] == plan['site_id'], 'host-renaming-forbidden')
            # NIC movement requires local remapping; never silently restore old names.
            require(good['resolved_ports'] == resolved_ports, 'port-remapping-required')
            before_profile = good['profile']
        txid = secrets.token_hex(24)
        record = {'schema':1, 'transaction_id':txid, 'phase':'pending', 'created':now,
                  'deadline':now + DEADLINE_SECONDS, 'boot_id':boot_id, 'challenge':secrets.token_urlsafe(24),
                  'plan':plan, 'resolved_ports':resolved_ports, 'before_profile':before_profile,
                  'before_plan':plan if good is None else good['plan'],
                  'before':_encode(before), 'desired':_encode(desired),
                  'original_digests':{path:_digest(raw) for path,raw in actual.items()}}
        state.write(directory / 'pending.json', record)
        # Timer dispatch is independent of the invoking SSH connection. No files
        # are changed unless systemd confirms that the timer is active.
        runner.run(['/usr/bin/systemctl', 'restart', 'rdc-network-rollback.timer'], timeout_s=5)
        runner.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'rdc-network-rollback.timer'], timeout_s=5)
        runner.run(['/usr/sbin/nft', '--check', '--file', '-'], stdin=desired[GUARD], timeout_s=5)
        _check_current(root, record)
        _publish(root, desired)
        _runtime(root, runner, desired, full=True)
        return txid


def _restore(root, runner, directory, record, *, boot):
    _check_current(root, record)
    before = _decode(record, 'before')
    if not boot:
        runner.run(['/usr/bin/systemctl','stop','rdc-host-policy.service'],timeout_s=10)
    _publish(root, before)
    if not boot:
        _runtime(root, runner, before, full=record['before_profile'] == 'full')
    _known(directory,record['before_plan'],record['resolved_ports'],record['before_profile'],before)
    _owned(directory, record['before_profile'], before)
    record = {**record, 'phase':'rolled-back'}
    state.write(directory / 'pending.json', record)
    return {'state':'rolled-back', 'transaction_id':record['transaction_id']}


def recover_pending(root, runner, *, now, boot_id=None, boot=False):
    root = execution_target(root, runner)
    now = _clock(root, now)
    directory = _directory(root)
    with state.lock(directory):
        record = _optional(directory, 'pending.json')
        if record is None or record.get('phase') in ('confirmed','rolled-back'):
            return {'state':'no-pending'}
        require(record.get('schema') == 1 and record.get('phase') == 'pending', 'network-state-invalid')
        if not boot and _boot(root, boot_id) == record['boot_id'] and now < record['deadline']:
            return {'state':'pending', 'transaction_id':record['transaction_id']}
        return _restore(root, runner, directory, record, boot=boot)


def _management_session(record, root, runner):
    try:
        result = runner.run(['/usr/bin/loginctl', 'show-session', 'self', '--all', '--no-pager'], timeout_s=10)
        session = dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
        network = ipaddress.IPv4Network(record['plan']['networks']['management']['cidr'])
        peer = ipaddress.IPv4Address(session['RemoteHost'])
        require(session.get('Remote') == 'yes' and session.get('Service') == 'sshd'
                and session.get('State') == 'active' and peer in network
                and peer not in (network.network_address, network.broadcast_address)
                and int(session['TimestampMonotonic']) >= (record['created'] + 1) * 1000000,
                'management-session-unproven')
        leader = session['Leader']
        require(re.fullmatch(r'[1-9][0-9]{0,9}', leader), 'management-session-unproven')
        descriptors = root / 'proc' / leader / 'fd'
        inodes = set()
        for entry in descriptors.iterdir():
            try:
                link = os.readlink(entry)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r'socket:\[([0-9]+)\]', link)
            if match:
                inodes.add(match[1])
        raw = (root / 'proc/net/tcp').read_bytes()
        require(len(raw) <= files.LIMIT, 'management-session-unproven')
        address = record['plan']['networks']['management']['host_ip']
        for line in raw.decode().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != '01' or fields[9] not in inodes:
                continue
            local, local_port = fields[1].split(':')
            remote, _ = fields[2].split(':')
            decode = lambda value: str(ipaddress.IPv4Address(bytes.fromhex(value)[::-1]))
            if decode(local) == address and int(local_port,16) == 22 and decode(remote) == str(peer):
                return
    except (OSError, ValueError, TypeError, KeyError):
        pass
    raise ApplianceError('management-session-unproven')


def confirm_management(transaction_id, challenge, *, root, runner, now, boot_id=None):
    root = execution_target(root, runner)
    now = _clock(root, now)
    directory = _directory(root)
    with state.lock(directory):
        record = _optional(directory, 'pending.json')
        require(record is not None and record.get('phase') == 'pending'
                and record.get('transaction_id') == transaction_id, 'network-confirmation-invalid')
        require(_boot(root, boot_id) == record['boot_id'] and now < record['deadline'], 'network-confirmation-expired')
        require(type(challenge) is str and hmac.compare_digest(challenge, record['challenge']), 'network-confirmation-invalid')
        _management_session(record, root, runner)
        try:
            observed = collect_host(record['plan'], root, runner)
            require(not audit_host(record['plan'], observed), 'host-audit-unproven')
        except ApplianceError:
            raise ApplianceError('host-audit-unproven') from None
        desired = _decode(record, 'desired')
        require(all(files.read_optional(root,p) == v for p,v in desired.items()), 'network-owned-file-changed')
        require(_clock(root,now) < record['deadline'], 'network-confirmation-expired')
        _known(directory, record['plan'], record['resolved_ports'], 'full', desired)
        _owned(directory, 'full', desired)
        state.write(directory / 'pending.json', {**record,'phase':'confirmed'})
        runner.run(['/usr/bin/systemctl', 'stop', 'rdc-network-rollback.timer'], timeout_s=10)


def restore_known_good(root, runner, *, now, boot_id=None):
    """Local console recovery, checked through the actual kernel tty endpoint."""
    root = execution_target(root, runner)
    _now(now)
    try:
        tty = os.readlink(root / 'proc/self/fd/0')
    except OSError:
        raise ApplianceError('local-console-required') from None
    require(re.fullmatch(r'/dev/(?:tty[1-9][0-9]*|ttyS[0-9]+|hvc[0-9]+)', tty), 'local-console-required')
    if root == Path('/'):
        require(os.isatty(0), 'local-console-required')
    directory = _directory(root)
    with state.lock(directory):
        good = _optional(directory, 'known-good.json')
        require(good is not None, 'network-known-good-missing')
        if root == Path('/'):
            require(resolve_ports(good['plan'], collect_ports(root,runner)) == good['resolved_ports'], 'port-remapping-required')
        record = _optional(directory, 'pending.json')
        if record is not None and record.get('phase') == 'pending':
            return _restore(root,runner,directory,record,boot=False)
        values = _decode(good,'files')
        inventory = _optional(directory,'owned.json')
        require(inventory is not None and all(_digest(files.read_optional(root,p)) == inventory['files'].get(p)
                                             for p in values), 'network-owned-file-changed')
        _publish(root,values)
        _runtime(root,runner,values,full=good['profile'] == 'full')
        return {'state':'restored-known-good'}


def _pve_get(runner, endpoint):
    try:
        result = runner.run(['/usr/bin/pvesh','get',endpoint,'--output-format','json'],timeout_s=5)
        require(len(result.stdout) <= files.LIMIT,'pve-policy-observation')
        return json.loads(result.stdout)
    except (ValueError,TypeError):
        raise ApplianceError('pve-policy-observation') from None


def post_pve(root, runner):
    """Apply host policy through PVE APIs, then activate non-management links.

    pmxcfs is an API-managed filesystem, not an ordinary POSIX directory. Its
    policy intent is recorded privately before mutation and read back afterward.
    An interrupted incomplete PVE intent requires inspection; it is not replayed.
    """
    root = execution_target(root,runner)
    directory = _directory(root)
    pending = _optional(directory,'pending.json')
    good = _optional(directory,'known-good.json')
    if pending is not None and pending.get('phase') == 'pending':
        _check_current(root,pending)
        desired = _decode(pending,'desired')
        candidate = all(files.read_optional(root,p) == raw for p,raw in desired.items())
        if candidate:
            plan, ports, values, profile = pending['plan'],pending['resolved_ports'],desired,'full'
        else:
            values = _decode(pending,'before')
            require(all(files.read_optional(root,p) == raw for p,raw in values.items()),'network-owned-file-changed')
            plan, ports, profile = pending['before_plan'],pending['resolved_ports'],pending['before_profile']
    elif good is not None:
        plan, ports, values, profile = good['plan'],good['resolved_ports'],_decode(good,'files'),good['profile']
        require(all(files.read_optional(root,p) == raw for p,raw in values.items()),'network-owned-file-changed')
    else:
        return {'state':'management-only'}
    if profile != 'full':
        return {'state':'management-only'}
    if root == Path('/'):
        require(resolve_ports(plan,collect_ports(root,runner)) == ports,'port-remapping-required')
    render_host(plan,ports)  # Validate the hostname before using it as an API path.
    node = '/nodes/' + plan['site_id'] + '/firewall'
    operations = [{'endpoint':'/cluster/firewall/options','desired':{'enable':1}},
                  {'endpoint':node+'/options','desired':{'enable':1,'policy_in':'DROP','policy_out':'ACCEPT'}}]
    # Separate lock avoids nesting the caller's network transaction lock.
    with state.lock(directory / 'pve-policy'):
        journal_path = directory / 'pve-policy' / 'intent.json'
        journal = _optional(journal_path.parent,'intent.json')
        for endpoint in ('/cluster/firewall/rules',node+'/rules'):
            require(_pve_get(runner,endpoint) == [],'pve-policy-foreign-rules')
        observed = [_pve_get(runner,op['endpoint']) for op in operations]
        require(all(type(value) is dict for value in observed),'pve-policy-observation')
        matches = lambda: all(all(observed[i].get(k) == v for k,v in op['desired'].items())
                              for i,op in enumerate(operations))
        if journal is not None:
            require(journal.get('operations') == operations,'pve-policy-identity')
            require(matches(),'pve-policy-needs-inspection')
        else:
            # Adopt only the initial empty/default options on this standalone node.
            for value in observed:
                require(all(k in ('digest','enable','policy_in','policy_out') for k in value)
                        and value.get('enable',0) in (0,1)
                        and value.get('policy_in','ACCEPT') in ('ACCEPT','DROP')
                        and value.get('policy_out','ACCEPT') == 'ACCEPT','pve-policy-unowned')
            journal = {'schema':1,'phase':'pending','operations':operations,'before':observed}
            state.write(journal_path,journal)
            for i,op in enumerate(operations):
                if all(observed[i].get(k) == v for k,v in op['desired'].items()):
                    continue
                argv = ['/usr/bin/pvesh','set',op['endpoint']]
                for key,value in op['desired'].items():
                    argv.extend(['--'+key,str(value)])
                runner.run(argv,timeout_s=5)
            observed = [_pve_get(runner,op['endpoint']) for op in operations]
            require(matches(),'pve-policy-unproven')
        state.write(journal_path,{**journal,'phase':'complete'})
        runner.run(['/usr/sbin/nft','--check','--file','-'],stdin=values[GUARD],timeout_s=5)
        runner.run(['/usr/sbin/nft','--file','-'],stdin=values[GUARD],timeout_s=5)
        runner.run(['/usr/sbin/pve-firewall','compile'],timeout_s=10)
        runner.run(['/usr/bin/systemctl','restart','pve-firewall.service'],timeout_s=10)
        status = runner.run(['/usr/sbin/pve-firewall','status'],timeout_s=5).stdout.decode().lower()
        require('enabled/running' in status,'pve-policy-unproven')
        try:
            active = json.loads(runner.run(['/usr/sbin/nft','-j','list','ruleset'],timeout_s=5).stdout)
        except (ValueError,TypeError):
            raise ApplianceError('host-guard-unproven') from None
        require(guard_active(plan,active),'host-guard-unproven')
        require(all(files.read_optional(root,p) == raw for p,raw in values.items()),'network-owned-file-changed')
        bridges = sorted(['vmbr1'] + [v['bridge'] for k,v in plan['networks'].items() if k != 'management'])
        try:
            for bridge in bridges:
                runner.run(['/usr/sbin/ifup',bridge],timeout_s=10)
            try:
                require(not audit_host(plan,collect_host(plan,root,runner)),'host-audit-unproven')
            except ApplianceError:
                raise ApplianceError('host-audit-unproven') from None
        except ApplianceError:
            for bridge in reversed(bridges):
                try:
                    runner.run(['/usr/sbin/ifdown','--force',bridge],timeout_s=10)
                except ApplianceError:
                    pass  # Preserve the failing observation; timed recovery remains armed.
            raise
    return {'state':'active'}


def main(argv=None):
    import argparse
    from .runner import Runner
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('recover','policy'))
    parser.add_argument('--boot',action='store_true')
    args = parser.parse_args(argv)
    try:
        runner = Runner()
        if args.action == 'recover':
            recover_pending(Path('/'),runner,now=int(time.monotonic()),boot=args.boot)
        else:
            # The systemd dependency must not admit guest startup in fallback.
            return 0 if post_pve(Path('/'),runner)['state'] == 'active' else 2
        return 0
    except (ApplianceError, OSError):
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

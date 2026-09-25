#!/usr/bin/env python3
"""Real local DNS/time and guest firewall, on disposable hosted Ubuntu only.

Namespaces model client source networks on one isolated L2 fixture. They do not
emulate OPNsense, DHCP, Proxmox or physical isolation. No namespace has a WAN route.
"""
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import time
from portable_network_bundle import prepare, verify
from portable_network_probe import check, dns_probe, ntp_probe
from portable_network_render import chrony

SOURCE = Path(__file__).resolve().parents[1]
ROOT = Path('/var/lib/rdc-portable-network-ci')
PROCESSES = []


def run(*args, timeout=30):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        print(result.stdout[-3000:] + result.stderr[-3000:], flush=True)
        raise ValueError('Disposable network command failed: ' + args[0])
    return result.stdout


def spawn(label, *args):
    with (ROOT / (label + '.log')).open('w') as log:
        process = subprocess.Popen(list(args), stdout=log, stderr=log)
    PROCESSES.append(process)
    return process


def require_ci():
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
        or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
        or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text()):
        raise ValueError('Disposable GitHub-hosted Ubuntu 24.04 only.')


def namespace(name, number, address):
    run('ip', 'netns', 'add', name)
    host, peer = 'rdcn' + str(number), 'rdcp' + str(number)
    run('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer)
    run('ip', 'link', 'set', host, 'master', 'rdc-local-ci'); run('ip', 'link', 'set', host, 'up')
    run('ip', 'link', 'set', peer, 'netns', name)
    run('ip', '-n', name, 'link', 'set', peer, 'name', 'lan0')
    run('ip', '-n', name, 'address', 'add', address + '/32', 'dev', 'lan0')
    run('ip', '-n', name, 'link', 'set', 'lan0', 'up'); run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    for subnet in ('10.76.0.0/16', '198.18.0.0/24'):
        run('ip', '-n', name, 'route', 'add', subnet, 'dev', 'lan0')
    assert 'default' not in run('ip', '-n', name, 'route')


def child(name, *arguments):
    return run('ip', 'netns', 'exec', name, sys.executable, str(Path(__file__)), *arguments, timeout=30)


def wait_ready(operation):
    deadline = time.monotonic() + 15
    while True:
        try: return operation()
        except (ValueError, OSError):
            if time.monotonic() >= deadline: raise
            time.sleep(.3)


def main():
    require_ci(); ROOT.mkdir(mode=0o700)
    plan = json.loads((SOURCE / 'examples/portable-site.json').read_text())
    settings = json.loads((SOURCE / 'examples/portable-network.json').read_text())
    kit = ROOT / 'kit'; prepare(plan, settings, kit); verify(kit)
    for role in ('dns', 'nginx', 'chat', 'files', 'partner'):
        netroot = ROOT / ('netplan-' + role); target = netroot / 'etc/netplan'; target.mkdir(parents=True)
        (target / 'rdc.yaml').write_bytes((kit / 'netplan' / (role + '.yaml')).read_bytes())
        (target / 'rdc.yaml').chmod(0o600)
        run('netplan', 'generate', '--root-dir', str(netroot))
    run('unbound-checkconf', str(kit / 'dns/unbound.conf'))
    time_config = Path('/etc/chrony/rdc-portable.conf'); time_config.write_bytes((kit/'dns/chrony.conf').read_bytes())
    run('chronyd', '-p', '-f', str(time_config))
    run('systemd-analyze', 'verify', *(str(SOURCE / 'portable' / (n + '.service')) for n in
                                      ('rdc-portable-dns', 'rdc-portable-time', 'rdc-portable-firewall')))
    run('ip', 'link', 'add', 'rdc-local-ci', 'type', 'bridge'); run('ip', 'link', 'set', 'rdc-local-ci', 'up')
    for index, (name, address) in enumerate((('rdc-dns','10.76.30.10'),('rdc-staff','10.76.20.100'),
                                          ('rdc-admin','10.76.10.20'),('rdc-peer','10.76.30.99'),
                                          ('rdc-outsider','198.18.0.2'))):
        namespace(name, index, address)
    # These stock services exist only on the throwaway runner. Avoid pid/socket
    # collisions; -x prevents the fixture chronyd from adjusting its host clock.
    run('systemctl', 'stop', 'chrony', 'unbound')
    dns_config = Path('/etc/unbound/rdc-portable.conf'); dns_config.write_bytes((kit/'dns/unbound.conf').read_bytes())
    def start_dns():
        return spawn('dns', 'ip','netns','exec','rdc-dns','unbound','-d','-c',str(dns_config))
    def start_time(configuration):
        return spawn('time','ip','netns','exec','rdc-dns','chronyd','-x','-n','-f',str(configuration))
    dns = start_dns(); clock = start_time(time_config)
    wait_ready(lambda: child('rdc-staff','probe'))
    # Before firewall activation, Unbound itself must refuse non-site clients.
    child('rdc-outsider','dns-refused')
    run('ip','netns','exec','rdc-dns','nft','--check','--file',str(kit/'dns/firewall.nft'))
    run('ip','netns','exec','rdc-dns','nft','--file',str(kit/'dns/firewall.nft'))
    run('ip','netns','exec','rdc-dns','nft','--file',str(kit/'dns/firewall.nft'))  # atomic repeat
    child('rdc-staff','probe'); child('rdc-peer','probe'); child('rdc-outsider','dns-blocked')
    spawn('ssh-fixture','ip','netns','exec','rdc-dns',sys.executable,'-m','http.server','22','--bind','10.76.30.10')
    wait_ready(lambda: child('rdc-admin','tcp-allowed'))
    child('rdc-staff','tcp-blocked'); child('rdc-peer','tcp-blocked')
    # Repeat the positives after denied paths: an absent listener cannot explain
    # a claimed firewall denial, and a filter cannot silently kill all traffic.
    child('rdc-admin','tcp-allowed'); child('rdc-staff','probe')
    dns.terminate(); clock.terminate(); dns.wait(timeout=10); clock.wait(timeout=10)
    dns = start_dns(); clock = start_time(time_config)
    wait_ready(lambda: child('rdc-staff','probe'))
    print('PASS: real local DNS UDP/TCP, negative names, NTP, daemon restart without WAN routes, resolver ACL and same-bridge SSH enforcement.', flush=True)
    # A missing institutional time source must not quietly turn into a local
    # reference. This profile has no fallback to host RTC.
    clock.terminate(); clock.wait(timeout=10)
    settings['clock'] = {'mode':'local-source','source':'10.76.10.30'}
    source_config = Path('/etc/chrony/rdc-source-ci.conf'); source_config.write_text(chrony(plan,settings))
    run('chronyd','-p','-f',str(source_config)); clock = start_time(source_config)
    wait_ready(lambda: child('rdc-staff','time-unsynchronised'))
    assert clock.poll() is None, 'Absent source test must run against a living daemon'
    print('PASS: absent independent NTP source reports unsynchronised; no host-RTC fallback. UTC accuracy, DHCP, OPNsense, Proxmox and applications remain NOT TESTED.', flush=True)


def probe(mode):
    plan = json.loads((SOURCE/'examples/portable-site.json').read_text())
    settings = json.loads((SOURCE/'examples/portable-network.json').read_text())
    if mode == 'probe':
        result = check(plan, settings)
        if result['state'] != 'network-probes-passed':
            print(json.dumps(result)); raise ValueError('Client probes failed.')
    elif mode == 'dns-refused':
        dns_probe('10.76.30.10','chat.example.org',None)
    elif mode == 'dns-blocked':
        try: dns_probe('10.76.30.10','chat.example.org','10.76.30.11')
        except (OSError, ValueError): return
        raise ValueError('Firewall allowed an outsider DNS request.')
    elif mode == 'time-unsynchronised':
        # Require an actual NTP response with LI=3/stratum0, not a timeout.
        from portable_network_probe import ntp_query
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
            stream.settimeout(2);stream.connect(('10.76.30.10',123));stream.send(ntp_query(time.time()));reply=stream.recv(512)
        assert len(reply)>=48 and (reply[0]>>6==3 or reply[1]==0)
        try: ntp_probe('10.76.30.10')
        except ValueError: return
        raise ValueError('Client accepted an unsynchronised source.')
    else:
        allowed = True
        try:
            with socket.create_connection(('10.76.30.10',22), timeout=1): pass
        except OSError: allowed = False
        assert allowed == (mode=='tcp-allowed'), 'Unexpected guest SSH boundary'


if __name__ == '__main__':
    try:
        if len(sys.argv)>1: probe(sys.argv[1])
        else: main()
    finally:
        for process in reversed(PROCESSES):
            if process.poll() is None: process.terminate()
        for process in reversed(PROCESSES):
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill()

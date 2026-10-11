import importlib
import json
from pathlib import Path
import subprocess

import pytest

from appliance.contracts import ApplianceError
from appliance import state


PORTS = {"management": "enp1s0", "wan": "enp2s0"}


class ScriptedRunner:
    """Records dispatch boundaries only; never represents a live network pass."""
    def __init__(self, root, fail=None):
        self.target_root = root.resolve()
        self.calls = []
        self.fail = fail
        self.session = b"Remote=yes\nRemoteHost=10.77.0.3\nService=sshd\nState=active\nTimestampMonotonic=110000000\nLeader=123\n"

    def run(self, argv, *, stdin=b"", timeout_s=30):
        self.calls.append((argv, stdin, timeout_s))
        if self.fail and self.fail in argv:
            raise ApplianceError("command-failed")
        output = self.session if "show-session" in argv else b""
        return subprocess.CompletedProcess(argv, 0, output, b"")


def api():
    return importlib.import_module("appliance.rollback")


def pending(root):
    return state.read(root / "var/lib/rdc-appliance/private/network/pending.json")


def test_apply_arms_independent_rollback_before_any_reload(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="boot-one")
    record = pending(tmp_path)
    assert record["transaction_id"] == txid and record["deadline"] == 220
    commands = [call[0] for call in runner.calls]
    timer = commands.index(["/usr/bin/systemctl", "restart", "rdc-network-rollback.timer"])
    reload = commands.index(["/usr/sbin/ifreload", "-a"])
    assert timer < reload
    assert b"gateway 10.77.0.1" in (tmp_path / "etc/network/interfaces").read_bytes()
    with pytest.raises(ApplianceError, match="network-change-pending"):
        api().apply_host(site, tmp_path, runner, now=101, resolved_ports=PORTS, boot_id="boot-one")


def test_timer_arm_failure_never_publishes_candidate(site, tmp_path):
    runner = ScriptedRunner(tmp_path, fail="restart")
    with pytest.raises(ApplianceError):
        api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="boot-one")
    assert not (tmp_path / "etc/network/interfaces").exists()
    assert not any("ifreload" in call[0][0] for call in runner.calls)
    assert pending(tmp_path)["phase"] == "pending"


def test_deadline_recovers_real_files_to_management_only_baseline(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="boot-one")
    assert api().recover_pending(tmp_path, runner, now=219, boot_id="boot-one")["state"] == "pending"
    assert api().recover_pending(tmp_path, runner, now=220, boot_id="boot-one")["state"] == "rolled-back"
    text = (tmp_path / "etc/network/interfaces").read_text()
    assert "address 10.77.0.2/24" in text and "gateway" not in text
    assert "auto vmbr1" not in text
    assert pending(tmp_path)["phase"] == "rolled-back"


def test_reboot_forces_recovery_without_waiting_or_touching_pmxcfs(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="boot-one")
    runner.calls.clear()
    assert api().recover_pending(tmp_path, runner, now=1, boot_id="boot-two", boot=True)["state"] == "rolled-back"
    assert not runner.calls
    assert not (tmp_path / "etc/pve").exists()


def test_changed_owned_file_is_not_silently_adopted(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    (tmp_path / "etc/network/interfaces").write_text("foreign edit")
    with pytest.raises(ApplianceError, match="network-owned-file-changed"):
        api().recover_pending(tmp_path, runner, now=220, boot_id="one")
    assert (tmp_path / "etc/network/interfaces").read_text() == "foreign edit"


def test_failed_reload_leaves_durable_pending_for_recovery(site, tmp_path):
    runner = ScriptedRunner(tmp_path, fail="-a")
    with pytest.raises(ApplianceError):
        api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    assert pending(tmp_path)["phase"] == "pending"
    runner.fail = None
    assert api().recover_pending(tmp_path, runner, now=220, boot_id="one")["state"] == "rolled-back"


@pytest.mark.parametrize("session", [b"Remote=no\n", b"Remote=yes\nRemoteHost=203.0.113.3\nService=sshd\nState=active\nTimestampMonotonic=110000000\nLeader=123\n", b"Remote=yes\nRemoteHost=10.77.0.3\nService=sshd\nState=active\nTimestampMonotonic=90000000\nLeader=123\n"])
def test_confirmation_rejects_local_external_or_old_sessions(site, tmp_path, session):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    runner.session = session
    with pytest.raises(ApplianceError, match="management-session-unproven"):
        api().confirm_management(txid, pending(tmp_path)["challenge"], root=tmp_path, runner=runner, now=120, boot_id="one")
    assert pending(tmp_path)["phase"] == "pending"


def test_fresh_session_without_matching_kernel_socket_cannot_confirm(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    with pytest.raises(ApplianceError, match="management-session-unproven"):
        api().confirm_management(txid, pending(tmp_path)["challenge"], root=tmp_path, runner=runner, now=120, boot_id="one")


def test_temporary_root_refuses_an_unbound_real_runner(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    del runner.target_root
    with pytest.raises(ApplianceError, match="runner-root-mismatch"):
        api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    assert not runner.calls


def test_late_or_wrong_boot_confirmation_cannot_cancel_rollback(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site, tmp_path, runner, now=100, resolved_ports=PORTS, boot_id="one")
    for now, boot in [(220, "one"), (120, "two")]:
        with pytest.raises(ApplianceError, match="network-confirmation-expired"):
            api().confirm_management(txid, pending(tmp_path)["challenge"], root=tmp_path, runner=runner, now=now, boot_id=boot)


def kernel_connection(root, *, local="02004D0A", remote="03004D0A"):
    fd = root / "proc/123/fd"
    fd.mkdir(parents=True)
    (fd / "4").symlink_to("socket:[42]")
    tcp = root / "proc/net/tcp"
    tcp.parent.mkdir(parents=True)
    tcp.write_text("header\n 0: " + local + ":0016 " + remote + ":C000 01 0:0 0:0 0 0 0 42\n")


def test_session_socket_must_terminate_at_management_ip(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id="one")
    kernel_connection(tmp_path, local="016433C6")
    with pytest.raises(ApplianceError,match="management-session-unproven"):
        api().confirm_management(txid,pending(tmp_path)["challenge"],root=tmp_path,runner=runner,now=120,boot_id="one")


def test_confirm_cannot_accept_session_without_live_host_audit(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    txid = api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id="one")
    kernel_connection(tmp_path)
    with pytest.raises(ApplianceError,match="host-audit-unproven"):
        api().confirm_management(txid,pending(tmp_path)["challenge"],root=tmp_path,runner=runner,now=120,boot_id="one")
    assert pending(tmp_path)["phase"] == "pending"


def test_console_repair_has_no_boolean_bypass(site, tmp_path):
    runner = ScriptedRunner(tmp_path)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id="one")
    fd = tmp_path / "proc/self/fd"
    fd.mkdir(parents=True)
    (fd / "0").symlink_to("/dev/pts/3")
    with pytest.raises(ApplianceError,match="local-console-required"):
        api().restore_known_good(tmp_path,runner,now=120,boot_id="one")
    (fd / "0").unlink()
    (fd / "0").symlink_to("/dev/tty1")
    assert api().restore_known_good(tmp_path,runner,now=120,boot_id="one")["state"] == "rolled-back"
    assert "gateway" not in (tmp_path / "etc/network/interfaces").read_text()


class PolicyRunner(ScriptedRunner):
    def __init__(self,root,fail=None):
        super().__init__(root,fail)
        self.options = {'/cluster/firewall/options':{}, '/nodes/pilot/firewall/options':{}}
        self.ruleset = nft_observation()

    def run(self,argv,*,stdin=b'',timeout_s=30):
        result = super().run(argv,stdin=stdin,timeout_s=timeout_s)
        if argv[0] == '/usr/bin/pvesh':
            if argv[1] == 'get':
                value = [] if argv[2].endswith('/rules') else self.options[argv[2]]
                result.stdout = json.dumps(value).encode()
            else:
                self.options[argv[2]] = {k.removeprefix('--'): int(v) if v.isdigit() else v
                                        for k,v in zip(argv[3::2],argv[4::2])}
        elif argv == ['/usr/sbin/pve-firewall','status']:
            result.stdout = b'Status: enabled/running\n'
        elif argv == ['/usr/sbin/nft','-j','list','ruleset']:
            result.stdout = json.dumps(self.ruleset).encode()
        return result


def nft_observation():
    """Independent kernel-shaped fixture; not a packet-filter qualification."""
    def match(kind,key,value,op='=='):
        if kind in ('ip','tcp','udp'):
            left = {'payload':{'protocol':kind,'field':key}}
        else:
            left = {kind:{'key':key}}
        return {'match':{'op':op,'left':left,'right':value}}
    def rule(*matches, verdict='accept'):
        return [*matches,{verdict:None}]
    subnet = {'prefix':{'addr':'10.77.0.0','len':24}}
    state = match('ct','state',{'set':['established','related']},'in')
    v6 = match('meta','nfproto','ipv6')
    src = match('ip','saddr',subnet)
    dst = match('ip','daddr','10.77.0.2')
    gw = match('ip','daddr','10.77.0.1')
    rules = {'input':[
        rule(match('meta','iifname','lo')),rule(v6,verdict='drop'),
        rule(match('meta','iifname','vmbr0','!='),verdict='drop'),rule(state),
        rule(src,dst,match('tcp','dport',{'set':[22,8006]})),
        rule(src,dst,match('ip','protocol','icmp'))],
        'output':[
        rule(match('meta','oifname','lo')),rule(v6,verdict='drop'),
        rule(match('meta','oifname','vmbr0','!='),verdict='drop'),rule(state),
        rule(gw,match('udp','dport',{'set':[53,123]})),rule(gw,match('tcp','dport',{'set':[22,53]})),
        rule(match('tcp','dport',{'set':[80,443]})),rule(match('ip','daddr',subnet),match('ip','protocol','icmp'))]}
    entries = [{'table':{'family':'inet','name':'rdc_host_guard'}}]
    for chain,expressions in rules.items():
        entries.append({'chain':{'family':'inet','table':'rdc_host_guard','name':chain,
                        'type':'filter','hook':chain,'prio':-300 if chain == 'input' else 0,'policy':'drop'}})
        entries.extend({'rule':{'family':'inet','table':'rdc_host_guard','chain':chain,'expr':expr}}
                       for expr in expressions)
    return {'nftables':entries}


def test_post_pve_activates_bridges_only_after_live_firewall_verification(site,tmp_path):
    runner = ObservedRunner(tmp_path,site)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    runner.calls.clear()
    assert api().post_pve(tmp_path,runner)['state'] == 'active'
    commands = [call[0] for call in runner.calls]
    status = commands.index(['/usr/sbin/pve-firewall','status'])
    assert all(commands.index(['/usr/sbin/ifup',bridge]) > status for bridge in ('vmbr1','vmbr2','vmbr3'))
    assert not any('/etc/pve' in arg for argv in commands for arg in argv)


def test_failed_pve_mutation_stays_pending_and_is_not_replayed(site,tmp_path):
    runner = PolicyRunner(tmp_path,fail='set')
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    with pytest.raises(ApplianceError):
        api().post_pve(tmp_path,runner)
    runner.fail = None
    runner.calls.clear()
    with pytest.raises(ApplianceError,match='pve-policy-needs-inspection'):
        api().post_pve(tmp_path,runner)
    assert not any('set' in argv or argv[0] == '/usr/sbin/ifup' for argv,_,_ in runner.calls)


def test_post_pve_refuses_file_drift_before_network_activation(site,tmp_path):
    runner = PolicyRunner(tmp_path)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    (tmp_path / 'etc/network/interfaces').write_text('foreign')
    runner.calls.clear()
    with pytest.raises(ApplianceError,match='network-owned-file-changed'):
        api().post_pve(tmp_path,runner)
    assert not runner.calls


def test_post_pve_refuses_broadened_active_policy(site,tmp_path):
    runner = PolicyRunner(tmp_path)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    rules = [entry['rule'] for entry in runner.ruleset['nftables'] if entry.get('rule',{}).get('chain') == 'input']
    rules[-2]['expr'] = [{'accept':None}]
    runner.calls.clear()
    with pytest.raises(ApplianceError,match='host-guard-unproven'):
        api().post_pve(tmp_path,runner)
    assert not any(argv[0] == '/usr/sbin/ifup' for argv,_,_ in runner.calls)


class ObservedRunner(PolicyRunner):
    def __init__(self,root,site):
        super().__init__(root)
        self.site = site
        self.links = [{'ifname':'lo'}, {'ifname':'enp1s0','master':'vmbr0'}, {'ifname':'enp2s0','master':'vmbr1'}]
        self.links += [{'ifname':bridge,'linkinfo':{'info_kind':'bridge'}} for bridge in ('vmbr0','vmbr1','vmbr2','vmbr3')]
        for role,name in PORTS.items():
            directory = root / 'sys/class/net' / name
            directory.mkdir(parents=True)
            (directory / 'device').symlink_to('../../../devices/' + site['ports'][role]['pci_path'])

    def run(self,argv,*,stdin=b'',timeout_s=30):
        result = super().run(argv,stdin=stdin,timeout_s=timeout_s)
        if argv[0] == '/usr/sbin/ip':
            if 'address' in argv:
                rows = [{'ifname':link['ifname'],'addr_info':[]} for link in self.links]
                next(x for x in rows if x['ifname'] == 'vmbr0')['addr_info'] = [{'local':'10.77.0.2','prefixlen':24}]
                result.stdout = json.dumps(rows).encode()
            elif 'route' in argv:
                result.stdout = b'[{"dev":"vmbr0","gateway":"10.77.0.1"}]'
            else:
                result.stdout = json.dumps(self.links).encode()
        elif argv[0] == '/usr/sbin/ethtool':
            role = next(role for role,name in PORTS.items() if name == argv[-1])
            port = self.site['ports'][role]
            result.stdout = (('Permanent address: '+port['permanent_mac']) if '-P' in argv else
                             ('driver: '+port['driver']+'\nbus-info: '+port['pci_path'])).encode()
        elif argv[0] == '/usr/sbin/sysctl' and '-n' in argv:
            result.stdout = b'0\n' if argv[-1] == 'net.ipv4.ip_forward' else b'0\n1\n1\n'
        elif argv[0].endswith('tables-save'):
            result.stdout = b'*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n'
        return result


def test_host_collection_handles_positive_kernel_ipv6_disable(site,tmp_path):
    from appliance.host_network import collect_host, audit_host
    disabled = tmp_path / 'sys/module/ipv6/parameters/disable'
    disabled.parent.mkdir(parents=True)
    disabled.write_text('1\n')
    class DisabledRunner(ObservedRunner):
        def run(self,argv,**kwargs):
            assert not any(arg.startswith('net.ipv6.') for arg in argv)
            assert argv[0] != '/usr/sbin/ip6tables-save'
            return super().run(argv,**kwargs)
    observation = collect_host(site,tmp_path,DisabledRunner(tmp_path,site))
    assert observation['ipv6_disabled'] is True
    assert observation['forwarding'] is False
    assert audit_host(site,observation)==[]


def test_missing_ipv6_keys_without_kernel_proof_refuses_audit(site,tmp_path):
    from appliance.host_network import collect_host, audit_host
    class MissingRunner(ObservedRunner):
        def run(self,argv,**kwargs):
            result=super().run(argv,**kwargs)
            if any(arg.startswith('net.ipv6.') for arg in argv): result.stdout=b''
            return result
    observation=collect_host(site,tmp_path,MissingRunner(tmp_path,site))
    assert 'host-ipv6-disabled' in audit_host(site,observation)


def test_confirm_fresh_matching_socket_and_complete_observations_records_known_good(site,tmp_path):
    runner = ObservedRunner(tmp_path,site)
    txid = api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    kernel_connection(tmp_path)
    api().confirm_management(txid,pending(tmp_path)['challenge'],root=tmp_path,runner=runner,now=120,boot_id='one')
    directory = tmp_path / 'var/lib/rdc-appliance/private/network'
    assert pending(tmp_path)['phase'] == 'confirmed'
    assert state.read(directory / 'known-good.json')['profile'] == 'full'
    assert runner.calls[-1][0] == ['/usr/bin/systemctl','stop','rdc-network-rollback.timer']
    changed = json.loads(json.dumps(site))
    changed['networks']['management']['host_ip'] = '10.77.0.20'
    api().apply_host(changed,tmp_path,runner,now=200,resolved_ports=PORTS,boot_id='one')
    api().recover_pending(tmp_path,runner,now=320,boot_id='one')
    assert 'address 10.77.0.2/24' in (tmp_path / 'etc/network/interfaces').read_text()
    assert state.read(directory / 'known-good.json')['plan'] == site


def test_port_observation_does_not_substitute_current_mac_for_permanent_identity(site,tmp_path):
    from appliance.host_network import collect_ports,resolve_ports
    runner = ObservedRunner(tmp_path,site)
    assert resolve_ports(site,collect_ports(tmp_path,runner)) == PORTS
    runner.site = json.loads(json.dumps(site))
    runner.site['ports']['wan']['permanent_mac'] = '02:ff:00:00:00:01'
    with pytest.raises(ApplianceError,match='port-identity-unresolved'):
        resolve_ports(site,collect_ports(tmp_path,runner))


def test_incomplete_pending_metadata_cannot_turn_into_a_runtime_action(site,tmp_path):
    runner = ScriptedRunner(tmp_path)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    record = pending(tmp_path)
    del record['deadline']
    state.write(tmp_path / 'var/lib/rdc-appliance/private/network/pending.json',record)
    runner.calls.clear()
    with pytest.raises(ApplianceError,match='network-state-invalid'):
        api().recover_pending(tmp_path,runner,now=220,boot_id='one')
    assert runner.calls == []


def test_post_policy_missing_host_observations_deactivates_bridges(site,tmp_path):
    runner = PolicyRunner(tmp_path)
    api().apply_host(site,tmp_path,runner,now=100,resolved_ports=PORTS,boot_id='one')
    runner.calls.clear()
    with pytest.raises(ApplianceError,match='host-audit-unproven'):
        api().post_pve(tmp_path,runner)
    commands = [args for args,_,_ in runner.calls]
    assert all(['/usr/sbin/ifdown','--force',bridge] in commands for bridge in ('vmbr1','vmbr2','vmbr3'))

"""The local network must not grant broad trust or invent safe input values."""
import copy
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import portable_plan

ROOT = Path(__file__).resolve().parents[1]


def plan():
    return json.loads((ROOT / 'examples/portable-site.json').read_text())


def settings():
    return {'schema_version': 1, 'administrator_address': '10.76.10.20',
            'proxmox_address': '10.76.10.10',
            'linux_interfaces': {r: 'ens18' for r in ('dns', 'nginx', 'chat', 'files', 'partner')},
            'dhcp': {'start': '10.76.20.100', 'end': '10.76.20.199'},
            'clock': {'mode': 'host-rtc', 'source': None}}


def module():
    import portable_network
    return portable_network


def test_network_policy_uses_real_edge_address_and_narrow_grants():
    policy = module().derive(plan(), settings())
    assert policy['edge_interfaces']['management']['address'] == '10.76.10.2/24'
    assert policy['edge_interfaces']['staff']['address'] == '10.76.20.1/24'
    assert policy['dhcp']['dns'] == ['10.76.30.10']
    assert policy['dhcp']['ntp'] == ['10.76.30.10']
    assert policy['dhcp']['router'] == '10.76.20.1'
    assert policy['default_policy'] == 'deny'
    rules = policy['rules']
    assert any(r['source'] == '10.76.20.0/24' and r['destination'] == '10.76.30.11' and r['port'] == 443 for r in rules)
    assert not any(r['source'] == '10.76.50.0/24' and r['port'] in (22, 443, 8006) for r in rules)
    assert not any(r['destination'] in ('any', '0.0.0.0/0') for r in rules)
    assert policy['clock']['utc_verified'] is False


@pytest.mark.parametrize('field,value', [
    ('administrator_address', '10.76.20.20'), ('administrator_address', '10.76.10.2'),
    ('administrator_address', '10.76.10.1'), ('administrator_address', '10.76.10.10'),
    ('proxmox_address', '10.76.10.255'), ('proxmox_address', '10.76.10.0'),
    ('proxmox_address', '10.76.10.2')])
def test_conflicting_or_unusable_management_address_is_rejected(field, value):
    s = settings(); s[field] = value
    with pytest.raises(ValueError): module().derive(plan(), s)


@pytest.mark.parametrize('start,end', [('10.76.20.1','10.76.20.99'), ('10.76.20.200','10.76.20.100'),
                                      ('10.76.20.100','10.76.20.255'), ('10.76.10.100','10.76.10.150')])
def test_dhcp_cannot_lease_gateway_or_wrong_network(start, end):
    s = settings(); s['dhcp'] = {'start': start, 'end': end}
    with pytest.raises(ValueError): module().derive(plan(), s)


def test_interface_injection_and_missing_roles_rejected():
    s = settings(); s['linux_interfaces']['dns'] = 'ens18\n  extra: true'
    with pytest.raises(ValueError): module().derive(plan(), s)
    s = settings(); del s['linux_interfaces']['partner']
    with pytest.raises(ValueError): module().derive(plan(), s)


def test_clock_source_must_be_independent_local_device():
    s = settings(); s['clock'] = {'mode': 'local-source', 'source': '10.76.10.30'}
    assert module().derive(plan(), s)['clock']['source'] == '10.76.10.30'
    for source in ('8.8.8.8', '10.76.30.10', '10.76.10.2', '10.76.10.10', None):
        s['clock']['source'] = source
        with pytest.raises(ValueError): module().derive(plan(), s)


def test_hierarchical_service_hostnames_are_rejected():
    p = plan(); p['domains']['element'] = 'web.chat.example.org'
    with pytest.raises(ValueError): module().derive(p, settings())


def test_settings_cannot_smuggle_credentials_or_use_boolean_schema():
    for extra in ({'password': 'secret'}, {'schema_version': True}):
        s = settings(); s.update(extra)
        with pytest.raises(ValueError): module().derive(plan(), s)


def test_rendered_netplan_has_no_dhcp_ipv6_or_wait_for_uplink():
    import yaml
    from portable_network_render import artifacts
    files = artifacts(plan(), settings())
    net = yaml.safe_load(files['netplan/chat.yaml'])['network']['ethernets']['ens18']
    assert net['addresses'] == ['10.76.40.10/24']
    assert net['nameservers']['addresses'] == ['10.76.30.10']
    assert net['dhcp4'] is False and net['dhcp6'] is False and net['accept-ra'] is False
    assert net['link-local'] == [] and net['optional'] is True
    assert net['routes'] == [{'to': 'default', 'via': '10.76.40.1'}]
    # The actual daemon and firewall files are syntax/runtime-tested on Linux.


def test_private_immutable_kit_and_tamper_detection(tmp_path):
    from portable_network_bundle import prepare, verify
    destination = tmp_path / 'kit'
    result = prepare(plan(), settings(), destination)
    assert result['state'] == 'network-prepared'
    assert result['network_verified'] is False
    assert destination.stat().st_mode & 0o077 == 0
    assert (destination / 'manifest.json').stat().st_mode & 0o077 == 0
    verify(destination)
    with pytest.raises(ValueError): prepare(plan(), settings(), destination)
    f = destination / 'dns/unbound.conf'; f.write_text('bad configuration')
    with pytest.raises(ValueError): verify(destination)


def test_kit_refuses_symlink_and_nonempty_directory(tmp_path):
    from portable_network_bundle import prepare
    old = tmp_path / 'old'; old.mkdir(); (old / 'keep').write_text('keep')
    link = tmp_path / 'link'; link.symlink_to(old, target_is_directory=True)
    for path in (old, link):
        with pytest.raises(ValueError): prepare(plan(), settings(), path)
    assert (old / 'keep').read_text() == 'keep'


def test_verify_does_not_create_missing_directory(tmp_path):
    from portable_network_bundle import verify
    absent = tmp_path / 'absent'
    with pytest.raises(ValueError): verify(absent)
    assert not absent.exists()


def test_cli_network_prepare_without_proxmox_credentials(tmp_path):
    from rdc import main
    p = tmp_path/'site.json'; p.write_text(json.dumps(plan()))
    s = tmp_path/'network.json'; s.write_text(json.dumps(settings()))
    kit = tmp_path/'kit'
    assert main(['portable','network-prepare',str(p),'--settings',str(s),'--output-dir',str(kit),'--json']) == 0
    assert (kit/'START-HERE.md').exists()
    assert main(['portable','network-verify',str(p),'--settings',str(s),'--output-dir',str(kit),'--json']) == 0
    changed = settings(); changed['administrator_address'] = '10.76.10.40'
    s.write_text(json.dumps(changed))
    assert main(['portable','network-verify',str(p),'--settings',str(s),'--output-dir',str(kit),'--json']) != 0


def test_failed_network_checks_exit_nonzero(tmp_path, monkeypatch, capsys):
    import portable_network_probe
    from rdc import main
    p = tmp_path/'site.json'; p.write_text(json.dumps(plan()))
    s = tmp_path/'network.json'; s.write_text(json.dumps(settings()))
    monkeypatch.setattr(portable_network_probe, 'check', lambda *a: {'state':'network-check-failed','checks':[]})
    assert main(['portable','network-check',str(p),'--settings',str(s),'--json']) != 0

    assert 'network-check-failed' in capsys.readouterr().out


def test_wizard_network_preparation_needs_no_server_credentials(tmp_path):
    from portable_state import write
    from portable_wizard import wizard
    folder = tmp_path/'journey'; folder.mkdir(mode=0o700)
    write(folder/'site.json', plan())
    replies = iter(['8','10.76.10.20','10.76.10.10', *(['ens18']*5),
                    '10.76.20.100','10.76.20.199','host-rtc','SAVE','prepare','q'])
    prompts = []
    def respond(prompt):
        prompts.append(prompt); return next(replies)
    assert wizard(folder,input_fn=respond,output_fn=lambda _: None)['state'] == 'saved'
    assert (folder/'network-kit/manifest.json').exists()
    assert not any('token' in p.lower() for p in prompts)


def test_kit_rejects_extra_files_and_manifest_change(tmp_path):
    from portable_network_bundle import prepare, verify
    kit = tmp_path/'kit'; prepare(plan(), settings(), kit)
    extra = kit/'unexpected'; extra.write_text('ignore me')
    with pytest.raises(ValueError): verify(kit)
    extra.unlink()
    manifest = json.loads((kit/'manifest.json').read_text()); manifest['site_sha256']='0'*64
    (kit/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError): verify(kit)


def test_kit_symlink_parent_is_rejected_without_external_writes(tmp_path):
    from portable_network_bundle import prepare, verify
    kit = tmp_path/'kit'; prepare(plan(), settings(), kit)
    dns = kit/'dns'; dns.rename(kit/'moved'); dns.symlink_to(kit/'moved', target_is_directory=True)
    with pytest.raises(ValueError): verify(kit)

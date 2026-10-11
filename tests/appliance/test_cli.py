"""Exercise the preparation command at its actual process boundary."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_installed_status_is_allowlisted_and_does_not_claim_packet_evidence(site,tmp_path,monkeypatch):
    from appliance import operations, host_network, router, state
    from appliance.contracts import ApplianceError
    monkeypatch.setattr(host_network,'collect_host',lambda *args:{'secret':'never-publish'})
    monkeypatch.setattr(host_network,'audit_host',lambda *args:[])
    monkeypatch.setattr(router,'collect_router',lambda *args:{'config_xml':'PRIVATE-XML', 'checks':[],
        'upstream':{'cidrs':['192.0.2.0/24'],'gateway':'192.0.2.1'},'stage':'transit'})
    monkeypatch.setattr(router,'router_ready',lambda *args:{'checks_passed':True,'state':'configured','packet_tests':'not-performed'})
    monkeypatch.setattr(router,'_upstream',lambda *args:None)
    state.write(tmp_path/'network/pending.json',{'phase':'pending','transaction_id':'t','challenge':'PRIVATE-CHALLENGE'})
    report=operations.installed_status(site,{'build_id':'b'*64},object(),private=tmp_path)
    assert report['capabilities']['router']['state']=='configured'
    assert report['capabilities']['upstream']['state']=='configured'
    assert report['capabilities']['dns']['state']=='unknown'
    assert report['pending_network_transaction']=='t'
    text=json.dumps(report)
    assert 'PRIVATE' not in text and 'never-publish' not in text
    assert 'verified' not in text
    def unavailable(*args):raise ApplianceError('router-channel-file')
    monkeypatch.setattr(router,'collect_router',unavailable)
    report=operations.installed_status(site,{'build_id':'b'*64},object(),private=tmp_path)
    assert report['capabilities']['management']['state']=='configured'
    assert report['capabilities']['router']['state']=='blocked'


def run(*args):
    return subprocess.run([sys.executable, "-m", "appliance", "--json", *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=10)


@pytest.fixture
def inputs(tmp_path, site, release):
    site_file, release_file = tmp_path / "site.json", tmp_path / "release.json"
    site_file.write_text(json.dumps(site))
    release_file.write_text(json.dumps(release))
    return site_file, release_file


def test_preview_reports_layout_without_authorizing_install(inputs):
    site, release = inputs
    result = run("preview", str(site), "--release", str(release))
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["destructive_actions_enabled"] is False
    assert data["networks"]["management"]["host_ip"] == "10.77.0.2"


def test_install_is_explicitly_disabled_even_with_force():
    result = run("install")
    assert result.returncode == 2
    assert json.loads(result.stdout)["code"] == "installer-adapter-unqualified"
    assert run("install", "--force").returncode != 0


def test_malformed_plan_reports_redacted_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("TOP-SECRET-BROKEN-JSON")
    result = run("preview", str(path))
    assert result.returncode == 2
    assert "TOP-SECRET" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_status_reports_incomplete_delivery():
    result = run("status")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["installer"] == "implemented-unqualified"
    assert data["boot_qualification"] == "not-run"
    assert data["destructive_actions_enabled"] is False


def test_release_check_accepts_real_pins_without_claiming_qualification():
    result = run("release-check")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data["state"] == "inputs-validated"
    assert data["installable"] is False
    assert {"proxmox-iso", "opnsense-dvd", "probe-image", "restic"} <= set(data["components"])


def test_preflight_does_not_treat_input_inventory_as_boot_proof(inputs, inventory, tmp_path):
    site, release = inputs
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory))
    result = run("preflight", str(site), "--release", str(release), "--inventory", str(path))
    assert result.returncode == 2
    assert "installer-adapter-unqualified" in json.loads(result.stdout)["blockers"]


def test_verify_tampered_artifact_fails_without_printing_contents(tmp_path):
    path = tmp_path / "image"
    path.write_text("SECRET-ARTIFACT")
    result = run("media", "verify", "opnsense-dvd", "--file", str(path))
    assert result.returncode == 2
    assert "SECRET-ARTIFACT" not in result.stdout + result.stderr


def test_readiness_does_not_call_itself_hardware_inventory():
    result = run("inspect")
    assert result.returncode == 0
    assert json.loads(result.stdout)["scope"] == "build-platform-only"


def test_menu_can_exit_without_a_network_or_installed_host():
    result = subprocess.run([sys.executable, '-m', 'appliance', 'menu'], cwd=ROOT,
                            input='q\n', capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert 'Exit' in result.stdout


def test_installed_mutation_is_refused_on_preparation_computer():
    result = run('router', 'allocate')
    assert result.returncode == 2
    assert json.loads(result.stdout)['code'] in ('installed-host-required', 'root-required')


def test_attachment_uses_declared_virtual_zones(inputs):
    site, release = inputs
    result = run('attachment', str(site), '--release', str(release))
    assert result.returncode == 0, result.stdout + result.stderr
    assert set(json.loads(result.stdout)['zones']) == {'infrastructure', 'workload'}


def test_configuration_render_never_overwrites_existing_output(inputs, tmp_path):
    site, release = inputs
    ports = tmp_path / 'ports.json'; ports.write_text(json.dumps({'management': 'enp1s0', 'wan': 'enp2s0'}))
    output = tmp_path / 'rendered'; output.mkdir()
    (output / 'keep').write_text('untouched')
    result = run('network', 'render', str(site), '--ports', str(ports), '--output', str(output), '--release', str(release))
    assert result.returncode == 2
    assert (output / 'keep').read_text() == 'untouched'

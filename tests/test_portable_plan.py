import copy
import importlib
import json
import subprocess
import sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def sample():
    return json.loads((ROOT / 'examples/portable-site.json').read_text())


def test_preview_is_explicitly_not_deployment():
    m = importlib.import_module('portable_plan')
    p = m.preview(sample())
    assert p['deployment'] == 'not-performed'
    assert p['infrastructure_verification'] == 'not-performed'
    assert len(p['vms']) == 6
    assert p['startup_groups'][-1] == ['partner']
    assert 'default-deny' in json.dumps(p)
    assert 'No servers were changed' in m.render(p)


@pytest.mark.parametrize('case', ['duplicate_id', 'overlap', 'overlay', 'network_address', 'duplicate_address',
                                 'secret', 'bad_domain', 'boolean_id', 'missing_module', 'wan_bridge',
                                 'same_site', 'bad_endpoint', 'low_memory', 'unknown_schema'])
def test_invalid_plans_fail_without_echoing_values(case):
    m = importlib.import_module('portable_plan')
    p = sample()
    if case == 'duplicate_id': p['vms']['chat']['id'] = p['vms']['files']['id']
    if case == 'overlap': p['networks']['staff']['cidr'] = p['networks']['frontend']['cidr']
    if case == 'overlay': p['networks']['staff']['cidr'] = '100.64.1.0/24'
    if case == 'network_address': p['vms']['dns']['address'] = '10.76.30.0'
    if case == 'duplicate_address': p['vms']['nginx']['address'] = p['vms']['dns']['address']
    if case == 'secret': p['proxmox']['token'] = 'DO-NOT-PRINT-THIS'
    if case == 'bad_domain': p['domains']['chat'] = 'https://secret.example/'
    if case == 'boolean_id': p['vms']['chat']['id'] = True
    if case == 'missing_module': del p['vms']['dns']
    if case == 'wan_bridge': p['networks']['staff']['bridge'] = p['proxmox']['wan_bridge']
    if case == 'same_site': p['recovery_site'] = p['site']
    if case == 'bad_endpoint': p['proxmox']['endpoint'] = 'https://user:DO-NOT-PRINT-THIS@pve.example:8006'
    if case == 'low_memory': p['vms']['chat']['memory_mib'] = 10
    if case == 'unknown_schema': p['schema_version'] = 2
    with pytest.raises(ValueError) as error: m.preview(p)
    assert 'DO-NOT-PRINT-THIS' not in str(error.value)


def test_preview_does_not_mutate_input_and_is_deterministic():
    m = importlib.import_module('portable_plan'); p = sample(); original = copy.deepcopy(p)
    assert m.preview(p) == m.preview(p)
    assert p == original


def test_cli_preview_and_invalid_file(tmp_path):
    good = subprocess.run([str(ROOT/'rdc'), 'portable', 'preview', str(ROOT/'examples/portable-site.json'), '--json'], capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)['deployment'] == 'not-performed'
    bad = tmp_path/'bad.json'; bad.write_text('{"password":"DO-NOT-PRINT-THIS",')
    result = subprocess.run([str(ROOT/'rdc'), 'portable', 'preview', str(bad)], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'DO-NOT-PRINT-THIS' not in result.stdout + result.stderr
    assert list(tmp_path.iterdir()) == [bad]


@pytest.mark.parametrize('text', ['{}', '[]', 'null', '{"schema_version":1,"schema_version":1}', '['*2000])
def test_loader_and_validation_reject_malformed_structures(tmp_path, text):
    m = importlib.import_module('portable_plan'); path = tmp_path/'site.json'; path.write_text(text)
    with pytest.raises(ValueError): m.preview(m.load(path))


def test_oversized_file_rejected(tmp_path):
    m = importlib.import_module('portable_plan'); path = tmp_path/'site.json'; path.write_text(' '*65537)
    with pytest.raises(ValueError, match='size limit'): m.load(path)


def test_boolean_schema_and_duplicate_domains_rejected():
    m = importlib.import_module('portable_plan'); p = sample(); p['schema_version'] = True
    with pytest.raises(ValueError): m.preview(p)
    p = sample(); p['domains']['files'] = p['domains']['chat']
    with pytest.raises(ValueError): m.preview(p)

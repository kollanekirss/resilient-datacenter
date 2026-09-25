import copy
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

def module():
    path = ROOT / 'scripts' / 'validate_inventory.py'
    assert path.exists(), 'Inventory validator has not been implemented'
    spec = importlib.util.spec_from_file_location('validator', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def inventory():
    # Pure unit-test inputs only. Tests never connect to these addresses.
    return {'all': {'vars': {
        'headscale_hostname': 'control.pilot.test', 'derp_hostname': 'relay.pilot.test',
        'enrollment_admin': 'lab-admin', 'derper_artifact': '/local/derper',
        'derper_sha256': 'a' * 64, 'test_ca_certificate': '/local/ca.crt',
    }, 'children': {
        'controller': {'hosts': {'control-01': {'ansible_host': '1.1.1.1', 'ansible_user': 'ubuntu', 'tls_certificate': '/local/control.crt', 'tls_private_key': '/local/control.key'}}},
        'relay': {'hosts': {'relay-01': {'ansible_host': '8.8.8.8', 'ansible_user': 'ubuntu', 'tls_certificate': '/local/relay.crt', 'tls_private_key': '/local/relay.key'}}},
        'peers': {'hosts': {
            'server-a': {'ansible_host': '9.9.9.9', 'ansible_user': 'ubuntu', 'node_tag': 'tag:institution-a-server', 'peer_name': 'server-b', 'test_dns_name': 'a.pilot.test', 'tls_certificate': '/local/a.crt', 'tls_private_key': '/local/a.key'},
            'server-b': {'ansible_host': '8.8.4.4', 'ansible_user': 'ubuntu', 'node_tag': 'tag:institution-b-server', 'peer_name': 'server-a', 'test_dns_name': 'b.pilot.test', 'tls_certificate': '/local/b.crt', 'tls_private_key': '/local/b.key'},
        }},
    }}}

def test_valid_inventory():
    assert module().validate_inventory(inventory(), check_files=False) == []

@pytest.mark.parametrize('change,expected', [
    (lambda d: d['all']['children'].pop('relay'), 'relay'),
    (lambda d: d['all']['children']['peers']['hosts']['server-b'].update(ansible_host='9.9.9.9'), 'distinct'),
    (lambda d: d['all']['vars'].update(headscale_hostname='headscale.example.com'), 'hostname'),
    (lambda d: d['all']['vars'].update(headscale_hostname='bad;touch/file'), 'hostname'),
    (lambda d: d['all']['vars'].update(derper_sha256=''), 'sha256'),
    (lambda d: d['all']['vars'].update(enrollment_admin='evil\ncommand'), 'enrollment_admin'),
    (lambda d: d['all']['children']['peers']['hosts']['server-a'].update(node_tag='tag:institution-b-server'), 'tag'),
    (lambda d: d['all']['children']['peers']['hosts']['server-b'].update(peer_name='server-b'), 'peer_name'),
    (lambda d: d['all']['children']['peers']['hosts']['server-a'].update(ansible_connection='local'), 'connection'),
    (lambda d: d['all']['children']['controller']['hosts']['control-01'].update(ansible_host='127.0.0.1'), 'public'),
])
def test_rejects_invalid_input(change, expected):
    d=inventory(); change(d)
    assert any(expected in e for e in module().validate_inventory(d, check_files=False))

def test_empty_document_rejected():
    assert module().validate_inventory(None, check_files=False)

def test_missing_files_fail():
    assert module().validate_inventory(inventory(), check_files=True)

def test_secret_is_not_echoed():
    d=inventory(); d['all']['vars']['password']='VERY_SECRET_SENTINEL'
    errors=module().validate_inventory(d, check_files=False)
    assert errors and 'VERY_SECRET_SENTINEL' not in str(errors)

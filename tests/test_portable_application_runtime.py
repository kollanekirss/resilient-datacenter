import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from portable_applications import profiles
from application_access import portable_owner


def inputs():
    plan=json.loads((Path(__file__).resolve().parents[1]/'examples/portable-site.json').read_text())
    plan['domains']={role:role+'.south.test' for role in ('chat','element','files')}
    return profiles(plan)


@pytest.mark.parametrize('role,module', [('chat','service_rendering'),('files','nextcloud_rendering')])
def test_portable_tls_backend_preserves_only_trusted_frontend_headers(role,module):
    import importlib
    p=inputs()[role];address=p['access']['backend_address']
    text=importlib.import_module(module).proxy(p,address)
    assert 'bind '+address in text
    assert 'trusted_proxies static '+p['access']['frontend_address'] in text
    assert 'trusted_proxies_strict' in text
    assert 'header_up X-Forwarded-For {http.request.client_ip}' in text
    assert 'header_up X-Real-IP {http.request.client_ip}' in text
    with pytest.raises(ValueError):importlib.import_module(module).proxy(p,'10.76.40.99')


@pytest.mark.parametrize('module', ['service_runtime','nextcloud_runtime'])
def test_portable_units_do_not_wait_for_tailscale(module):
    import importlib
    m=importlib.import_module(module)
    role='chat' if module=='service_runtime' else 'files'
    network=portable_owner(inputs()[role])
    for component in m.UNITS:
        assert 'tailscaled' not in m.unit(component,network=network)
    assert 'tailscaled' in m.unit('proxy')


def test_portable_ingress_only_allows_frontend_or_local_health_checks():
    import service_runtime as runtime
    network=portable_owner(inputs()['chat']);address=network['access']['backend_address']
    entries=runtime.ingress_entries(address,network=network)
    expressions=entries[-1]['rule']['expr']
    assert {'match':{'op':'!=','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':network['access']['frontend_address']}} in expressions
    assert {'drop':None} == expressions[-1]
    assert 'tailscale0' not in json.dumps(entries)
    runtime.validate_ingress({'nftables':entries},address,network=network)
    entries[-1]['rule']['expr'].pop()
    with pytest.raises(ValueError):runtime.validate_ingress({'nftables':entries},address,network=network)

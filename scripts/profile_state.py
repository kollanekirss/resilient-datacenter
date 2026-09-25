#!/usr/bin/env python3
"""Reduce read-only client status to a small enrollment result; no credentials emitted."""
import ipaddress
import json
import sys


def inspect_peer(status: dict, prefs: dict, hostname: str, tag: str) -> dict:
    controller = prefs.get('ControlURL')
    backend = status.get('BackendState')
    expected = 'https://' + hostname
    fresh = backend in ('NeedsLogin', 'NoState') and controller in ('', 'https://controlplane.tailscale.com')
    if controller != expected and not fresh:
        raise ValueError('Client belongs to a different controller; migration requires review')
    if backend != 'Running':
        return {'status': 'awaiting_enrollment' if backend in ('NeedsLogin','NoState','NeedsMachineAuth') else 'client_not_running', 'overlay_ip': None, 'node_id': None}
    identity = status.get('Self', {})
    if identity.get('Tags') != [tag]:
        raise ValueError('Expected exactly the approved node tag; inspect controller authorization')
    addresses = []
    for candidate in status.get('TailscaleIPs', []):
        address = ipaddress.ip_address(candidate)
        if address.version == 4 and address in ipaddress.ip_network('100.64.0.0/10'):
            addresses.append(str(address))
    if len(addresses) != 1:
        raise ValueError('Expected exactly one overlay IPv4 address')
    return {'status':'enrolled', 'overlay_ip':addresses[0], 'node_id':identity.get('ID')}


def main():
    try:
        data=json.load(sys.stdin)
        print(json.dumps(inspect_peer(data['status'],data['prefs'],data['hostname'],data['tag'])))
        return 0
    except Exception:
        print('Client state did not match the expected controller, tag or overlay address; inspect through management access.')
        return 1

if __name__=='__main__': raise SystemExit(main())

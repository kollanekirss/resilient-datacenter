"""Prepare a dedicated gateway profile; this wizard changes no network or service."""
import ipaddress
from pathlib import Path
import gateway_contracts as contracts
import regional_agreements as agreements
from regional_operations import export


def wizard(identity,identity_file,output,*,input_fn=input,output_fn=print):
    own=agreements.verify_identity(identity)
    result={'kind':'regional-gateway','schema_version':1,'institution_id':own['institution_id'],
            'node_name':own['gateway_node'],'regional_controller':own['regional_controller'],'identity_file':str(Path(identity_file).absolute()),'upstreams':{}}
    output_fn('Experimental dedicated gateway: one regional network identity, a private LAN to separate service VMs, no subnet forwarding. Matrix transport is available for testing; Nextcloud federation is still closed. Use :cancel to stop.')
    output_fn('Pinned institution: '+own['institution_id']+'; regional address: '+own['gateway_ipv4']+'; approval fingerprint: '+agreements.fingerprint(identity))
    def ask(label,valid):
        while True:
            value=input_fn(label+': ').strip()
            if value==':cancel':raise EOFError()
            try:
                if valid(value):return value
            except ValueError:pass
            output_fn('Use the requested format and keep gateway and service addresses distinct.')
    try:
        def subnet(value):
            parsed=ipaddress.ip_network(value,strict=True)
            return parsed.version==4 and 24<=parsed.prefixlen<=30 and any(parsed.subnet_of(block) for block in contracts.RFC1918)
        result['lan_subnet']=ask('Dedicated private LAN subnet, for example 10.203.1.0/24',subnet)
        network=ipaddress.ip_network(result['lan_subnet']);used=set()
        def address(value):
            parsed=ipaddress.ip_address(value)
            return parsed in network and parsed not in (network.network_address,network.broadcast_address) and value not in used
        result['lan_address']=ask('This gateway private LAN IPv4',address);used.add(result['lan_address'])
        for service in sorted(own['services']):
            result['upstreams'][service]=ask(service+' server private LAN IPv4 (separate service VM)',address);used.add(result['upstreams'][service])
        for field,label in [('tls_certificate','Absolute PEM certificate path covering '+', '.join(own['services'].values())),('tls_private_key','Absolute private PEM key path')]:
            result[field]=ask(label,lambda value:Path(value).is_absolute() and value not in [result.get(k) for k in ('identity_file','tls_certificate')])
        errors=contracts.validate(result,identity)
        if errors:raise ValueError('; '.join(errors))
        import json
        output_fn(json.dumps(result,indent=2))
        if input_fn('Type SAVE to prepare this profile: ').strip()!='SAVE':return {'state':'cancelled'}
    except (EOFError,KeyboardInterrupt):return {'state':'cancelled'}
    return export(output,result)

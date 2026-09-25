"""Dedicated single-membership regional gateway and narrowly scoped peer catalogue."""
import ipaddress
import json
from pathlib import Path
import re
import regional_agreements as agreements

FIELDS={'kind','schema_version','institution_id','node_name','regional_controller','lan_address','lan_subnet','identity_file','tls_certificate','tls_private_key','upstreams'}
RFC1918=tuple(ipaddress.ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
MAX_PEERS=8


def validate(profile,identity):
    try:
        if not isinstance(profile,dict) or set(profile)!=FIELDS or profile['kind']!='regional-gateway' or type(profile['schema_version']) is not int or profile['schema_version']!=1:raise ValueError('Use the documented gateway profile fields')
        agreements.canonical(profile);owned=agreements.verify_identity(identity)
        if any(profile[key]!=owned[other] for key,other in (('institution_id','institution_id'),('node_name','gateway_node'),('regional_controller','regional_controller'))):raise ValueError('Gateway profile differs from its signed institution identity')
        for name in ('identity_file','tls_certificate','tls_private_key'):
            if not isinstance(profile[name],str) or not Path(profile[name]).is_absolute():raise ValueError('Gateway inputs require absolute local file paths')
        if len({profile[name] for name in ('identity_file','tls_certificate','tls_private_key')})!=3:raise ValueError('Use separate identity, certificate and key files')
        if not isinstance(profile['lan_subnet'],str):raise ValueError('Use a private dedicated LAN CIDR')
        subnet=ipaddress.ip_network(profile['lan_subnet'],strict=True)
        if subnet.version!=4 or not 24<=subnet.prefixlen<=30 or not any(subnet.subnet_of(block) for block in RFC1918):raise ValueError('Use a dedicated RFC1918 IPv4 LAN with prefix /24 through /30')
        upstreams=profile['upstreams']
        if not isinstance(upstreams,dict) or set(upstreams)!=set(owned['services']):raise ValueError('Each declared application needs one fixed local upstream')
        addresses=[profile['lan_address'],*upstreams.values()]
        if any(not isinstance(value,str) for value in addresses):raise ValueError('Use literal LAN IPv4 addresses')
        parsed=[ipaddress.ip_address(value) for value in addresses]
        if len(set(parsed))!=len(parsed) or any(value not in subnet or value in (subnet.network_address,subnet.broadcast_address) for value in parsed):raise ValueError('Gateway and service endpoints need distinct usable addresses on the dedicated LAN')
        return []
    except (ValueError,TypeError) as error:return [str(error)]


def image_pins():
    data=json.loads(Path(__file__).with_name('gateway_images.json').read_text())
    if set(data)!={'schema_version','components'} or data['schema_version']!=1 or set(data['components'])!={'gateway'}:raise ValueError('Unknown gateway image catalogue')
    item=data['components']['gateway']
    if set(item)!={'version','image','platform','config_digest'} or item['platform']!='linux/amd64' or not re.fullmatch(r'docker.io/envoyproxy/envoy@sha256:[a-f0-9]{64}',item['image']) or not re.fullmatch(r'sha256:[a-f0-9]{64}',item['config_digest']) or not re.fullmatch(r'\d+\.\d+\.\d+',item['version']):raise ValueError('Gateway requires a reviewed fixed upstream image')
    return data['components']


def peer_rules(identity,documents,revoked_ids,*,now):
    owned=agreements.verify_identity(identity);ownprint=agreements.fingerprint(identity);agreements._time(now)
    if not isinstance(documents,list) or len(documents)>MAX_PEERS:raise ValueError('This gateway supports at most eight active peer agreement documents')
    if not isinstance(revoked_ids,list) or any(not agreements._hex(value,32) for value in revoked_ids):raise ValueError('Invalid local revocation records')
    rules=[];seen_ids=set();seen_peers=set();seen_addresses=set();seen_domains=set(owned['services'].values())
    for document in documents:
        offered=agreements.verify_agreement(document);identifier=offered['agreement_id']
        if identifier in seen_ids:raise ValueError('Duplicate gateway agreement identifier')
        seen_ids.add(identifier)
        parties=[offered[k] for k in ('initiator','recipient')]
        if parties.count(identity)!=1:raise ValueError('Agreement does not match the exact pinned local institution identity')
        peer=next(item for item in parties if item!=identity);peerprint=agreements.fingerprint(peer)
        # The local institution's signature already binds the independently
        # approved peer. Gateway initialization separately pins the local key.
        result=agreements.evaluate(document,local_fingerprint=ownprint,approved_peers=[peerprint],revoked_ids=revoked_ids,now=now)
        if result['state']!='mutually-approved':continue
        other=peer['payload'];domains={name:other['services'][name] for name in result['services']}
        if peerprint in seen_peers or other['gateway_ipv4'] in seen_addresses or set(domains.values())&seen_domains:raise ValueError('Ambiguous active peer identity, address or domain')
        seen_peers.add(peerprint);seen_addresses.add(other['gateway_ipv4']);seen_domains.update(domains.values())
        rules.append({'agreement_id':identifier,'fingerprint':peerprint,'institution_id':other['institution_id'],
                      'address':other['gateway_ipv4'],'domains':domains,'services':result['services'],'expires_at':result['expires_at']})
    return sorted(rules,key=lambda item:item['fingerprint'])

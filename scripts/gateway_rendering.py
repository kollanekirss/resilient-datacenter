"""Fixed application gateway configuration; no user-provided directives or URLs.

Nextcloud federation is deliberately closed until its protocol acceptance exists.
Only the reviewed Matrix server-to-server endpoints are currently rendered.
"""
import ipaddress
import json
import re
import gateway_contracts

HCM='type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager'
ROUTER={'name':'envoy.filters.http.router','typed_config':{'@type':'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'}}
SUPPORTED=('matrix',)


def socket(address,port):return {'socket_address':{'address':address,'port_value':port}}


def cluster(name,address,port,hostname=None):
    result={'name':name,'connect_timeout':'5s','type':'STATIC','load_assignment':{'cluster_name':name,'endpoints':[{'lb_endpoints':[{'endpoint':{'address':socket(address,port)}}]}]}}
    if hostname:
        result['transport_socket']={'name':'envoy.transport_sockets.tls','typed_config':{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext',
            'sni':hostname,'common_tls_context':{'validation_context':{'trusted_ca':{'filename':'/etc/ssl/certs/ca-certificates.crt'},
            'match_typed_subject_alt_names':[{'san_type':'DNS','matcher':{'exact':hostname}}]}}}}
    return result


def rbac(policies):
    return {'name':'envoy.filters.http.rbac','typed_config':{'@type':'type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC','rules':{'action':'ALLOW','policies':policies}}}


def policy(addresses,authority):
    return {'permissions':[{'header':{'name':':authority','string_match':{'exact':authority}}}],
            'principals':[{'direct_remote_ip':{'address_prefix':address,'prefix_len':32}} for address in addresses]}


def listener(name,address,port,vhosts,policies,*,tls=False):
    hcm={'@type':HCM,'stat_prefix':name,'codec_type':'AUTO','normalize_path':True,'merge_slashes':False,
         'path_with_escaped_slashes_action':'REJECT_REQUEST','use_remote_address':True,'xff_num_trusted_hops':0,
         'request_headers_timeout':'15s','stream_idle_timeout':'300s',
         'route_config':{'name':name,'virtual_hosts':vhosts},'http_filters':[rbac(policies),ROUTER]}
    if not tls:hcm['upgrade_configs']=[{'upgrade_type':'CONNECT'}]
    chain={'filters':[{'name':'envoy.filters.network.http_connection_manager','typed_config':hcm}]}
    if tls:
        chain['transport_socket']={'name':'envoy.transport_sockets.tls','typed_config':{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
            'common_tls_context':{'tls_params':{'tls_minimum_protocol_version':'TLSv1_2'},
            'tls_certificates':[{'certificate_chain':{'filename':'/etc/rdc-gateway/tls.crt'},'private_key':{'filename':'/etc/rdc-gateway/tls.key'}}]}}}
    return {'name':name,'address':socket(address,port),'filter_chains':[chain]}


def envoy(profile,identity,peers):
    errors=gateway_contracts.validate(profile,identity)
    if errors:raise ValueError('; '.join(errors))
    owned=identity['payload'];ingress=[];outbound=[];clusters=[];incoming_policies={};outgoing_policies={}
    for service in SUPPORTED:
        if service not in owned['services']:continue
        hostname=owned['services'][service]
        allowed=[peer for peer in peers if service in peer['services']]
        if allowed:
            for suffix in ('',':443'):
                incoming_policies[service+('port' if suffix else '')]=policy([peer['address'] for peer in allowed],hostname+suffix)
        clusters.append(cluster('local_'+service,profile['upstreams'][service],8443,hostname))
        routes=[{'match':{'prefix':prefix},'route':{'cluster':'local_'+service,'timeout':'60s'}} for prefix in ('/_matrix/federation/','/_matrix/key/')]
        routes.append({'match':{'path':'/.well-known/matrix/server'},'direct_response':{'status':200,'body':{'inline_string':json.dumps({'m.server':hostname+':443'})}}})
        ingress.append({'name':service,'domains':[hostname,hostname+':443'],'routes':routes})
        for peer in allowed:
            name=service+'_'+peer['fingerprint'];target=peer['domains'][service]+':443'
            clusters.append(cluster(name,peer['address'],443))
            outgoing_policies[name]=policy([profile['upstreams'][service]],target)
            outbound.append({'name':name,'domains':[target],'routes':[{'match':{'connect_matcher':{}},'route':{'cluster':name,'timeout':'0s',
                'upgrade_configs':[{'upgrade_type':'CONNECT','connect_config':{}}]}}]})
    fallback={'name':'denied','domains':['*'],'routes':[{'match':{'prefix':'/'},'direct_response':{'status':403}}]}
    ingress.append(fallback);outbound.append(fallback)
    return {'static_resources':{'listeners':[listener('regional',owned['gateway_ipv4'],443,ingress,incoming_policies,tls=True),
        listener('private_lan',profile['lan_address'],3128,outbound,outgoing_policies)],'clusters':clusters}}


def firewall(profile,peers,*,lan_interface,now,replace):
    if not isinstance(lan_interface,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',lan_interface) or lan_interface in ('lo','tailscale0'):
        raise ValueError('Use a separate detected dedicated LAN interface')
    if type(now) is not int or type(replace) is not bool:raise ValueError('Invalid firewall time or transaction')
    # No shell evaluation: this text is passed directly to nft's parser on stdin.
    local=str(ipaddress.IPv4Address(profile['lan_address']))
    sources=sorted({str(ipaddress.IPv4Address(profile['upstreams'][key])) for key in SUPPORTED if key in profile['upstreams']})
    members=[]
    for peer in peers:
        seconds=peer['expires_at']-now
        if seconds>0 and set(peer['services'])&set(SUPPORTED):members.append(str(ipaddress.IPv4Address(peer['address']))+' timeout '+str(seconds)+'s')
    lines=['delete table inet rdc_gateway'] if replace else []
    lines+=['add table inet rdc_gateway',
        'add set inet rdc_gateway peers { type ipv4_addr; flags timeout; }']
    if members:lines+=['add element inet rdc_gateway peers { '+', '.join(members)+' }']
    for name,hook in (('input','input'),('output','output'),('forward','forward')):
        lines+=['add chain inet rdc_gateway '+name+' { type filter hook '+hook+' priority -20; policy accept; }']
    # Both directions, including already-established TCP sessions, are checked.
    for selector in ('tcp dport 443','tcp sport 443'):
        lines+=['add rule inet rdc_gateway input iifname "tailscale0" '+selector+' ip saddr @peers accept',
                'add rule inet rdc_gateway input iifname "tailscale0" '+selector+' drop',
                'add rule inet rdc_gateway output oifname "tailscale0" '+selector+' ip daddr @peers accept',
                'add rule inet rdc_gateway output oifname "tailscale0" '+selector+' drop']
    # A packet addressed to the VPN endpoint must not enter through the LAN.
    lines+=['add rule inet rdc_gateway input iifname != "tailscale0" ip daddr 100.64.0.0/10 tcp dport 443 drop']
    if sources:
        lines+=['add rule inet rdc_gateway input iifname "'+lan_interface+'" ip saddr { '+', '.join(sources)+' } ip daddr '+local+' tcp dport 3128 accept']
    lines+=['add rule inet rdc_gateway input tcp dport 3128 drop',
            'add rule inet rdc_gateway forward iifname { "tailscale0", "'+lan_interface+'" } drop',
            'add rule inet rdc_gateway forward oifname { "tailscale0", "'+lan_interface+'" } drop']
    return '\n'.join(lines)+'\n'

"""Bounded relay topology extension to the strict infrastructure inventory."""
from copy import deepcopy
from profile_config import _validate_managed_inventory,_identifier,_safe_values
from validate_inventory import hostname


def catalogue(data):
    variables=data['all']['vars'];hosts=data['all']['children']['relay']['hosts']
    additional=variables.get('additional_relays',[])
    extra_names={entry['host'] for entry in additional}
    primary=next(name for name in hosts if name not in extra_names)
    entries=[{'host':primary,'hostname':variables['derp_hostname'],'region_id':901},*additional]
    return [{**entry,'address':hosts[entry['host']]['ansible_host']} for entry in entries]


def validate(data,*,check_files):
    try:variables=data['all']['vars']
    except (KeyError,TypeError):return _validate_managed_inventory(data,check_files=check_files,infrastructure_only=True)
    if not isinstance(variables,dict) or 'additional_relays' not in variables:
        return _validate_managed_inventory(data,check_files=check_files,infrastructure_only=True)
    if not _safe_values(data):return ['Unsafe infrastructure values']
    extra=variables['additional_relays']
    if not isinstance(extra,list) or not 1<=len(extra)<=3:return ['Provide one to three additional relay locations']
    if not hostname(variables.get('derp_hostname')) or not hostname(variables.get('headscale_hostname')):return ['Invalid controller or primary relay DNS name']
    names=[];domains=[variables['derp_hostname'],variables['headscale_hostname']];regions=[]
    for entry in extra:
        if not isinstance(entry,dict) or set(entry)!={'host','hostname','region_id'}:return ['Each additional relay requires only host, hostname and region_id']
        if not _identifier(entry['host']) or not hostname(entry['hostname']) or type(entry['region_id']) is not int or not 902<=entry['region_id']<=999:
            return ['Invalid additional relay host, DNS name or region ID (902–999)']
        names.append(entry['host']);domains.append(entry['hostname']);regions.append(entry['region_id'])
    if len(names)!=len(set(names)) or len(domains)!=len(set(domains)) or len(regions)!=len(set(regions)):
        return ['Relay hosts, DNS names and region IDs must be distinct']
    try:
        groups=data['all']['children'];hosts=groups['relay']['hosts']
        if not isinstance(hosts,dict) or not set(names)<=set(hosts) or len(hosts)!=len(extra)+1:
            return ['Declare exactly one primary relay host plus each additional relay host']
        entries=catalogue(data)
    except (KeyError,TypeError,StopIteration):return ['Invalid relay inventory']
    errors=[]
    # Run the original strict inventory/certificate contract on each complete
    # controller+relay projection. No host-level variables gain new privileges.
    for entry in entries:
        single=deepcopy(data);single['all']['vars'].pop('additional_relays')
        single['all']['vars']['derp_hostname']=entry['hostname']
        single['all']['children']['relay']['hosts']={entry['host']:hosts[entry['host']]}
        errors.extend(_validate_managed_inventory(single,check_files=check_files,infrastructure_only=True))
    if errors:return errors
    addresses=[host['ansible_host'] for group in groups.values() for host in group['hosts'].values()]
    all_names=[name for group in groups.values() for name in group['hosts']]
    if len(addresses)!=len(set(addresses)) or len(all_names)!=len(set(all_names)):
        return ['Every infrastructure host requires a distinct name and public IPv4 address']
    return []

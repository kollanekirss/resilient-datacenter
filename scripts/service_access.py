"""Prepare explicit one-direction application access in the operator inventory."""
from copy import deepcopy
from pathlib import Path
from setup_contracts import validate_infrastructure,SERVICE_PORTS
from profile_config import load_profile
from support_report import write_report


def change(data,source,destination,service,*,remove=False):
    if validate_infrastructure(data,check_files=False):raise ValueError('Use the current infrastructure-only inventory')
    revised=deepcopy(data);variables=revised['all']['vars']
    entry={'source':source,'destination':destination,'service':service}
    # Validate the requested relationship even when removing an absent entry.
    proposed=deepcopy(revised);proposed['all']['vars']['service_access']=[entry]
    if validate_infrastructure(proposed,check_files=False):raise ValueError('Select distinct declared nodes and either https or backup')
    entries=variables.setdefault('service_access',[])
    if remove:variables['service_access']=[a for a in entries if a!=entry]
    elif entry not in entries:entries.append(entry)
    if validate_infrastructure(revised,check_files=False):raise ValueError('Revised service-access inventory failed validation')
    return revised


def action(args,*,input_fn=input,output_fn=print):
    data=load_profile(str(args.inventory))
    if validate_infrastructure(data,check_files=False):raise ValueError('Use a valid infrastructure-only inventory')
    nodes=[n['name'] for n in data['all']['vars']['enrollment_nodes']]
    if len(nodes)<2:raise ValueError('Declare at least a user/writer node and a separate service/storage node in the infrastructure setup')
    if args.access_action=='setup':
        output_fn('Prepare an access change. No controller is contacted; application accounts and room permissions remain separate.')
        output_fn('Declared nodes: '+', '.join(nodes))
        source=input_fn('Connecting user/writer node: ').strip()
        destination=input_fn('Destination service/storage node: ').strip()
        service=input_fn('Service (https for chat/web, backup for encrypted storage): ').strip()
        remove=input_fn('Action (allow or remove): ').strip()
        if remove not in ('allow','remove'):return {'state':'cancelled'}
        remove=remove=='remove'
    else:source,destination,service,remove=args.source,args.destination,args.service,args.remove
    revised=change(data,source,destination,service,remove=remove)
    if args.access_action=='setup':
        output_fn(('Remove' if remove else 'Allow')+' '+source+' → '+destination+' on '+SERVICE_PORTS[service]+'. Reverse access, SSH and other ports are not granted by this declaration.')
        if input_fn('Type SAVE to write the revised private inventory: ').strip()!='SAVE':return {'state':'cancelled'}
    if Path(args.output_file).resolve()==Path(args.inventory).resolve():raise ValueError('Choose a new inventory filename so the previous reviewed configuration is retained')
    write_report(Path(args.output_file),revised)
    return {'state':'prepared','configuration_file':str(args.output_file),'controller_changed':False,
            'next_step':'Review this new inventory, then run infrastructure check and infrastructure apply with it. Use it as the current inventory for subsequent operations.'}

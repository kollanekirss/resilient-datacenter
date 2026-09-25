"""Guided, resumable Proxmox installation journey; no implicit remote mutations."""
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
from portable_plan import validate,preview,render,load,require,MODULES
from portable_state import directory,read,write
from portable_operations import action

ROOT=Path(__file__).resolve().parents[1]


class Cancel(Exception):pass


def ask(label,default='',*,input_fn=input):
    value=input_fn(label+(' ['+str(default)+']' if default!='' else '')+': ').strip()
    if value==':cancel':raise Cancel()
    return value or default


def prepare(folder,*,input_fn=input,output_fn=print):
    plan=json.loads((ROOT/'examples/portable-site.json').read_text())
    plan['site']=ask('Site name',plan['site'],input_fn=input_fn)
    plan['recovery_site']=ask('Independent recovery site',plan['recovery_site'],input_fn=input_fn)
    for field,label in [('endpoint','Proxmox HTTPS URL'),('node','Proxmox node'),('storage','VM disk storage'),('wan_bridge','Existing dedicated WAN bridge')]:
        plan['proxmox'][field]=ask(label,plan['proxmox'][field],input_fn=input_fn)
    base=ipaddress.ip_network(ask('Reserved private /16 network; verify no uplink/site overlap','10.76.0.0/16',input_fn=input_fn),strict=True)
    require(base.version==4 and base.prefixlen==16,'The guided network layout requires an IPv4 /16. Advanced layouts can use the documented JSON schema.')
    first=int(ask('First free VM ID',201,input_fn=input_fn))
    domain=ask('Institution domain for service names','example.org',input_fn=input_fn)
    for index,(zone,net) in enumerate(plan['networks'].items()):
        subnet=ipaddress.ip_network((int(base.network_address)+(index+1)*10*256,24))
        net['cidr']=str(subnet);net['gateway']=str(subnet.network_address+1)
    for index,(role,(zone,_)) in enumerate(MODULES.items()):
        plan['vms'][role]['id']=first+index
        offset=2 if role=='edge' else 11 if role in ('nginx','files') else 10
        plan['vms'][role]['address']=str(ipaddress.ip_network(plan['networks'][zone]['cidr']).network_address+offset)
    plan['domains']={role:role+'.'+domain for role in ('chat','element','files')}
    validate(plan);output_fn(render(preview(plan)))
    output_fn('Default resources and bridge names are shown above. Edit site.json before any allocation if your host differs. No existing bridge will be created or reconfigured.')
    if ask('Type SAVE to save this private plan, or :cancel',input_fn=input_fn)!='SAVE':raise Cancel()
    folder=directory(folder);write(folder/'site.json',plan)
    return plan


def instructions(role,output_fn=print):
    output_fn('Open this guest in the Proxmox web console. All virtual network links stay disconnected. Install only to the single planned disk; do not attach any other disks.')
    if role=='edge':
        output_fn('OPNsense: log into the installation environment as installer (initial password opnsense), select the intended disk and install. Set a private root password. Assign interfaces manually if prompted; do not rely on automatic link detection. Keep all links disconnected. Shut down after installation.')
    else:
        output_fn('Ubuntu: choose Server installation without networking, skip online mirror/update steps, install to the single planned disk and create your own administrator account. Do not reuse default/shared passwords. Shut down after installation. Configure application software in the later service phase.')
    output_fn('Choose finish only after installation and credential setup. Then choose boot to eject the ISO and start from disk. Check the OS/version and log in through the console; choose confirm-login to record your observation. VM running alone does not prove a successful OS boot.')


def wizard(folder,*,input_fn=input,output_fn=print):
    folder=Path(folder).absolute();plan_path=folder/'site.json';token_file=None;ca_file=None
    try:
        plan=validate(load(plan_path)) if plan_path.exists() else prepare(folder,input_fn=input_fn,output_fn=output_fn)
        while True:
            progress=[]
            for role in MODULES:
                journal=folder/'guest-state'/(role+'.json')
                phase=read(journal).get('phase','unknown') if journal.exists() else 'not-started'
                progress.append(role+': '+phase)
            output_fn('Last recorded progress (not a live health check): '+', '.join(progress))
            output_fn('Portable installation: 1 Preview | 2 Host check | 3 Allocate shells | 4 Fetch media | 5 Upload media | 6 Guest installation | 7 Instructions | q Save and exit')
            choice=ask('Choose a step','q',input_fn=input_fn)
            if choice=='q':return {'state':'saved','plan':str(plan_path),'notice':'Progress retained. Local service/network configuration is a subsequent phase.'}
            if choice=='7':instructions('edge',output_fn);instructions('chat',output_fn);continue
            verbs={'1':'preview','2':'check','3':'allocate-shells','4':'media-fetch','5':'media-upload'}
            args=SimpleNamespace(plan=plan_path,portable_action=verbs.get(choice),media_dir=folder/'media',state_dir=folder/'guest-state',
                                 token_file=None,ca_file=None,kind=None,iso_storage='local',role=None,operator=None)
            if choice=='6':
                args.role=ask('Guest role: edge, dns, nginx, chat, files or partner',input_fn=input_fn)
                if args.role not in MODULES:
                    output_fn('Select one of the listed guest roles.');continue
                instructions(args.role,output_fn)
                step=ask('Action: attach, start, finish, boot, status or confirm-login','status',input_fn=input_fn)
                if step not in ('attach','start','finish','boot','status','confirm-login'):
                    output_fn('Select one of the listed guest actions.');continue
                args.portable_action='guest-'+step
                if step in ('finish','confirm-login'):
                    args.operator=ask('Your name: attest the installation/credentials (finish) or installed OS and successful disk console login (confirm-login)',input_fn=input_fn)
            if not args.portable_action:output_fn('Choose one of the listed steps.');continue
            if choice in ('4','5'):
                args.kind=ask('Media: ubuntu or opnsense','opnsense',input_fn=input_fn)
                if choice=='5':args.iso_storage=ask('Proxmox ISO storage','local',input_fn=input_fn)
            if args.portable_action not in ('preview','media-fetch'):
                if token_file is None:
                    token_file=Path(ask('Path to private Proxmox API token file (not the token)',input_fn=input_fn)).expanduser()
                    ca=ask('Path to trusted Proxmox CA PEM; blank uses system trust','',input_fn=input_fn)
                    ca_file=Path(ca).expanduser() if ca else None
                args.token_file=token_file;args.ca_file=ca_file
            if args.portable_action not in ('preview','check','guest-status'):
                output_fn('Selected operation: '+args.portable_action+'; site '+plan['site']+('; guest '+args.role if args.role else '')+'.')
                if ask('Type RUN to perform this operation, or anything else to return','',input_fn=input_fn)!='RUN':continue
            try:
                result=action(args)
                output_fn(render(result) if args.portable_action=='preview' else json.dumps(result,indent=2))
            except ValueError as error:
                output_fn('Operation needs attention: '+str(error))
            except OSError:
                output_fn('Operation could not access local resources. Inspect private paths and disk space. Progress was retained.')
    except (Cancel,KeyboardInterrupt,EOFError):return {'state':'cancelled','notice':'Saved progress retained; no automatic remote rollback.'}

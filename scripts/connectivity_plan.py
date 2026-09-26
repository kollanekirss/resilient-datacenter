"""Connectivity intent and honest checkpoints; no remote operations."""
import copy
import hashlib
import ipaddress
import json
from urllib.parse import urlsplit
from portable_plan import domain, name, require

ROLES=('institution_controller','institution_relay','partner_controller','partner_relay')
BASE=(
    ('institution','Institution identifier',''),
    ('site','Site identifier',''),
    ('proxmox_endpoint','Proxmox HTTPS URL with dotted DNS hostname',''),
    ('node','Proxmox node name','pve'),
    ('storage','VM disk storage','local-lvm'),
    ('wan_bridge','Dedicated WAN bridge','vmbr0'),
    ('management_bridge','Independent management bridge','vmbr1'),
    ('services_bridge','Approved services bridge','vmbr2'),
    ('partner_bridge','Private partner transit bridge','vmbr3'),
    ('private_network','Reserved RFC1918 IPv4 /16; verify against all existing networks','10.76.0.0/16'),
)
STAGES=('Plan and inspect host','Build local edge and bootstrap network',
        'Build or connect coordination and relays','Establish field access',
        'Establish inter-institution connectivity','Exercise continuity and hand over')


def questions(answers=None):
    result=list(BASE)
    for role in ROLES:
        label=role.replace('_',' ')
        default='existing' if role.startswith('partner') else 'local' if role.endswith('controller') else 'external'
        result.extend(((role+'_placement',label+': local VM, external server to deploy, or existing service',default),
                       (role+'_url',label+' HTTPS URL (port 443, distinct DNS name)',''),
                       (role+'_location',label+' location: domestic or foreign','domestic')))
    return result


def valid_url(value, *, proxmox=False):
    try:
        u=urlsplit(value)
        return (type(value) is str and len(value)<=300 and not any(c.isspace() for c in value)
                and u.scheme=='https' and domain(u.hostname) and u.port in ((None,443,8006) if proxmox else (None,443))
                and u.username is None and u.password is None and u.path in ('','/') and not u.query and not u.fragment)
    except (TypeError,ValueError,AttributeError):return False


def valid_field(field,value):
    if type(value) is not str or not value:return False
    if field=='proxmox_endpoint' or field.endswith('_url'):return valid_url(value,proxmox=field=='proxmox_endpoint')
    if field.endswith('_placement'):return value in ('local','external','existing')
    if field.endswith('_location'):return value in ('domestic','foreign')
    if field=='private_network':
        try:
            network=ipaddress.ip_network(value,strict=True)
            return network.version==4 and network.prefixlen==16 and any(network.subnet_of(ipaddress.ip_network(block)) for block in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        except ValueError:return False
    return field in {q[0] for q in BASE} and name(value)


def record(answers):
    require(type(answers) is dict,'Use a supported connectivity plan.')
    keys=[q[0] for q in questions()]
    require(set(answers)==set(keys[:len(answers)]),'Resume planning in order; unexpected or missing answers are not accepted.')
    require(all(valid_field(k,v) for k,v in answers.items()),'Invalid answer. Use the stated choices, distinct bridge names and credential-free HTTPS DNS URLs.')
    bridges=[v for k,v in answers.items() if k.endswith('_bridge')]
    require(len(bridges)==len(set(bridges)),'WAN, management, services and partner transit need distinct bridges.')
    endpoints=[urlsplit(v).hostname for k,v in answers.items() if k.endswith('_url')]
    require(len(endpoints)==len(set(endpoints)),'Use distinct coordinator and relay hostnames for the two networks; shared-endpoint profiles are not implemented.')
    for role in ROLES:
        require(not (answers.get(role+'_placement')=='local' and answers.get(role+'_location')=='foreign'),
                'A local role belongs to this domestic site; choose external or existing for a foreign location.')
    complete=len(answers)==len(keys)
    roles=[{'role':r,'placement':'local','network':n} for r,n in (
        ('opnsense','institution'),('naming-time','local'),('partner-gateway','partner'),('test-target','local'))]
    for role in ROLES:
        roles.append({'role':role,'network':'institution' if role.startswith('institution') else 'partner',
                      'placement':answers.get(role+'_placement','unselected'),
                      'endpoint':answers.get(role+'_url','unselected'),
                      'location':answers.get(role+'_location','unselected')})
    limitations=['All server configuration and live checks are not verified.',
                 'Single coordinator per network: controller continuity is not implemented.',
                 'One selected relay per network: relay redundancy is not configured.',
                 'Public addressing, port conflicts and bootstrap DNS reachability need inspection before deployment.',
                 'Domestic location is operator-declared; domestic routing and independent power are not verified.',
                 'Static WireGuard fallback is planned future work, not an available installer option.']
    if any(v=='foreign' for k,v in answers.items() if k.endswith('_location')):
        limitations.append('A selected dependency is foreign: domestic-isolation readiness cannot be claimed with this plan.')
    revision=hashlib.sha256(json.dumps(answers,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'kind':'connectivity-install','schema_version':1,'state':'prepared' if complete else 'draft',
            'answers':copy.deepcopy(answers),'revision':revision,'deployment':'not-performed','roles':roles,
            'networks':{'institution':{'controller':answers.get('institution_controller_url','unselected'),
                                      'members':['field-devices','opnsense']},
                        'partner':{'controller':answers.get('partner_controller_url','unselected'),
                                   'members':['partner-gateway']}},
            'stages':[{'name':stage,'state':'planned' if i==0 else 'unsupported','verified':[]} for i,stage in enumerate(STAGES)],
            'limitations':limitations}


def validate(data):
    require(type(data) is dict and type(data.get('schema_version')) is int and data.get('schema_version')==1,
            'Select a supported connectivity record.')
    require(data==record(data.get('answers')),'Connectivity record differs from supported planning state; no deployment evidence is accepted here.')
    return copy.deepcopy(data)


def render(data):
    data=validate(data);a=data['answers']
    lines=['Connectivity plan: '+data['state'],'Institution: '+a.get('institution','unselected')+'; site: '+a.get('site','unselected'),
           'This is planning intent only; it does not describe past or current server state.','', 'Selected roles (placement is intent, not observed deployment):']
    for role in data['roles']:
        lines.append('  '+role['role']+' | '+role['network']+' | '+role['placement']+
                     (' | '+role['endpoint']+' | '+role['location'] if 'endpoint' in role else ''))
    lines+=['','Planned host: '+a.get('proxmox_endpoint','unselected'),
            'Bridges: '+', '.join(k.removesuffix('_bridge')+'='+a[k] for k in ('wan_bridge','management_bridge','services_bridge','partner_bridge') if k in a),
            'Reserved network: '+a.get('private_network','unselected'),
            'Publicly trusted endpoint certificates must be prepared beforehand; no private CA installation on staff devices.',
            'Keep local accounts/device admission, DNS and time available without foreign services.',
            '', 'Planning snapshot (not runtime evidence; host inspection and shell allocation are separate operations):']
    lines.extend(f"  {i}. {stage['name']}: {stage['state']}" for i,stage in enumerate(data['stages'],1))
    lines+=['','Built/configured: not established by this plan alone. Review the separate operation checkpoints.',
            'Verified: input structure only; no host, network or certificate checks.',
            'Available next: explicit host inspection and stopped VM shell allocation. Guest OS/network activation remain unavailable.',
            'Next step: finish planning.' if data['state']=='draft' else
            'Next step: choose host inspection in the connectivity operation menu.',
            '', 'Limits and dependencies:']
    lines.extend('  - '+item for item in data['limitations'])
    return '\n'.join(lines)

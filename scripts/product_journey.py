"""Purpose-first intent and machine roles; never infer deployment from a plan."""
import json
from pathlib import Path
import platform
import shlex
import yaml
from profile_config import _identifier,load_profile
from setup_files import write_bundle

FIELDS=('purpose','institution_id','services','responsible_operator','primary_location','recovery_location','network')


def acceptable(field,value):
    if not isinstance(value,str) or not value:return False
    if field=='purpose':return value in ('personal','institution','regional')
    if field=='services':return value in ('matrix','nextcloud','both')
    if field=='network':return value in ('new','existing')
    if field=='responsible_operator':return len(value)<=100 and all(c.isalnum() or c in ' @._+-' for c in value)
    if field=='institution_id':return len(value)<=32 and _identifier(value)
    return field in ('institution_id','primary_location','recovery_location') and _identifier(value)


def validate_answers(answers,*,draft=False):
    if not isinstance(answers,dict) or set(answers)-set(FIELDS) or (not draft and set(answers)!=set(FIELDS)):
        raise ValueError('Use the supported journey questions only')
    if any(not acceptable(field,value) for field,value in answers.items()):raise ValueError('A saved journey answer is invalid')
    if answers.get('primary_location') and answers.get('primary_location')==answers.get('recovery_location'):
        raise ValueError('Name distinct primary and recovery locations; verify their independence separately')


def machines(answers):
    validate_answers(answers);a=answers;regional=a['purpose']=='regional'
    selected=['matrix','nextcloud'] if a['services']=='both' else [a['services']]
    result=[]
    def add(role,network,location,*,state='to-prepare',**extra):
        result.append({'role':role,'machine':a['institution_id']+'-'+role,'network':network,'location':location,'state':state,**extra})
    if a['network']=='new':
        for role in ('controller','relay'):add(role,'regional' if regional else 'institutional','choose-an-offsite-location')
    for service in selected:
        add(service,'institutional',a['primary_location'])
        add(service+'-replacement','institutional',a['recovery_location'],state='capacity-to-prepare')
    add('backup','institutional',a['recovery_location'])
    if regional:
        add('gateway','regional',a['primary_location'],forwarding='disabled')
        add('gateway-backup','regional',a['recovery_location'])
        add('gateway-replacement','regional',a['recovery_location'],state='capacity-to-prepare',forwarding='disabled')
    return result


def record(answers,*,draft=False):
    validate_answers(answers,draft=draft)
    return {'kind':'product-journey','schema_version':1,'state':'draft' if draft else 'prepared',
            'answers':dict(answers),'machines':[] if draft else machines(answers)}


def load(path,*,allow_draft=False):
    data=load_profile(str(path))
    if not isinstance(data,dict) or set(data)!={'kind','schema_version','state','answers','machines'} or data['kind']!='product-journey' or type(data['schema_version']) is not int or data['schema_version']!=1 or data['state'] not in ('draft','prepared'):
        raise ValueError('Select a supported saved product journey')
    draft=data['state']=='draft'
    if draft and not allow_draft:raise ValueError('Resume the draft with rdc start before opening deployment tasks')
    if data!=record(data['answers'],draft=draft):raise ValueError('Saved machine roles differ from the supported journey')
    return data


def checklist(data,path):
    a=data['answers'];regional=a['purpose']=='regional'
    lines=['# Your self-hosting journey','',
           'Purpose: '+a['purpose']+'. Responsible operator: '+a['responsible_operator']+'.',
           'This is a preparation plan. No machine is installed, enrolled or proven protected by saving it.',
           'Different location labels do not prove separate power, connectivity or storage. Verify these in your own environment.',
           'Service recovery means an active service plus encrypted backup and prepared replacement capacity, not two writable copies.','',
           '| Role | Suggested machine label | Network | Location | Preparation |','|---|---|---|---|---|']
    for item in data['machines']:lines.append('| '+' | '.join(item[key] for key in ('role','machine','network','location','state'))+' |')
    lines+=['','Each row is a logical role. Keep controller and relay separate in this tested baseline; chat and files each require their own enrolled VM.',
            'Replacement rows are capacity to use after independently fencing the old server, not additional running copies of its VPN identity.',
            'Application servers require Ubuntu 24.04 amd64 with systemd, approximately 4 GiB RAM and at least 12 GiB free disk plus space for data and recovery.',
            'The controller and relay need public DNS/reachability. Local service nodes use outbound enrollment; public management SSH is not required at home.']
    if regional:lines+=['Keep your existing institutional controller for internal users and services. The dedicated gateway and its separate backup target join the regional controller; use the reviewed restricted private LAN link for applications. Institutional service backups stay on the institutional network. Never give one ordinary client two network memberships. There is no Headscale-controller federation or general subnet forwarding.']
    lines+=['','## Work in this order','',
            '1. Prepare the network, verify its controller identity and obtain enrollment approval. For a new network, prepare offsite controller and relay DNS, TLS and independent administration access.',
            '2. On each intended Ubuntu node, check/install the client and explicitly enroll it. Approve only the required device-to-service and backup connections.',
            '3. On each selected service VM, choose stable service domains, prepare trusted certificates, check/install the package, then create local accounts. Network enrollment does not create application accounts.',
            '4. Log in from a user device and send/read a chat message or upload/download a file. Record the outcome.',
            '5. Prepare the independently placed backup target and its pinned access. Save the repository password and emergency access independently, take an encrypted snapshot, inspect its age and enable the reviewed schedule.',
            '6. Perform a fenced recovery exercise. For a fresh replacement, recover its original network identity before installing/restoring the application. Test a real user operation afterward.',
            '7. If sharing with partners, exchange independently verified identities and bilateral approvals, attach the separate gateway and test permitted exchange plus denial/revocation. A restored connector stays suspended until reviewed.','',
            'Open the guided task menu from this reviewed project checkout:',
            '```sh','./rdc guide '+shlex.quote(str(path.absolute())),'```',
            'Run each task only on the machine named by its instructions. Tasks reuse the existing checked operations and retain their own previews and confirmations.',
            'Keep this private journey with your operating records. See docs/guided-setup.md, docs/matrix-services.md, docs/nextcloud-services.md, docs/backups.md and docs/regional-gateway.md.',
            'Automatic failover, optional institutional SSO, real-site resilience and beginner acceptance are not established by this plan.']
    return '\n'.join(lines)+'\n'


def wizard(directory,*,resume=None,input_fn=input,output_fn=print):
    directory=Path(directory).absolute();answers={}
    if resume:answers=dict(load(resume,allow_draft=True)['answers'])
    output_fn('Plan personal services, institutional communications or regional partnership. No servers will change. Use :back, :save or :cancel.')
    output_fn('This computer: '+platform.system()+' '+platform.machine()+'. Server installation requires supported Ubuntu; preparation can run here.')
    labels={'purpose':'Purpose: personal, institution or regional','institution_id':'Short environment name, e.g. my-home or north',
            'services':'Services: matrix (chat), nextcloud (files) or both','responsible_operator':'Who will maintain accounts, updates and recovery? Name or email',
            'primary_location':'Short primary-location label, e.g. tallinn','recovery_location':'Different recovery-location label, e.g. tartu',
            'network':'Network: new or existing'}
    index=0
    def save(draft):
        data=record(answers,draft=draft)
        outputs={'draft.yml':yaml.safe_dump(data,sort_keys=False)} if draft else {'journey.json':json.dumps(data,indent=2)+'\n','START-HERE.md':checklist(data,directory/'journey.json')}
        overwrite=False
        if directory.exists() and (directory/'BUNDLE.json').exists():
            # A verified draft-only bundle can finish without an overwrite prompt.
            existing=set(p.name for p in directory.iterdir())
            if resume and Path(resume).absolute()==directory/'draft.yml' and existing=={'draft.yml','BUNDLE.json'}:
                import hashlib
                meta=json.loads((directory/'BUNDLE.json').read_text())
                overwrite=meta=={'state':'draft','sha256':{'draft.yml':hashlib.sha256((directory/'draft.yml').read_bytes()).hexdigest()}}
            if not overwrite and input_fn('Existing journey files will be replaced. Type REPLACE or :cancel: ').strip()!='REPLACE':return {'state':'cancelled'}
            overwrite=True
        write_bundle(directory,outputs,overwrite=overwrite)
        return {'state':'draft' if draft else 'prepared','configuration_file':str(directory/('draft.yml' if draft else 'journey.json')),'deployment':'not-performed'}
    try:
        while index<len(FIELDS):
            field=FIELDS[index];default=answers.get(field,'both' if field=='services' and answers.get('purpose')=='institution' else '')
            label=labels[field]
            if field=='network' and answers.get('purpose')=='regional':label='Regional network: new (you operate it) or existing (join it); your internal network stays independent'
            value=input_fn(label+(' ['+default+']' if default else '')+': ').strip()
            if value==':cancel':return {'state':'cancelled'}
            if value==':save':return save(True)
            if value==':back':index=max(0,index-1);continue
            value=value or default
            if not acceptable(field,value) or (field=='recovery_location' and value==answers.get('primary_location')):
                output_fn('Use one of the stated choices, a short lowercase location/name, or a different recovery location.');continue
            answers[field]=value;index+=1
        output_fn(checklist(record(answers),directory/'journey.json'))
        choice=input_fn('Type SAVE to save this preparation plan, :save for a draft or :cancel: ').strip()
        if choice==':save':return save(True)
        if choice!='SAVE':return {'state':'cancelled'}
        return save(False)
    except (KeyboardInterrupt,EOFError):return {'state':'cancelled'}

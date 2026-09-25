#!/usr/bin/env python3
"""Prepare private setup files through questions; never install or enroll anything."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import yaml
from profile_config import load_profile, _identifier, _safe_values, RESERVED
from validate_inventory import hostname
from setup_contracts import validate_infrastructure, validate_local_manifest
from setup_files import prepare_outputs, write_bundle

ROOT=Path(__file__).resolve().parents[1]


def questions(answers):
    fields=[('purpose','Create your own network or join one? Type independent or join','choice'),('institution_id','Environment/institution identifier (lowercase, e.g. my-home)','id'),('headscale_hostname','Controller DNS name (no https:// prefix)','hostname')]
    if answers.get('purpose')=='independent':
        fields += [('control_ip','Offsite controller public IPv4 address','ip'),('control_user','Controller SSH username','user'),('derp_hostname','Relay DNS name','hostname'),('relay_ip','Relay public IPv4 address','ip'),('relay_user','Relay SSH username','user'),('enrollment_admin','Headscale enrollment administrator name','admin')]
        fields += [('tls_mode','Certificates: type supplied or managed-acme (public HTTP port 80 required)','tls-mode')]
        if answers.get('tls_mode')=='managed-acme':
            fields += [('acme_email','Email for your Let\'s Encrypt account','email'),('acme_terms','Review https://letsencrypt.org/repository/ and accept the current subscriber agreement; type accept to authorize issuance','terms')]
        else:
            fields += [(name,label,'path') for name,label in [('control_cert','Absolute path to controller certificate chain'),('control_key','Absolute path to controller private key'),('relay_cert','Absolute path to relay certificate chain'),('relay_key','Absolute path to relay private key')]]
        fields += [('relay_count','How many relay locations? Enter 1–4; use separate power and connectivity where possible','relay-count')]
        for index in range(2,int(answers.get('relay_count','1'))+1):
            prefix=f'relay{index}'
            fields += [(prefix+'_hostname',f'Relay location {index} DNS name','hostname'),(prefix+'_ip',f'Relay location {index} public IPv4','ip'),(prefix+'_user',f'Relay location {index} SSH username','user')]
            if answers.get('tls_mode')!='managed-acme':
                fields += [(prefix+'_cert',f'Relay location {index} absolute certificate path','path'),(prefix+'_key',f'Relay location {index} absolute private key path','path')]
        fields += [('derper_artifact','Absolute path to the verified or locally built Linux relay executable','path')]
        fields += [('derper_sha256','Relay executable SHA256 from its build metadata','sha'),('node_count','How many local nodes? Enter 1–32','count')]
        for index in range(int(answers.get('node_count','0'))):
            fields += [(f'node{index}_name',f'Local node {index+1} name (no public IP needed)','id'),(f'node{index}_tag',f'Local node {index+1} requested tag, starting tag:','tag')]
    else:
        fields += [('node_name','Name for this local node','id'),('node_tag','Requested administrator-approved tag, starting tag:','tag')]
    return fields


def acceptable(kind,value):
    if not isinstance(value,str) or not value or not _safe_values(value): return False
    if kind=='tls-mode': return value in ('supplied','managed-acme')
    if kind=='terms': return value=='accept'
    if kind=='email': return bool(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._+%-]{0,63}@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,63}',value))
    if kind=='choice': return value in ('join','independent')
    if kind=='id': return _identifier(value) and value not in RESERVED
    if kind=='admin': return bool(re.fullmatch(r'[a-z][a-z0-9-]{0,30}',value))
    if kind=='hostname': return hostname(value)
    if kind=='tag': return value.startswith('tag:') and _identifier(value[4:])
    if kind=='path': return Path(value).is_absolute()
    if kind=='user': return bool(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',value))
    if kind=='sha': return bool(re.fullmatch('[a-f0-9]{64}',value))
    if kind=='relay-count': return value.isdigit() and 1<=int(value)<=4
    if kind=='count': return value.isdigit() and 1<=int(value)<=32
    if kind=='ip':
        try:
            ip=ipaddress.ip_address(value); return ip.version==4 and ip.is_global
        except ValueError: return False
    return False


def configuration(answers):
    a=answers
    if a['purpose']=='join':
        return {'kind':'local-node','schema_version':1,**{k:a[k] for k in ['institution_id','headscale_hostname','node_name','node_tag']}}
    variables={'schema_version':2,'deployment_mode':'independent',**{k:a[k] for k in ['institution_id','headscale_hostname','derp_hostname','enrollment_admin','derper_artifact','derper_sha256']},'enrollment_nodes':[{'name':a[f'node{i}_name'],'node_tag':a[f'node{i}_tag']} for i in range(int(a['node_count']))]}
    managed=a.get('tls_mode')=='managed-acme'
    if managed: variables.update(schema_version=3,tls_mode='managed-acme',acme_email=a['acme_email'],acme_terms_accepted=a['acme_terms']=='accept')
    groups={}
    for group,prefix in [('controller','control'),('relay','relay')]:
        groups[group]={'hosts':{prefix+'-offsite':{'ansible_host':a[prefix+'_ip'],'ansible_user':a[prefix+'_user'],**({} if managed else {'tls_certificate':a[prefix+'_cert'],'tls_private_key':a[prefix+'_key']})}}}
    for index in range(2,int(a.get('relay_count','1'))+1):
        prefix=f'relay{index}';name=f'relay-offsite-{index}'
        variables.setdefault('additional_relays',[]).append({'host':name,'hostname':a[prefix+'_hostname'],'region_id':900+index})
        groups['relay']['hosts'][name]={'ansible_host':a[prefix+'_ip'],'ansible_user':a[prefix+'_user'],**({} if managed else {'tls_certificate':a[prefix+'_cert'],'tls_private_key':a[prefix+'_key']})}
    return {'all':{'vars':variables,'children':groups}}


def run_wizard(directory: Path, *, resume=None, input_fn=input, output_fn=print):
    answers={}
    if resume:
        draft=load_profile(str(resume))
        if not isinstance(draft,dict) or set(draft)!={'kind','schema_version','answers'} or draft['kind']!='setup-draft' or type(draft['schema_version']) is not int or draft['schema_version']!=1 or not isinstance(draft['answers'],dict) or not _safe_values(draft):
            raise ValueError('Not a supported setup draft')
        answers=draft['answers']
        if any(not isinstance(v,str) for v in answers.values()): raise ValueError('Invalid saved answers')
        if 'node_count' in answers and not acceptable('count',answers['node_count']): raise ValueError('Invalid saved node count')
        if 'relay_count' in answers and not acceptable('relay-count',answers['relay_count']): raise ValueError('Invalid saved relay count')
        allowed={k:kind for k,_,kind in questions(answers)}
        if set(answers)-set(allowed) or any(not acceptable(allowed[k],v) for k,v in answers.items()): raise ValueError('Invalid or unsupported saved answer')
    output_fn('Prepare networking only. No application or backup is installed. Use :back, :save or :cancel at setup questions and final review. Preparation changes no servers.')
    def save(outputs):
        try: return write_bundle(directory,outputs)
        except FileExistsError:
            if input_fn('Setup files already exist. Replace them? Type yes: ').strip().lower()!='yes': return None
            return write_bundle(directory,outputs,overwrite=True)
    def draft_save():
        text=yaml.safe_dump({'kind':'setup-draft','schema_version':1,'answers':answers},sort_keys=False)
        return 'draft' if save({'draft.yml':text}) else 'cancelled'
    index=0
    try:
        while True:
            fields=questions(answers)
            if index>=len(fields):
                data=configuration(answers)
                errors=validate_infrastructure(data,check_files=True) if answers['purpose']=='independent' else validate_local_manifest(data)
                if errors:
                    output_fn('Not ready to apply. Remaining prerequisites: '+'; '.join(errors))
                    output_fn('Saving an incomplete draft. Obtain the DNS/certificate/artifact prerequisites, then resume it.')
                    return draft_save()
                output_fn('Review the configuration. No installation will run:\n'+yaml.safe_dump(data,sort_keys=False))
                output_fn('Prepared local-node files are requests, not approved invitations. Confirm controller identity independently.')
                choice=input_fn('Write these private setup files? Type yes, :back, :save or :cancel: ').strip().lower()
                if choice==':back': index=max(0,len(fields)-1); continue
                if choice==':save': return draft_save()
                if choice!='yes': return 'cancelled'
                outputs=prepare_outputs(answers['purpose'],data)
                return 'prepared' if save(outputs) else 'cancelled'
            key,label,kind=fields[index]
            default=answers.get(key,'1' if key=='relay_count' else '')
            value=input_fn(label+(f' [{default}]' if default else '')+': ').strip()
            if value==':cancel': return 'cancelled'
            if value==':save': return draft_save()
            if value==':back': index=max(0,index-1); continue
            value=value or default
            if not acceptable(kind,value):
                output_fn('That answer is not valid. Use the format in the question, or :save to return later.'); continue
            answers[key]=value
            if key in ('purpose','tls_mode'):
                permitted={k for k,_,_ in questions(answers)}
                answers={k:v for k,v in answers.items() if k in permitted}
            if key in ('node_count','relay_count'):
                permitted={k for k,_,_ in questions(answers)}
                answers={k:v for k,v in answers.items() if k in permitted}
            index+=1
    except (KeyboardInterrupt,EOFError):
        output_fn('Cancelled; no enrollment or installation was started.')
        return 'cancelled'


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--resume',type=Path); p.add_argument('--output-dir',type=Path,default=ROOT/'inventories/lab/setup'); a=p.parse_args()
    try:
        result=run_wizard(a.output_dir,resume=a.resume)
        print('Setup '+result+'. Output directory: '+str(a.output_dir))
        return 0 if result in ('prepared','draft') else 1
    except (ValueError,OSError):
        print('Cannot prepare output. Check the draft, directory ownership and safe file paths; private values omitted.')
        return 1
if __name__=='__main__': raise SystemExit(main())

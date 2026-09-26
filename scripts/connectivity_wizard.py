"""Scope-first planning and explicitly selected Proxmox shell operations."""
from pathlib import Path
from connectivity_plan import questions, record, render, valid_field
from connectivity_state import load, save, NAME
from portable_plan import require

OPENING='''Connectivity installer — network foundation only
Purpose: local networking, field-user access and separate inter-institution connectivity.
Includes: OPNsense, local DNS/time, selected Headscale/DERP roles and a partner gateway.
Services are installed separately. This workflow does not install chat, files, SSO applications or backups.
Prerequisites: supported clean Proxmox, independent console/management access, networking,
prepared domains/public certificates, and any selected external servers.
Process: plan, review changes, execute a supported stage, verify, then continue or save and exit.
Current version: planning, read-only host checks and stopped VM shell allocation. Guided OPNsense installation is available; Linux installation and network activation remain outstanding.
No servers are contacted or changed by launching this wizard. API credentials are requested only for a selected host operation. Pinned software downloads require the separate prepare checkpoint.
Choose Start planning, Resume connectivity installation, or Exit.'''


def wizard(folder,*,resume=None,input_fn=input,output_fn=print):
    output_fn(OPENING)
    original=None;answers={};folder=Path(folder).absolute()
    try:
        while True:
            choice=input_fn('Choose start, resume or exit: ').strip().lower()
            if choice in ('exit','q',':cancel'):return {'state':'cancelled'}
            if choice in ('start','resume'):break
            output_fn('Choose start, resume or exit; nothing has changed.')
        if choice=='start':
            require(resume is None,'A resume file was supplied. Choose resume, or start again without --resume.')
            require(not folder.exists() or not any(folder.iterdir()),'This workspace already contains files. Resume connectivity.json or choose a new directory.')
        else:
            path=Path(resume).absolute() if resume else folder/NAME
            original=load(path);folder=path.parent;answers=dict(original['answers'])
            output_fn('Saved planning intent, not a live health check:\n'+render(original))
            if original['state']=='prepared':
                from connectivity_operations import menu
                return menu(folder,original,input_fn=input_fn,output_fn=output_fn)
        output_fn('Placement choices: local = create here, external = deploy on another server, existing = connect to an existing service.')
        output_fn('This is a domestic-site profile. Use :back to correct, :save to save a draft, or :cancel to leave unchanged.')
        fields=questions();index=0
        def persist():
            data=record(answers);path=save(folder,data,expected=original)
            output_fn('Private connectivity plan saved: '+str(path))
            output_fn(render(data))
            if data['state']=='prepared':
                from connectivity_operations import menu
                return menu(folder,data,input_fn=input_fn,output_fn=output_fn)
            output_fn('Connectivity planning ended. No services installer will be started.')
            return {'state':data['state'],'configuration_file':str(path),'deployment':'not-performed'}
        while index<len(fields):
            field,label,default=fields[index];default=answers.get(field,default)
            value=input_fn(f'Stage 1/6 — planning: {label}'+(' ['+default+']' if default else '')+': ').strip()
            if value==':cancel':return {'state':'cancelled'}
            if value==':save':return persist()
            if value==':back':
                index=max(0,index-1)
                answers={k:v for k,v in answers.items() if k in {q[0] for q in fields[:index]}}
                output_fn('Later answers cleared so the revised plan can be reviewed consistently.')
                continue
            value=value or default
            if not valid_field(field,value):
                output_fn('Use the stated choices, a short lowercase identifier, a canonical private /16, or a credential-free dotted HTTPS URL as requested.');continue
            proposed={k:answers[k] for k,_,_ in fields[:index]};proposed[field]=value
            try:record(proposed)
            except ValueError as error:output_fn(str(error));continue
            if answers.get(field)!=value:
                answers=proposed
            else:
                answers.update(proposed)
            index+=1
        output_fn(render(record(answers)))
        if input_fn('Type SAVE to save this plan, or anything else to exit without saving: ').strip()!='SAVE':
            return {'state':'cancelled'}
        return persist()
    except (KeyboardInterrupt,EOFError):
        output_fn('Stopped during planning. Previously saved planning state is unchanged; planning did not change servers.')
        return {'state':'cancelled'}

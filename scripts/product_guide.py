"""Allowlisted task navigation into the existing command parser; no shell execution."""
from dataclasses import dataclass
from pathlib import Path
import re
from product_journey import load


@dataclass(frozen=True)
class Task:
    label: str
    machine: str
    argv: tuple[str,...]


def groups(data,directory):
    directory=Path(directory).absolute();a=data['answers'];selected=['matrix','nextcloud'] if a['services']=='both' else [a['services']]
    result={}
    def task(label,machine,*argv):return Task(label,machine,tuple(str(value) for value in argv))
    operator='operator workstation; applies only to the reviewed remote controller and relay'
    node='THIS intended Ubuntu node; confirm its role and controller before installing or enrolling'
    result['network']=[task('Prepare network settings (choose independent for new, join for existing)',operator,'setup','--output-dir',directory/'network')]
    if a['network']=='new':
        result['network'] += [task('Check prepared controller and relay',operator,'infrastructure','check','@inventory'),
                              task('Install reviewed controller and relay',operator,'infrastructure','apply','@inventory')]
    result['node']=[task('Check local prerequisites',node,'node','check','@manifest'),task('Install local network client',node,'node','apply','@manifest'),
                    task('Request enrollment or verify existing membership',node,'node','enroll','@manifest'),task('Check enrollment',node,'node','status','@manifest'),
                    task('Diagnose network access without making changes',node,'doctor','@manifest')]
    for service in selected:
        command='services' if service=='matrix' else 'files';machine='THIS dedicated '+('chat' if service=='matrix' else 'file')+' VM on the institutional network'
        profile=directory/(service+'.json');issuer=directory/(service+'-issuer.json')
        tasks=[task('Prepare service domains and certificate paths',machine,command,'setup','--output-file',profile),
               task('Check the prepared service settings',machine,command,'check',profile),task('Install or resume this service',machine,command,'apply',profile),
               task('Create an application account',machine,command,'account'),task('Inspect this service',machine,command,'status'),
               task('Prepare optional DNS certificate issuance',machine,command,'issuer','setup','--output-file',issuer),
               task('Issue certificates using the reviewed DNS account',machine,command,'issuer','issue',issuer),
               task('Enable reviewed automatic certificate renewal',machine,command,'issuer','enable'),task('Inspect renewal evidence',machine,command,'issuer','status')]
        if a['purpose']=='regional':tasks += [task('Attach a reviewed gateway service link',machine,command,'regional','attach','@document'),
                                            task('Inspect partner attachment',machine,command,'regional','status'),task('Suspend partner attachment',machine,command,'regional','disable')]
        result[service]=tasks
    backup_profile=directory/'backup.json';machine='THIS node whose data you want to protect; storage preparation runs on the separate target instead'
    result['backup']=[task('Prepare storage on the separate backup target','THIS dedicated backup target on the source node’s network: institutional for services, regional for the separate gateway','backup','target','prepare','@manifest'),
                      task('Authorize the writer public key on the backup target','THIS backup target; verify the source node before granting access','backup','target','authorize','@public_key'),
                      task('Prepare the backup connection profile',machine,'backup','setup','--output-file',backup_profile),
                      task('Configure new backup credentials',machine,'backup','configure',backup_profile),
                      task('Initialize only a new empty repository after saving recovery access',machine,'backup','initialize'),
                      task('Include the installed application or gateway in future backups',machine,'backup','include-services'),
                      task('Take an encrypted snapshot',machine,'backup','run'),task('Inspect backup age and evidence',machine,'backup','status'),
                      task('Enable the reviewed daily schedule',machine,'backup','schedule','enable','--frequency','daily'),
                      task('Disable the schedule before changing installed roles',machine,'backup','schedule','disable')]
    machine='THIS isolated replacement; use independent administration and fence the old instance before promotion'
    result['recovery']=[task('Import saved repository password and SSH recovery access',machine,'backup','configure',backup_profile,'--recovery-password-file','@password_file','--recovery-ssh-key-file','@ssh_key'),
                        task('Fresh replacement: prepare original network identity from an application snapshot',machine,'backup','bootstrap-stage','@snapshot','--package','@package'),
                        task('Fresh replacement: review the network identity change',machine,'backup','bootstrap-plan','@snapshot'),
                        task('Fresh replacement: restore the network identity after fencing',machine,'backup','bootstrap-apply','@snapshot'),
                        task('Prepared replacement: stage the full application snapshot',machine,'backup','restore-stage','@snapshot'),
                        task('Review full restoration',machine,'backup','restore-plan','@snapshot'),
                        task('Restore the full snapshot after fencing',machine,'backup','restore-apply','@snapshot'),
                        task('Recover an interrupted restore transaction',machine,'backup','restore-recover')]
    result['upgrades']=[task('Check the reviewed local version transition','THIS chat or file-service VM','upgrade','check'),
                        task('Apply the reviewed upgrade during a maintenance window','THIS chat or file-service VM with verified encrypted backups','upgrade','apply'),
                        task('Recover the exact interrupted upgrade','THIS node with its original private upgrade journal','upgrade','recover')]
    if a['purpose']=='regional':
        machine='institution approval workstation; keep the private approval key off the gateway';workspace=directory/'approvals'
        profile=directory/'regional-identity.json'
        result['approvals']=[task('Prepare the public institution and gateway identity request',machine,'regional','setup','--output-file',profile),
                             task('Create or resume the encrypted approval identity',machine,'regional','init','--workspace',workspace,profile),
                             task('Export your public identity for independent verification',machine,'regional','export-identity','--workspace',workspace,'--output-file','@output'),
                             task('Inspect a received signed document',machine,'regional','inspect','@document'),
                             task('Approve an independently verified partner identity',machine,'regional','approve','--workspace',workspace,'@document'),
                             task('Offer a 30-day partnership for the selected services',machine,'regional','offer','--workspace',workspace,'--peer-fingerprint','@fingerprint','--services',*selected,'--output-file','@output'),
                             task('Review and accept a received partnership offer',machine,'regional','accept','--workspace',workspace,'@document','--output-file','@output'),
                             task('Import a completed agreement',machine,'regional','import-agreement','--workspace',workspace,'@document'),
                             task('Inspect local approval records',machine,'regional','status','--workspace',workspace)]
        profile=directory/'gateway.json';issuer=directory/'gateway-issuer.json';machine='THIS dedicated regional gateway; one regional client and a restricted private LAN to internal services'
        result['gateway']=[task('Prepare gateway settings from your public signed identity',machine,'gateway','setup','--identity','@identity','--output-file',profile),
                           task('Prepare gateway DNS certificate issuance',machine,'gateway','issuer','setup','--identity','@identity','--output-file',issuer),
                           task('Issue gateway certificates',machine,'gateway','issuer','issue',issuer),
                           task('Check gateway prerequisites',machine,'gateway','check',profile),task('Install or resume the gateway',machine,'gateway','apply',profile),
                           task('Review and replace the complete active agreement selection',machine,'gateway','policy','@agreements'),
                           task('Export a reviewed application attachment document',machine,'gateway','service-link','--package','@package','--output-file','@output'),
                           task('Revoke an agreement on this gateway',machine,'gateway','revoke','@agreement_id'),
                           task('Resume the exact interrupted policy change',machine,'gateway','resume'),task('Inspect gateway enforcement and recovery review',machine,'gateway','status'),
                           task('Enable reviewed certificate renewal',machine,'gateway','issuer','enable')]
    return result


LABELS={'inventory':'Absolute prepared infrastructure inventory path','manifest':'Absolute local-node manifest path',
        'document':'Absolute reviewed document path','identity':'Absolute signed public identity path','public_key':'Absolute writer public-key file path',
        'output':'Absolute new output file path (in an existing private directory)','password_file':'Absolute private saved repository-password file path',
        'ssh_key':'Absolute private saved SSH recovery-key file path','snapshot':'Complete 64-character snapshot ID',
        'fingerprint':'Independently verified full partner fingerprint','agreement_id':'Complete agreement ID to revoke',
        'package':'Application package: matrix, nextcloud or gateway (service links support matrix/nextcloud)'}


def arguments(task,input_fn):
    result=[]
    for argument in task.argv:
        if not argument.startswith('@'):result.append(argument);continue
        key=argument[1:]
        if key=='agreements':
            count=input_fn('How many complete agreements should remain active (0–8)? This replaces the selection: ').strip()
            if count==':cancel':return None
            if not count.isdigit() or not 0<=int(count)<=8:raise ValueError('Choose between zero and eight reviewed agreements')
            for _ in range(int(count)):
                value=input_fn('Absolute completed agreement document path: ').strip()
                if value==':cancel':return None
                if not Path(value).is_absolute():raise ValueError('Use an absolute agreement file path')
                result+=['--agreement',value]
            continue
        value=input_fn(LABELS[key]+': ').strip()
        if value==':cancel':return None
        if key in ('snapshot','fingerprint','agreement_id'):
            if not re.fullmatch('[a-f0-9]{'+str(32 if key=='agreement_id' else 64)+'}',value):raise ValueError('Use the complete reviewed identifier')
        elif key=='package':
            allowed=('matrix','nextcloud') if task.argv[:2]==('gateway','service-link') else ('matrix','nextcloud','gateway')
            if value not in allowed:raise ValueError('Choose a listed supported package')
        elif not Path(value).is_absolute():raise ValueError('Use an absolute path; its contents are validated by the selected operation')
        result.append(value)
    return result


def choose(path,*,input_fn=input,output_fn=print):
    path=Path(path).absolute();data=load(path);options=groups(data,path.parent)
    output_fn('Your saved journey describes intent, not completed installation. Select the part you are working on now; 0 cancels.')
    names=list(options)
    for index,name in enumerate(names,1):output_fn(str(index)+'. '+{'matrix':'Chat — Matrix and Element','nextcloud':'Files — Nextcloud'}.get(name,name.replace('_',' ').capitalize()))
    choice=input_fn('Part: ').strip()
    if choice in ('0',':cancel'):return None
    if not choice.isdigit() or not 1<=int(choice)<=len(names):raise ValueError('Choose a displayed part')
    tasks=options[names[int(choice)-1]]
    for index,task in enumerate(tasks,1):output_fn(str(index)+'. '+task.label+'\n   On: '+task.machine)
    choice=input_fn('Task (0 cancels): ').strip()
    if choice in ('0',':cancel'):return None
    if not choice.isdigit() or not 1<=int(choice)<=len(tasks):raise ValueError('Choose a displayed task')
    task=tasks[int(choice)-1]
    output_fn('Selected: '+task.label+'. Scope: '+task.machine+'. Existing checks and explicit change confirmations still apply.')
    return arguments(task,input_fn)

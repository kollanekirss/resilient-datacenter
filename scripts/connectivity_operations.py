"""Explicit, journaled connectivity shell operations and user checkpoints."""
from datetime import datetime, timezone
from pathlib import Path
from connectivity_state import load, NAME
from portable_plan import require
from portable_state import directory, lock, read, write
from proxmox_api import Client, credentials
import connectivity_provision as provision


def saved_settings(folder,plan):
    folder=Path(folder)/'provisioning'
    if not folder.exists():
        require(not folder.is_symlink(),'Provisioning directory cannot be a symlink.')
        return None
    directory(folder)
    require(set(p.name for p in folder.iterdir())<={'settings.json','journal.json'},'Unrelated provisioning files will not be adopted.')
    if not (folder/'settings.json').exists():
        require(not any(folder.iterdir()),'Incomplete provisioning settings; inspect local records.')
        return None
    return provision.validate_settings(plan,read(folder/'settings.json'))


def run(folder,plan,config,verb,api):
    require(verb in ('check','allocate'),'Unsupported connectivity operation.')
    folder=Path(folder)
    with lock(folder):
        require(load(folder/NAME)==plan,'Connectivity plan changed; reopen the wizard before making remote changes.')
        existing=saved_settings(folder,plan)
        provision.validate_settings(plan,config)
        state=directory(folder/'provisioning');path=state/'journal.json'
        require(not path.is_symlink() and (existing is None or path.exists()),
                'Provisioning journal is missing or symlinked; allocation history cannot be reset. Inspect private records and remote resources.')
        previous=provision.validate_journal(plan,existing,read(path)) if existing is not None and path.exists() else None
        if existing is not None and existing!=config:
            require(previous is None or not previous['vms'],
                    'VM allocation or observed shells bind these settings. Do not change IDs or management settings; inspect the existing resources.')
        data=previous if existing==config and previous is not None else provision.journal(plan,config)
        if existing!=config:
            write(state/'settings.json',config)
            write(path,data)
        def persist(value):
            provision.validate_journal(plan,config,value);write(path,value)
        try:
            if verb=='check':
                for entry in data['vms'].values():
                    if entry['state']=='task':provision.wait_task(api,plan['answers']['node'],entry['upid'])
            result=provision.check(plan,config,api) if verb=='check' else provision.allocate(plan,config,api,data,persist)
            if verb=='check':
                for vmid in result['existing_vm_ids']:
                    data['vms'][str(vmid)]={'state':'verified','upid':data['vms'].get(str(vmid),{}).get('upid')}
        except (ValueError,OSError):
            data['last']={'operation':verb,'outcome':'failed','at':datetime.now(timezone.utc).isoformat()}
            persist(data)
            raise
        data['last']={'operation':verb,'outcome':result['state'],'at':datetime.now(timezone.utc).isoformat()}
        persist(data)
        return result


def checkpoint(result,output_fn):
    if result['state']=='shells-allocated':
        output_fn('Built/configured: '+str(len(result['existing_vm_ids']))+' connectivity VM shells; stopped with disconnected NICs.')
    else:
        output_fn('Built/configured by this check: none. Existing matching shells: '+str(result['existing_vm_ids']))
    output_fn('Verified now: visible bridges, management address, capacity and visible VM ownership/state. Independent console access is still an operator check.')
    output_fn('Not yet available: installed guest OSs, active network policy, field access or partner connectivity from this workflow.')
    output_fn('Next step: '+('Guest OS installation and local network activation adapters (not implemented yet).' if result['state']=='shells-allocated' else
              'Review the allocation preview, then explicitly choose allocate; host-check success does not prove create permissions.'))


def menu(folder,plan,*,input_fn=input,output_fn=print,api_factory=Client):
    folder=Path(folder)
    outcome={'state':'prepared','configuration_file':str(folder/NAME),'deployment':'not-established-by-plan'}
    output_fn('Connectivity checkpoints: host inspection and VM shell allocation are available. Guest OS installation and network activation remain unavailable.')
    config=saved_settings(folder,plan)
    if config is not None:
        path=folder/'provisioning/journal.json'
        if path.exists():
            data=provision.validate_journal(plan,config,read(path))
            if data['last']:
                last=data['last'];output_fn(f"Historical result only: {last['operation']} -> {last['outcome']} at {last['at']}. Rerun checks for current state.")
            pending=[vmid for vmid,entry in data['vms'].items() if entry['state'] in ('intent','task')]
            if pending:output_fn('Pending/uncertain allocations: '+', '.join(pending)+'. Inspect tasks; missing uncertain shells are never automatically recreated.')
    try:
        while True:
            choice=input_fn('Choose preview, settings, check (read only), allocate (stopped shells), or exit [exit]: ').strip().lower() or 'exit'
            if choice in ('exit','q',':cancel'):
                output_fn('Progress retained. No services installer was started.');return outcome
            if choice not in ('preview','settings','check','allocate'):
                output_fn('Choose one of the stated operations.');continue
            try:
                if config is None or choice=='settings':
                    value=input_fn('First free VM ID [300]: ').strip() or '300'
                    require(value.isascii() and value.isdecimal() and len(value)<=9,'Use a numeric VM ID from 100 to 999999999.')
                    first=int(value)
                    address=input_fn('Existing independent Proxmox management IPv4 address: ').strip()
                    selected=provision.settings(plan,first,address)
                else:selected=config
                output_fn(provision.preview(plan,selected))
                if choice=='settings':
                    config=selected
                    output_fn('Settings preview only. A confirmed operation saves them; changes are refused after any allocation intent or observed shell.')
                    continue
                if choice=='preview':continue
                confirmation='CHECK' if choice=='check' else 'ALLOCATE'
                output_fn('This operation reads host state only.' if choice=='check' else 'This operation allocates new VM definitions and blank disks. It never starts guests or changes bridges. Ensure independent console access before continuing.')
                if input_fn('Type '+confirmation+' to continue, or anything else to return: ').strip()!=confirmation:continue
                token=Path(input_fn('Path to private Proxmox API token file (not its contents): ').strip()).expanduser()
                ca=input_fn('Trusted Proxmox CA file; blank uses system certificate trust: ').strip()
                api=api_factory(plan['answers']['proxmox_endpoint'],credentials(token),Path(ca).expanduser() if ca else None)
                result=run(folder,plan,selected,choice,api)
                config=selected
                checkpoint(result,output_fn)
            except ValueError as error:
                output_fn('Operation needs attention: '+str(error))
                config=saved_settings(folder,plan)
            except OSError:
                output_fn('Operation interrupted by a local resource error. Inspect private records and Proxmox task state; no rollback or automatic replay was performed.')
                config=saved_settings(folder,plan)
    except (KeyboardInterrupt,EOFError):
        output_fn('Stopped. Saved progress retained; inspect any unresolved task before retrying. No automatic rollback was performed.')
        return outcome

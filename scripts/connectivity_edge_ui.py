"""Explicit user checkpoints for isolated OPNsense installation."""
from pathlib import Path
import connectivity_edge as edge
from connectivity_operations import saved_settings
from portable_plan import require
from portable_state import read
from proxmox_api import Client, credentials

NEXT={'new':'prepare','media-ready':'upload','uploaded':'attach','media-attached':'start',
      'installer-running':'finish','disk-ready':'boot','disk-running':'confirm','installed-attested':'exit'}
EFFECTS={
    'prepare':'Download and verify the pinned OPNsense image on this computer. No Proxmox connection.',
    'upload':'Upload the verified image to ISO-capable Proxmox storage. No VM is changed.',
    'attach':'Attach the verified installer ISO and change boot order on the owned stopped OPNsense VM.',
    'start':'Start the isolated OPNsense installer VM. Installation inside its console is an operator step.',
    'finish':'After console installation, a new private root password and guest shutdown: detach the ISO and select disk-only boot.',
    'boot':'Start the OPNsense VM from its installed disk. Running does not verify its OS or login.',
    'confirm':'Record your observed OPNsense version and successful console login using the new private credentials.',
    'status':'Read the current guest configuration and power state. Do not change it or resolve pending tasks.'}


def checkpoint(result,output_fn):
    phase=result['phase'];observed=result.get('observed')
    output_fn('Saved OPNsense checkpoint: '+phase)
    output_fn('Recorded work (historical checkpoint): '+{'media-ready':'pinned image prepared locally.', 'uploaded':'image uploaded with a successful checksum-checked task.',
        'media-attached':'installer ISO attached; VM stopped.', 'installer-running':'installer VM started; console installation pending.',
        'disk-ready':'installer ISO removed; VM stopped with disk-only boot.', 'disk-running':'disk-only VM running.',
        'installed-attested':'console installation and login attested by the operator.'}.get(phase,'no guest installation recorded.'))
    output_fn('Observed now: '+(str(observed) if observed else 'no guest OS or power-state check in this action.'))
    output_fn('OS identity and login: '+('operator-attested, not automatically probed.' if result['os_verification']=='operator-attested' else 'not verified.'))
    if result.get('pending'):output_fn('Unresolved request retained: '+result['pending']['action']+'. Resume that action; never reset its journal to retry.')
    output_fn('Not yet available: configured routing/firewall policy, Linux roles, publicly trusted service endpoints, field access or partner connectivity. Network links remain disconnected.')
    if phase=='installer-running':
        output_fn('Operator console step: open this VM in Proxmox Console. Log in to the live installer as installer / opnsense. Install only to this VM\'s sole 20 GiB disk; set a new private root password. Shut down inside the guest when finished; do not reconnect its interfaces. Then choose finish.')
        output_fn('Vendor instructions: https://docs.opnsense.org/manual/install.html')
    elif phase=='disk-running':output_fn('Operator console step: verify the installed OPNsense version and log in with your new credentials. Choose confirm; never enter the password into this wizard.')
    else:output_fn('Next step: '+NEXT.get(phase,'prepare')+(' (network configuration is a subsequent adapter).' if phase=='installed-attested' else '.'))


def menu(folder,plan,*,input_fn=input,output_fn=print,api_factory=Client):
    folder=Path(folder);config=saved_settings(folder,plan)
    require(config is not None,'Allocate the connectivity shells before OPNsense installation.')
    vm=next(vm for vm in config['vms'] if vm['role']=='opnsense')
    output_fn('Stage 2 — OPNsense console installation. Target: '+plan['answers']['proxmox_endpoint']+', node '+plan['answers']['node']+', VM '+str(vm['id'])+'.')
    output_fn('All four network interfaces stay disconnected. Each action stops at a checkpoint; no services or other guests are installed.')
    item=edge.guest_media.catalogue()['opnsense']
    output_fn('Pinned media: OPNsense '+item['version']+'; '+str(item['download_bytes'])+' download bytes; '+item['url'])
    output_fn('Local cache: '+str(folder/'provisioning/media')+'. Prepare may download/decompress it; later actions use the saved verified image.')
    try:
        while True:
            path=folder/'provisioning/edge.json'
            phase='new';pending=None
            if path.exists():
                state=edge.validate(config,read(path));phase=state['phase'];pending=state['pending']
                output_fn('Historical checkpoint (not live health): '+phase)
            output_fn('Next checkpoint: '+(pending['action'] if pending else NEXT[phase]))
            choice=input_fn('Choose prepare, upload, attach, start, finish, boot, confirm, status, or exit [exit]: ').strip().lower() or 'exit'
            if choice in ('exit','q',':cancel'):return
            if choice not in EFFECTS:output_fn('Choose one of the stated checkpoints.');continue
            output_fn(EFFECTS[choice])
            if input_fn('Type '+choice.upper()+' to continue, or anything else to return: ').strip()!=choice.upper():continue
            try:
                kwargs={}
                if choice=='upload':kwargs['storage']=input_fn('Existing ISO storage ID [local]: ').strip() or 'local'
                if choice in ('finish','confirm'):kwargs['operator']=input_fn('Operator name (no passwords): ').strip()
                if choice=='confirm':kwargs['version']=input_fn('Exact OPNsense version observed at the installed console: ').strip()
                if choice!='prepare':
                    token=Path(input_fn('Path to private Proxmox API token file: ').strip()).expanduser()
                    ca=input_fn('Trusted Proxmox CA file; blank uses system trust: ').strip()
                    kwargs['api']=api_factory(plan['answers']['proxmox_endpoint'],credentials(token),Path(ca).expanduser() if ca else None)
                checkpoint(edge.run(folder,plan,choice,**kwargs),output_fn)
            except (ValueError,OSError) as error:
                output_fn('Checkpoint needs attention: '+(str(error) if isinstance(error,ValueError) else 'Local resource error.'))
                output_fn('Progress retained. Inspect unresolved Proxmox tasks/console; no rollback or automatic replay was attempted.')
    except (KeyboardInterrupt,EOFError):output_fn('Stopped. Saved progress retained; inspect any unresolved task before resuming.')

"""Guided offline institutional approvals; server transport is a separate operation."""
from datetime import datetime,timezone
import getpass
import ipaddress
import json
from pathlib import Path
import sys
import time
import regional_agreements as contracts
from regional_workspace import Workspace,PROFILE_FIELDS
from profile_config import load_profile,_identifier
from support_report import write_report
from validate_inventory import hostname


def imported(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>contracts.MAX_BYTES:raise ValueError('Select a small regular partner JSON document')
    return contracts.decode(path.read_bytes())


def export(path,document):
    # Reuse private, exclusive output creation; never overwrite another document.
    contracts.canonical(document);write_report(Path(path),document)
    return {'state':'prepared','document':str(path),'transport':'not-installed-or-verified'}


def interactive():
    if not sys.stdin.isatty():raise ValueError('Approval signing and trust changes need an interactive operator terminal')


def wizard(output,*,input_fn=input,output_fn=print):
    data={'kind':'regional-identity-request','schema_version':1}
    output_fn('Prepare your claimed institution/gateway identity. This creates no network access. Use :cancel to stop.')
    fields=[('institution_id','Institution identifier',_identifier),('regional_controller','Regional controller DNS name',hostname),
            ('gateway_node','Enrolled regional gateway node name',_identifier)]
    for field,label,valid in fields:
        while True:
            value=input_fn(label+': ').strip()
            if value==':cancel':return {'state':'cancelled'}
            if valid(value):data[field]=value;break
            output_fn('Use the requested name format.')
    while True:
        value=input_fn('Gateway regional IPv4 from node status (100.64.0.0/10): ').strip()
        if value==':cancel':return {'state':'cancelled'}
        try:valid=ipaddress.ip_address(value) in ipaddress.ip_network('100.64.0.0/10') and value!='100.100.100.100'
        except ValueError:valid=False
        if valid:data['gateway_ipv4']=value;break
        output_fn('Use the actual enrolled regional IPv4, not an internal or public address.')
    while True:
        choice=input_fn('Services to declare: matrix, nextcloud or both: ').strip()
        if choice==':cancel':return {'state':'cancelled'}
        if choice in ('matrix','nextcloud','both'):break
        output_fn('Choose one of the listed service packages.')
    data['services']={}
    for name in (['matrix','nextcloud'] if choice=='both' else [choice]):
        while True:
            value=input_fn('Permanent '+name+' service DNS name: ').strip()
            if value==':cancel':return {'state':'cancelled'}
            if hostname(value) and value not in data['services'].values():data['services'][name]=value;break
            output_fn('Use a distinct application DNS name.')
    contracts.identity(b'\x01'*32,**{k:data[k] for k in PROFILE_FIELDS})
    output_fn(json.dumps(data,indent=2))
    if input_fn('Type SAVE to prepare this identity request: ').strip()!='SAVE':return {'state':'cancelled'}
    return export(output,data)


def action(args):
    command=args.regional_action
    if command=='setup':return wizard(args.output_file)
    if command=='inspect':
        document=imported(args.document)
        if document.get('kind')=='regional-agreement':
            offered=contracts.verify_agreement(document)
            return {'state':'signature-verified','agreement_id':offered['agreement_id'],'expires_at':offered['expires_at'],
                    'local_trust':'not-evaluated','transport':'not-installed-or-verified'}
        payload=document.get('payload')
        if not isinstance(payload,dict):raise ValueError('Unsupported regional signature envelope')
        kind=payload.get('kind')
        if kind=='regional-identity':
            identity=contracts.verify_identity(document)
            return {'state':'signature-verified','identity':identity,'fingerprint':contracts.fingerprint(document),'institution_authenticity':'confirm-fingerprint-independently'}
        if kind=='regional-offer':
            offered=contracts.verify_offer(document)
            return {'state':'signature-verified','agreement_id':offered['agreement_id'],'services':offered['services'],
                    'bilateral_acceptance':'missing','transport':'not-installed-or-verified'}
        raise ValueError('Unsupported regional document')
    workspace=Workspace(args.workspace)
    if command=='init':
        interactive();profile=load_profile(str(args.profile))
        print('Create or resume a private operator approval workspace. Keep its encrypted signing key and passphrase independently recoverable.')
        passphrase=getpass.getpass('Signing-key passphrase (at least 12 characters): ')
        if not (workspace.base/'signing-key.pem').exists() and passphrase!=getpass.getpass('Repeat passphrase: '):raise ValueError('Passphrases differ')
        return workspace.initialize(profile,passphrase)
    if command=='export-identity':return export(args.output_file,workspace.identity())
    if command=='status':return workspace.status(now=int(time.time()))
    if command=='export-agreement':
        document=workspace._state()['agreements'].get(args.agreement_id)
        if document is None:raise ValueError('Select an existing agreement identifier')
        return export(args.output_file,document)
    if command=='import-agreement':return workspace.import_agreement(imported(args.document))
    interactive()
    if command=='approve':
        document=imported(args.document);identity=contracts.verify_identity(document)
        print(json.dumps(identity,indent=2));print('Public-key fingerprint: '+contracts.fingerprint(document))
        confirmed=input('Enter the complete fingerprint confirmed with this institution through an independent channel: ').strip()
        return workspace.approve(document,confirmed_fingerprint=confirmed)
    if command=='offer':
        if not 1<=args.days<=90:raise ValueError('Choose an agreement duration of 1–90 days')
        now=int(time.time());passphrase=getpass.getpass('Signing-key passphrase: ')
        document=workspace.offer(args.peer_fingerprint,args.services,passphrase=passphrase,now=now,expires_at=now+args.days*86400)
        return export(args.output_file,document)
    if command=='accept':
        document=imported(args.document);offered=contracts.verify_offer(document)
        print('Requested services: '+', '.join(offered['services']))
        print('Initiator fingerprint: '+contracts.fingerprint(offered['initiator']))
        print('Expires: '+datetime.fromtimestamp(offered['expires_at'],timezone.utc).isoformat())
        if input('Type ACCEPT to sign this exact reviewed offer: ').strip()!='ACCEPT':return {'state':'cancelled'}
        accepted=workspace.accept(document,passphrase=getpass.getpass('Signing-key passphrase: '),now=int(time.time()))
        return export(args.output_file,accepted)
    if command=='revoke':
        print('This revokes approval in the operator workspace. Gateway enforcement requires the updated policy.')
        if input('Type REVOKE '+args.agreement_id+' to continue: ').strip()!='REVOKE '+args.agreement_id:return {'state':'cancelled'}
        return workspace.revoke(args.agreement_id)
    raise ValueError('Unsupported regional operation')

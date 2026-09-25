"""Portable phase commands: local preparation and explicitly selected remote actions."""
from pathlib import Path
from portable_plan import load,validate,preview,require
from proxmox_api import Client,credentials


def action(args):
    plan=validate(load(args.plan));verb=args.portable_action
    if verb=='preview':return preview(plan)
    if verb.startswith(('applications-','frontend-')):
        from portable_application_commands import action as applications_action
        return applications_action(args,plan)
    if verb.startswith('network-'):
        require(args.settings is not None, 'Supply --settings with the reviewed local network settings JSON.')
        from portable_network import derive
        settings=load(args.settings);derive(plan,settings)
        if verb=='network-check':
            from portable_network_probe import check
            return check(plan,settings)
        require(args.output_dir is not None, 'Supply --output-dir for the private network kit.')
        from portable_network_bundle import prepare,verify
        if verb=='network-prepare':return prepare(plan,settings,args.output_dir)
        if verb=='network-verify':return verify(args.output_dir,plan=plan,settings=settings)
        raise ValueError('Unsupported network operation.')
    cache=Path(args.media_dir or args.plan.parent/'media')
    state=Path(args.state_dir or args.plan.parent/'guest-state')
    if verb=='media-fetch':
        from guest_media import prepare
        require(args.kind in ('ubuntu','opnsense'),'Select --kind ubuntu or opnsense.')
        return dict(prepare(args.kind,cache),state='media-verified',execution='not-performed')
    if verb=='upload-abandon':
        from guest_upload import abandon
        return abandon(plan,args.kind,state)
    require(args.token_file is not None,'Supply --token-file pointing to a private API credential file.')
    api=Client(plan['proxmox']['endpoint'],credentials(args.token_file),args.ca_file)
    if verb in ('check','allocate-shells'):
        from proxmox_provision import check,allocate
        return (check if verb=='check' else allocate)(plan,api)
    if verb=='media-upload':
        from guest_upload import upload
        require(args.kind in ('ubuntu','opnsense'),'Select --kind ubuntu or opnsense.')
        return upload(plan,args.kind,cache,args.iso_storage,api,state)
    from guest_upload import receipt
    import guest_installation as guest
    require(args.role in guest.MODULES,'Select --role edge, dns, nginx, chat, files or partner.')
    medium=receipt(plan,'opnsense' if args.role=='edge' else 'ubuntu',state,api)
    if verb=='guest-finish':return guest.finish(plan,args.role,medium,api,state,operator=args.operator)
    if verb=='guest-confirm-login':return guest.confirm_login(plan,args.role,medium,api,state,operator=args.operator)
    handlers={'guest-attach':guest.attach,'guest-start':guest.start,'guest-boot':guest.boot,'guest-status':guest.status}
    require(verb in handlers,'Unsupported portable action.')
    return handlers[verb](plan,args.role,medium,api,state)

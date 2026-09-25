"""Wizard/CLI boundary for portable applications; mutation only on selected VM."""
from portable_plan import require,load


def action(args,plan):
    verb=args.portable_action
    if verb in ('applications-prepare','applications-verify'):
        require(args.settings is not None and args.output_dir is not None,'Supply --settings and --output-dir for the private application kit.')
        from portable_application_bundle import prepare,verify
        if verb=='applications-prepare':return prepare(plan,load(args.settings),args.output_dir)
        return verify(args.output_dir,plan,load(args.settings))
    import sys
    from backup_operations import require_platform
    require_platform()
    require(sys.stdin.isatty(),'Run installation from an interactive console on the intended VM.')
    from portable_application_install import backend,frontend
    if verb=='applications-apply':
        require(args.role in ('chat','files'),'Choose --role chat or files for this dedicated VM.')
        phrase='INSTALL PORTABLE '+args.role+' '+plan['site']
        print('Install '+args.role+' on this VM, with the saved local LAN identity and no Headscale enrollment.')
        if input('Type '+phrase+' to proceed: ').strip()!=phrase:return {'state':'cancelled'}
        return backend(plan,args.role)
    require(verb in ('frontend-apply','frontend-renew'),'Unsupported application action.')
    require(args.settings is not None and args.tls_dir is not None,'Supply --settings and --tls-dir on the intended NGINX VM.')
    phrase=('RENEW' if verb=='frontend-renew' else 'INSTALL')+' FRONTEND '+plan['site']
    print('Configure the dedicated local HTTPS frontend on this VM using the saved site and network settings.')
    if input('Type '+phrase+' to proceed: ').strip()!=phrase:return {'state':'cancelled'}
    return frontend(plan,load(args.settings),args.tls_dir,renew=verb=='frontend-renew')


def wizard_step(plan,folder,*,input_fn=input,output_fn=print):
    from portable_state import read
    from portable_application_bundle import prepare,verify
    from portable_wizard import ask
    settings_path=folder/'network.json'
    require(settings_path.exists(),'Prepare local network settings in step 8 first.')
    settings=read(settings_path)
    destination=folder/'applications'
    if destination.exists():result=verify(destination,plan,settings)
    else:
        output_fn('Prepare private application profiles and the local NGINX configuration. No VM will be changed.')
        if ask('Prepare application kit? yes/no','yes',input_fn=input_fn)!='yes':return {'state':'cancelled'}
        result=prepare(plan,settings,destination)
    output_fn('Application preparation is available at '+str(destination/'START-HERE.md')+'. Run deployment steps on the intended VMs, then test offline login and recovery.')
    return result

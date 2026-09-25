"""Prepare file-service settings without installing software or collecting secrets."""
from pathlib import Path
from profile_config import _identifier
from validate_inventory import hostname
from support_report import write_report
from nextcloud_contracts import validate


def wizard(output,*,input_fn=input,output_fn=print):
    profile={'kind':'nextcloud-services','schema_version':1,'tls_mode':'supplied'}
    output_fn('Prepare Nextcloud on its own enrolled Ubuntu VM. Nothing is installed here. Type :cancel to stop.')
    for field,label in [('institution_id','Institution identifier'),('node_name','Enrolled local node name'),
                        ('nextcloud_hostname','Permanent file-service DNS name'),('tls_certificate','Absolute trusted certificate-chain path ON THE FILE SERVER'),
                        ('tls_private_key','Absolute private-key path ON THE FILE SERVER')]:
        while True:
            value=input_fn(label+': ').strip()
            if value==':cancel':return {'state':'cancelled'}
            valid=hostname(value) if field.endswith('_hostname') else Path(value).is_absolute() if field.startswith('tls_') else _identifier(value)
            if not valid:output_fn('Use a valid identifier, actual DNS name or absolute path as requested.');continue
            profile[field]=value;break
    if validate(profile):raise ValueError('File-service settings are invalid; use distinct certificate and private-key paths')
    output_fn('Review https://'+profile['nextcloud_hostname']+' on '+profile['node_name']+'. Accounts and deployment are separate next steps.')
    if input_fn('Type SAVE to write this private profile: ').strip()!='SAVE':return {'state':'cancelled'}
    write_report(Path(output),profile)
    return {'state':'prepared','configuration_file':str(output),'installation':'not-performed'}

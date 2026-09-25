"""Prepare a non-secret local Matrix profile without changing any server."""
from pathlib import Path
from profile_config import _identifier
from validate_inventory import hostname
from support_report import write_report
from service_contracts import validate


def wizard(output,*,input_fn=input,output_fn=print):
    values={'kind':'matrix-services','schema_version':1,'tls_mode':'supplied'}
    output_fn('Prepare Matrix and Element settings. This does not install services. Type :cancel to stop.')
    output_fn('Use the same institution/node names as the enrolled local node. Matrix account identities permanently include the Matrix hostname.')
    fields=[('institution_id','Institution identifier'),('node_name','Enrolled local node name'),
            ('matrix_hostname','Stable Matrix DNS name'),('element_hostname','Separate Element web DNS name'),
            ('tls_certificate','Absolute certificate-chain file path ON THE SERVICE NODE'),
            ('tls_private_key','Absolute private-key file path ON THE SERVICE NODE')]
    for field,label in fields:
        while True:
            value=input_fn(label+': ').strip()
            if value==':cancel':return {'state':'cancelled'}
            if field in ('institution_id','node_name') and not _identifier(value):output_fn('Use a lowercase identifier.');continue
            if field.endswith('_hostname') and not hostname(value):output_fn('Use an actual DNS name.');continue
            if field=='element_hostname' and value==values['matrix_hostname']:output_fn('Element needs a separate browser origin.');continue
            if field.startswith('tls_') and not Path(value).is_absolute():output_fn('Use an absolute local path.');continue
            values[field]=value;break
    errors=validate(values)
    if errors:raise ValueError('; '.join(errors))
    output_fn('Accounts will look like @name:'+values['matrix_hostname']+'. Registration and federation start disabled. Supplied certificates require your renewal procedure.')
    if input_fn('Type SAVE to write this private profile: ').strip()!='SAVE':return {'state':'cancelled'}
    write_report(Path(output),values)
    return {'state':'prepared','configuration_file':str(output),'installation':'not-performed'}

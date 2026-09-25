"""Prepare public backup connection settings through questions; no server changes."""
from pathlib import Path
from backup_contracts import validate,valid_host_key
from profile_config import _identifier
from support_report import write_report


def wizard(output,*,input_fn=input,output_fn=print):
    answers={'kind':'backup-profile','schema_version':1}
    fields=[('institution_id','Institution/environment identifier'),('node_name','Source node name'),
            ('role','Source role: controller, relay or peer'),('backup_host','Backup destination IPv4 or DNS name'),
            ('backup_port','SFTP port (2222 for the project storage node)'),
            ('backup_host_key','Independently verified destination key: ssh-ed25519 BASE64')]
    output_fn('Prepare backup settings only. Keep passwords and private keys out of this file. Type :cancel to stop.')
    for field,label in fields:
        while True:
            value=input_fn(label+': ').strip()
            if value==':cancel': return {'state':'cancelled'}
            if field=='backup_port':
                if not value.isdigit() or not 1<=int(value)<=65535: output_fn('Use a valid numeric port.');continue
                value=int(value)
            elif field in ('institution_id','node_name') and not _identifier(value): output_fn('Use a lowercase identifier.');continue
            elif field=='role' and value not in ('controller','relay','peer'): output_fn('Choose one of the listed roles.');continue
            elif field=='backup_host_key' and not valid_host_key(value): output_fn('Provide the complete Ed25519 public host key without comments.');continue
            answers[field]=value;break
    errors=validate(answers)
    if errors: raise ValueError('; '.join(errors))
    write_report(Path(output),answers)
    return {'state':'prepared','installation':'not-performed','configuration_file':str(output)}

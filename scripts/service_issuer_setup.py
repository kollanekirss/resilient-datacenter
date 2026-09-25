"""Non-secret certificate-request wizard; makes no provider calls."""
from pathlib import Path
from service_issuer_contracts import validate
from support_report import write_report


def wizard(output,*,input_fn=input,output_fn=print,package='matrix'):
    if package not in ('matrix','nextcloud'):raise ValueError('Unsupported certificate application')
    profile={'kind':'nextcloud-certificates' if package=='nextcloud' else 'service-certificates','schema_version':1,'provider':'cloudflare','acme_agree_terms':True}
    output_fn('Prepare private-service certificates using Cloudflare DNS and Let’s Encrypt. No public HTTP listener is needed. Type :cancel to stop.')
    names=[('nextcloud_hostname','Permanent file-service DNS name')] if package=='nextcloud' else [('matrix_hostname','Permanent Matrix DNS name'),('element_hostname','Separate Element DNS name')]
    for field,label in [('institution_id','Enrolled institution identifier'),('node_name','Enrolled node name'),*names,('acme_email','Certificate account email')]:
        answer=input_fn(label+': ').strip()
        if answer==':cancel':return {'state':'cancelled'}
        profile[field]=answer
    errors=validate(profile)
    if errors:raise ValueError('; '.join(errors))
    output_fn('Review the current certificate issuer terms at https://letsencrypt.org/repository/. DNS provider access and renewal are independent dependencies; save emergency account access separately.')
    if input_fn('Type AGREE to accept those terms and save the request: ').strip()!='AGREE':return {'state':'cancelled'}
    write_report(Path(output),profile)
    return {'state':'prepared','configuration_file':str(output),'certificate_issued':False,
            'next_step':'Run '+('files' if package=='nextcloud' else 'services')+' issuer issue with this file on the enrolled Ubuntu node.'}

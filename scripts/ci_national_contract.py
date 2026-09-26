"""Pure safety/evidence contracts for the disposable domestic-isolation exercise."""
import ipaddress
from pathlib import Path
import re

REQUIRED=('baseline','outside_cut','field_restart','field_address_change','relay_loss',
          'federation_after_cut','partner_partition','partner_reconnection','authority_return')


def addresses(values):
    result=[]
    for value in values:
        address=ipaddress.ip_address(value)
        if address not in ipaddress.ip_network('172.29.10.0/24') or int(str(address).split('.')[-1]) not in range(2,241):
            raise ValueError('Use only declared domestic fixture endpoints')
        result.append(str(address))
    if not result or len(set(result))!=len(result):raise ValueError('Declare unique domestic endpoints')
    return ', '.join(sorted(result))


def cut_rules(bootstrap,participants=None):
    bootstrap=addresses(bootstrap);participants=addresses(participants) if participants is not None else bootstrap
    # No broad established-flow exception: pre-cut foreign connections must stop.
    # Replies are restricted to declared domestic participants. New original
    # flows reach only DNS, HTTPS control/relay and STUN bootstrap endpoints.
    return '''table inet rdc_domestic_cut {
chain output { type filter hook output priority -80; policy accept;
oifname "wan0" ip daddr { '''+bootstrap+''' } tcp dport { 53, 443 } accept
oifname "wan0" ip daddr { '''+bootstrap+''' } udp dport { 53, 3478 } accept
oifname "wan0" ip daddr { '''+participants+''' } ct direction reply accept
oifname "wan0" counter drop
}
}'''


def restart_command(name,root):
    if not re.fullmatch(r'(north|south)-(user|service|gateway)',name):raise ValueError('Unexpected fixture client')
    root=Path(root);folder=root/name
    return ['ip','netns','exec',name,str(root/'tailscaled'),'--state='+str(folder/'tailscaled.state'),
            '--socket='+str(folder/'tailscale.sock'),'--tun=tailscale0','--port=41641']


def evidence(phases,controller_loss):
    if set(phases)!=set(REQUIRED) or any(value is not True for value in phases.values()):raise ValueError('Required isolation phase did not pass')
    if any(value not in ('available','unavailable','not-exercised') for value in controller_loss.values()):raise ValueError('Invalid observation')
    return {'state':'domestic-isolation-lab-passed','phases':phases,'controller_loss':controller_loss,
            'controller_high_availability':'not-proven','public_certificate_device_acceptance':'not-tested',
            'physical_carrier_diversity':'not-tested','mobile_device_clients':'not-tested',
            'dns':'one-isolated-domestic-resolver','field_uplink_change':'simulated-underlay-address-change',
            'notice':'Two institutions on one disposable runner; synthetic outside-region boundary, not geographic independence.'}


def partner_rules(value):
    address=ipaddress.ip_address(value)
    if address not in ipaddress.ip_network('100.64.0.0/10'):raise ValueError('Use a declared overlay partner')
    return '\n'.join(('table inet rdc_partner_cut {',
        'chain output { type filter hook output priority -90; policy accept;',
        'oifname "tailscale0" ip daddr '+str(address)+' counter drop',
        '}', '}', ''))

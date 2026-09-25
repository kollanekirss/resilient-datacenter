"""Only reviewed complete component sets, including explicit upgrade predecessors."""
import json
from pathlib import Path
import re


def current(package):
    if package=='matrix':from service_contracts import image_pins
    elif package=='nextcloud':from nextcloud_contracts import image_pins
    else:raise ValueError('No reviewed application upgrade for this package')
    return image_pins()


def path(package):
    data=json.loads(Path(__file__).with_name('upgrade_images.json').read_text())
    if not isinstance(data,dict) or set(data)!={'schema_version','paths'} or type(data['schema_version']) is not int or data['schema_version']!=1 or not isinstance(data['paths'],list) or len(data['paths'])!=2:
        raise ValueError('Unknown upgrade catalogue')
    if [item.get('package') for item in data['paths'] if isinstance(item,dict)]!=['matrix','nextcloud']:raise ValueError('Ambiguous upgrade packages')
    for item in data['paths']:
        if set(item)!={'package','source','target'}:raise ValueError('Unknown upgrade path fields')
        target=current(item['package'])
        if item['target']!=target or not isinstance(item['source'],dict) or set(item['source'])!=set(target):raise ValueError('Upgrade path differs from the current reviewed target')
        component='synapse' if item['package']=='matrix' else 'nextcloud'
        for name,pin in item['source'].items():
            if name!=component:
                if pin!=target[name]:raise ValueError('Unreviewed companion component transition')
                continue
            if (not isinstance(pin,dict) or set(pin)!=set(target[name]) or pin['platform']!='linux/amd64' or
                not re.fullmatch(re.escape(target[name]['image'].split('@')[0])+r'@sha256:[a-f0-9]{64}',pin['image']) or
                not re.fullmatch(r'sha256:[a-f0-9]{64}',pin['config_digest']) or
                not re.fullmatch(r'\d+\.\d+\.\d+',pin['version'])):raise ValueError('Predecessor requires a reviewed fixed image identity')
        old=tuple(map(int,item['source'][component]['version'].split('.')));new=tuple(map(int,target[component]['version'].split('.')))
        if not old<new or old[0]!=new[0]:raise ValueError('Downgrades and major-version jumps are unsupported')
    return next((item for item in data['paths'] if item['package']==package),None) or _unsupported()


def _unsupported():raise ValueError('Unsupported upgrade package')


def predecessor(package):return path(package)['source']


def for_owner(application):
    if not isinstance(application,dict) or application.get('packages') not in (['matrix'],['nextcloud']):raise ValueError('Unsupported application identity')
    package=application['packages'][0]
    for pins in (current(package),predecessor(package)):
        if application.get('images')=={key:value['image'] for key,value in pins.items()}:return pins
    raise ValueError('Installed image set has no reviewed compatibility contract')


def transition(package,installed):
    reviewed=path(package)
    if installed==reviewed['target']:return None
    if installed!=reviewed['source']:raise ValueError('No reviewed transition from these installed components')
    return reviewed

"""Collect only the remaining site-specific network facts; never guess discovery."""
import ipaddress
from portable_network import derive, LINUX_ROLES
from portable_state import read, write
from portable_plan import require


def step(plan, folder, *, input_fn=input, output_fn=print):
    from portable_wizard import ask, Cancel
    from portable_network_bundle import prepare, verify
    path = folder / 'network.json'; kit = folder / 'network-kit'
    if path.exists():
        settings = read(path); derive(plan, settings)
    else:
        output_fn('Prepare local network settings. Check addresses and guest interface names through the console; these are not discovered automatically.')
        settings = {'schema_version': 1,
                    'administrator_address': ask('Static administrator IPv4 on management network', input_fn=input_fn),
                    'proxmox_address': ask('Existing Proxmox management IPv4', input_fn=input_fn),
                    'linux_interfaces': {}, 'dhcp': {}, 'clock': {}}
        for role in LINUX_ROLES:
            settings['linux_interfaces'][role] = ask(role + ' observed Linux Ethernet interface', 'ens18', input_fn=input_fn)
        net = ipaddress.ip_network(plan['networks']['staff']['cidr'])
        settings['dhcp']['start'] = ask('Staff DHCP first address', str(net.network_address + net.num_addresses // 2), input_fn=input_fn)
        settings['dhcp']['end'] = ask('Staff DHCP last address', str(net.broadcast_address - 1), input_fn=input_fn)
        mode = ask('Clock mode: host-rtc or local-source', 'host-rtc', input_fn=input_fn)
        settings['clock'] = {'mode': mode, 'source': ask('Independent local NTP IPv4 in management subnet', input_fn=input_fn) if mode == 'local-source' else None}
        policy = derive(plan, settings)
        output_fn('DNS/time: ' + plan['vms']['dns']['address'] + '; edge management: ' + plan['vms']['edge']['address'] +
                  '; clock: ' + mode + '. Correct UTC still needs independent verification. WAN and partner connections stay disconnected.')
        if ask('Type SAVE to retain these settings, or :cancel', input_fn=input_fn) != 'SAVE': raise Cancel()
        write(path, settings)
    choice = ask('Local network action: prepare, verify, check, or back', 'verify' if kit.exists() else 'prepare', input_fn=input_fn)
    if choice == 'back': return
    if choice == 'prepare':
        result = prepare(plan, settings, kit)
        output_fn(result['notice']); output_fn('Follow ' + str(kit / 'START-HERE.md'))
    elif choice == 'verify': output_fn(verify(kit, plan=plan, settings=settings)['notice'])
    elif choice == 'check':
        from portable_network_probe import check
        result = check(plan, settings)
        for item in result['checks']: output_fn(item['outcome'].upper() + ': ' + item['check'])
        output_fn(result['notice'])
    else: output_fn('Select one of the listed local network actions.')

"""Bounded literal-IP client probes. Replies prove neither isolation nor UTC trust."""
import ipaddress
import secrets
import socket
import struct
import time
from portable_plan import require
from portable_network import derive

TIMEOUT = 2.0
NTP_EPOCH = 2208988800


def dns_query(host, identifier):
    name = b''.join(bytes([len(label)]) + label.encode('ascii') for label in host.split('.')) + b'\0'
    return struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + name + struct.pack('!2H', 1, 1)


def dns_name(packet, position):
    labels = []; seen = set(); end = None
    while True:
        require(position < len(packet) and position not in seen and len(seen) < 128, 'Malformed DNS name.')
        seen.add(position); size = packet[position]
        if size & 0xc0 == 0xc0:
            require(position + 1 < len(packet), 'Truncated DNS pointer.')
            if end is None: end = position + 2
            position = ((size & 0x3f) << 8) | packet[position + 1]
            continue
        require(size <= 63, 'Invalid DNS label.')
        position += 1
        if size == 0: return '.'.join(labels), end if end is not None else position
        require(position + size <= len(packet), 'Truncated DNS label.')
        try: labels.append(packet[position:position + size].decode('ascii').lower())
        except UnicodeError: raise ValueError('Invalid DNS name encoding.') from None
        position += size


def dns_answer(packet, request, expected):
    require(12 <= len(packet) <= 4096, 'Invalid DNS response length.')
    identifier, flags, qd, an, ns, ar = struct.unpack('!6H', packet[:12])
    require(packet[:2] == request[:2] and flags & 0x8000 and not flags & 0x7a00 and qd == 1,
            'Mismatched or truncated DNS response.')
    question, offset = dns_name(packet, 12); wanted, qend = dns_name(request, 12)
    require(question == wanted and packet[offset:offset + 4] == request[qend:qend + 4], 'DNS question differs.')
    offset += 4; addresses = []
    for index in range(an + ns + ar):
        host, offset = dns_name(packet, offset)
        require(offset + 10 <= len(packet), 'Truncated DNS record.')
        kind, cls, ttl, size = struct.unpack('!HHIH', packet[offset:offset + 10]); offset += 10
        require(offset + size <= len(packet), 'Truncated DNS data.')
        if index < an:
            require(host == wanted and kind == 1 and cls == 1 and size == 4, 'Unexpected DNS answer type or owner.')
            addresses.append(socket.inet_ntoa(packet[offset:offset + size]))
        offset += size
    require(offset == len(packet), 'Unexpected trailing DNS data.')
    if expected is None:
        require(flags & 15 in (3, 5) and not addresses, 'Unrelated DNS names should be refused or absent.')
    else:
        require(flags & 15 == 0 and addresses and set(addresses) == {expected}, 'Local DNS returned the wrong address or no answer.')
    return True


def receive(stream, count, deadline):
    result = b''
    while len(result) < count:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Probe deadline exceeded.')
        stream.settimeout(remaining)
        part = stream.recv(count - len(result))
        require(part, 'Connection closed during response.')
        result += part
    return result


def dns_probe(address, host, expected, *, tcp=False, port=53):
    require(ipaddress.ip_address(address).version == 4, 'Use a literal IPv4 resolver address.')
    request = dns_query(host, secrets.randbelow(65536)); deadline = time.monotonic() + TIMEOUT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
        stream.settimeout(TIMEOUT); stream.connect((address, port))
        if tcp:
            stream.sendall(struct.pack('!H', len(request)) + request)
            size = struct.unpack('!H', receive(stream, 2, deadline))[0]
            require(12 <= size <= 4096, 'DNS TCP response is too large or short.')
            packet = receive(stream, size, deadline)
        else:
            stream.send(request); packet = stream.recv(4097)
    return dns_answer(packet, request, expected)


def timestamp(unix_time):
    value = unix_time + NTP_EPOCH
    return struct.pack('!II', int(value) % (2**32), int((value % 1) * (2**32)))


def ntp_query(now):
    packet = bytearray(48); packet[0] = 0x23; packet[40:48] = timestamp(now)
    return bytes(packet)


def ntp_time(raw, near):
    seconds, fraction = struct.unpack('!II', raw)
    value = seconds + fraction / 2**32 - NTP_EPOCH
    return value + round((near - value) / 2**32) * 2**32


def ntp_answer(packet, request, sent, received):
    require(len(packet) == 48 and packet[0] & 7 == 4 and (packet[0] >> 3) & 7 in (3, 4)
            and packet[0] >> 6 != 3 and 1 <= packet[1] <= 15, 'NTP server is malformed or unsynchronised.')
    require(packet[24:32] == request[40:48] and packet[32:40] != b'\0' * 8 and packet[40:48] != b'\0' * 8,
            'NTP response does not match the request.')
    t2, t3 = ntp_time(packet[32:40], sent), ntp_time(packet[40:48], sent)
    require(0 <= received - sent <= TIMEOUT + .5 and t3 >= t2, 'Invalid NTP timing.')
    offset = ((t2 - sent) + (t3 - received)) / 2
    require(abs(offset) <= 5, 'Local clock differs from this client by more than five seconds; inspect both clocks.')
    return {'stratum': packet[1], 'offset_seconds': round(offset, 6), 'utc_verified': False}


def ntp_probe(address, *, port=123):
    require(ipaddress.ip_address(address).version == 4, 'Use a literal IPv4 time server address.')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(TIMEOUT); stream.connect((address, port))
        sent = time.time(); request = ntp_query(sent); stream.send(request)
        packet = stream.recv(513); received = time.time()
    return ntp_answer(packet, request, sent, received)


def check(plan, settings, *, dns_probe=dns_probe, ntp_probe=ntp_probe):
    policy = derive(plan, settings); address = plan['vms']['dns']['address']; checks = []
    def run(name, operation):
        try:
            evidence = operation()
            checks.append({'check': name, 'outcome': 'pass', 'evidence': evidence})
        except (ValueError, OSError):
            checks.append({'check': name, 'outcome': 'fail', 'detail': 'No matching valid response within the probe limits; check addressing, policy, service and clocks.'})
    for host, expected in policy['dns_records'].items():
        for tcp in (False, True):
            run(host + (' DNS/TCP' if tcp else ' DNS/UDP'), lambda h=host, e=expected, t=tcp: dns_probe(address, h, e, tcp=t))
    unrelated = 'rdc-' + secrets.token_hex(8) + '.example.net'
    run('unrelated DNS refused', lambda: dns_probe(address, unrelated, None))
    run('local NTP relative to this client', lambda: ntp_probe(address))
    passed = all(item['outcome'] == 'pass' for item in checks)
    return {'state': 'network-probes-passed' if passed else 'network-check-failed', 'checks': checks,
            'clock_mode': settings['clock']['mode'], 'utc_verified': False, 'wan_isolation_verified': False,
            'applications_verified': False, 'firewall_enforcement_verified': False,
            'notice': ('Client DNS/time probes passed. ' if passed else 'One or more client probes failed. ') +
                      'These observations do not establish correct UTC, DHCP, physical isolation, firewall enforcement or application readiness.'}

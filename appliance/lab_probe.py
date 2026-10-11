"""Bounded lab wire clients and Ethernet observations, without pass labels.

Caller chooses an isolated network namespace/guest. These clients use numeric
IPv4 destinations, never proxy settings or public name resolution. DNS/NTP wire
formats follow RFC 1035 / RFC 5905; DHCP observations follow RFC 2131.
"""
import errno
import hashlib
import ipaddress
import re
import secrets
import socket
import ssl
import struct
import time

MAX_REPLY = 8192


def _need(condition):
    if not condition:
        raise ValueError('malformed lab observation')


def _nonce(nonce):
    _need(type(nonce) is str and re.fullmatch(r'[A-Za-z0-9-]{1,63}', nonce) is not None)
    return nonce


def dns_request(nonce, *, transaction=None, query_name=None):
    _nonce(nonce)
    transaction = secrets.randbelow(65535) + 1 if transaction is None else transaction
    _need(type(transaction) is int and 0 <= transaction <= 65535)
    parts = (nonce, 'lab', 'invalid') if query_name is None else query_name.split('.') if type(query_name) is str else ()
    _need(parts and sum(map(len, parts)) + len(parts) <= 254
          and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in parts))
    name = b''.join(bytes((len(part),)) + part.encode('ascii') for part in parts) + b'\0'
    return struct.pack('!6H', transaction, 0x100, 1, 0, 0, 0) + name + struct.pack('!2H', 1, 1)


def _dns_name(raw, offset):
    labels, visited, end = [], set(), None
    while True:
        _need(0 <= offset < len(raw) and offset not in visited and len(visited) < 128)
        visited.add(offset)
        size = raw[offset]; offset += 1
        if size & 0xc0 == 0xc0:
            _need(offset < len(raw))
            end = offset + 1 if end is None else end
            offset = ((size & 0x3f) << 8) | raw[offset]
            continue
        _need(size <= 63 and offset + size <= len(raw))
        if size == 0:
            return '.'.join(labels).lower(), end if end is not None else offset
        label = raw[offset:offset+size].decode('ascii')
        _need(re.fullmatch(r'[A-Za-z0-9-]+', label) is not None)
        labels.append(label); offset += size
        _need(sum(map(len, labels)) + len(labels) <= 254)


def parse_dns(raw, request):
    _need(type(raw) is bytes and 12 <= len(raw) <= MAX_REPLY)
    transaction, flags, questions, answers, _, _ = struct.unpack('!6H', raw[:12])
    _need(raw[:2] == request[:2] and flags & 0x8000 and not flags & 0x7800
          and not flags & 0x200 and questions == 1 and 0 < answers <= 64 and not flags & 15)
    expected, request_end = _dns_name(request, 12)
    question, offset = _dns_name(raw, 12)
    _need(expected == question and raw[offset:offset+4] == request[request_end:request_end+4] == b'\0\1\0\1')
    offset += 4
    records = []
    for _ in range(answers):
        owner, offset = _dns_name(raw, offset)
        _need(offset + 10 <= len(raw))
        kind, family, ttl, size = struct.unpack('!HHIH', raw[offset:offset+10]); offset += 10
        _need(offset + size <= len(raw))
        value = socket.inet_ntoa(raw[offset:offset+4]) if kind == 1 and family == 1 and size == 4 else None
        if kind == 5 and family == 1:
            value, end = _dns_name(raw, offset)
            _need(end == offset + size)
        records.append((owner, kind, value)); offset += size
    owners = {expected}
    for _ in range(len(records)):
        owners.update(value for owner, kind, value in records if owner in owners and kind == 5 and value)
    addresses = sorted({value for owner, kind, value in records if owner in owners and kind == 1 and value})
    _need(addresses)
    return {'transaction': transaction, 'question': question, 'addresses': addresses}


def probe_network(kind, *, host, port=None, nonce, source=None, timeout_s=5, ca_file=None, server_name=None, query_name=None):
    """Return facts from one finite probe; denial/allowance is a scenario decision."""
    _nonce(nonce)
    _need(kind in ('tcp', 'http', 'https', 'dns', 'ntp'))
    _need(query_name is None or kind == 'dns')
    dns_query = dns_request(nonce, query_name=query_name) if kind == 'dns' else None
    host = str(ipaddress.IPv4Address(host))
    source = str(ipaddress.IPv4Address(source)) if source is not None else None
    _need(type(timeout_s) in (int, float) and not isinstance(timeout_s, bool) and 0 < timeout_s <= 30)
    port = {'tcp': 18080, 'http': 80, 'https': 443, 'dns': 53, 'ntp': 123}[kind] if port is None else port
    _need(type(port) is int and 1 <= port <= 65535)
    context = None
    if kind == 'https':
        _need(ca_file is not None and type(server_name) is str and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', server_name))
        context = ssl.create_default_context(cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    start = time.monotonic(); deadline = start + timeout_s
    result = {'attempted': True, 'connected': False, 'protocol': kind, 'destination': host,
              'port': port, 'source': source, 'nonce': nonce, 'response_nonce': None,
              'error': None, 'response_hex': ''}
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0: raise TimeoutError()
        return value
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind in ('dns', 'ntp') else socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining())
            if source: sock.bind((source, 0))
            sock.connect((host, port))
            result['source'] = sock.getsockname()[0]
            # UDP connect chooses a destination; it does not prove a listener.
            result['connected'] = kind not in ('dns', 'ntp')
            if kind in ('dns', 'ntp'):
                request = dns_query if kind == 'dns' else b'\x23' + b'\0'*39 + hashlib.sha256(nonce.encode()).digest()[:8]
                result['query_hex'] = request.hex()
                sock.send(request); sock.settimeout(remaining())
                raw = sock.recv(MAX_REPLY + 1)
                _need(len(raw) <= MAX_REPLY)
                result.update(connected=True, response_hex=raw.hex())
                if kind == 'dns':
                    result.update(parse_dns(raw, request), response_nonce=nonce)
                else:
                    _need(len(raw) >= 48)
                    mode, version, leap, stratum = raw[0] & 7, (raw[0] >> 3) & 7, raw[0] >> 6, raw[1]
                    origin = raw[24:32] == request[40:48]
                    valid = mode == 4 and version in (3, 4) and origin and raw[40:48] != b'\0'*8
                    result.update(mode=mode, version=version, leap=leap, stratum=stratum,
                                  origin_matches=origin, synchronized=valid and leap != 3 and 1 <= stratum <= 15,
                                  response_nonce=nonce if valid else None)
                    if not valid: result['error'] = 'malformed-response'
            elif kind in ('http', 'https'):
                stream = sock
                if context:
                    sock.settimeout(remaining())
                    stream = context.wrap_socket(sock, server_hostname=server_name)
                    result.update(certificate_valid=True,
                                  certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
                try:
                    name = server_name or host
                    stream.settimeout(remaining())
                    stream.sendall(('GET /' + nonce + ' HTTP/1.1\r\nHost: ' + name +
                                    '\r\nConnection: close\r\n\r\n').encode('ascii'))
                    # Read a bounded raw response without unbounded header lines
                    # or automatic redirects, decompression or proxy lookup.
                    raw = bytearray()
                    while len(raw) <= MAX_REPLY:
                        stream.settimeout(remaining())
                        chunk = stream.recv(min(4096, MAX_REPLY + 1 - len(raw)))
                        if not chunk: break
                        raw.extend(chunk)
                    _need(len(raw) <= MAX_REPLY and b'\r\n\r\n' in raw)
                    headers, body = bytes(raw).split(b'\r\n\r\n', 1)
                    first = headers.split(b'\r\n')[0]
                    _need(re.fullmatch(rb'HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?', first) is not None)
                    result.update(http_status=int(first.split()[1]), response_hex=body.hex(),
                                  response_nonce=nonce if body.strip() == nonce.encode() else None)
                finally:
                    if stream is not sock: stream.close()
    except ssl.SSLError:
        result.update(error='tls-rejected', certificate_valid=False)
    except (TimeoutError, socket.timeout):
        result['error'] = 'timeout'
    except ConnectionRefusedError:
        result['error'] = 'connection-refused'
    except (ValueError, UnicodeError, struct.error):
        result['error'] = 'malformed-response'
    except OSError as error:
        result['error'] = 'unreachable' if error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) else 'io-error'
    result['duration_ms'] = int((time.monotonic() - start) * 1000)
    return result


def _mac(raw): return ':'.join(f'{byte:02x}' for byte in raw)


def _frame(raw):
    _need(14 <= len(raw) <= 65535)
    record = {'source_mac': _mac(raw[6:12]), 'destination_mac': _mac(raw[:6])}
    ether = int.from_bytes(raw[12:14], 'big'); offset = 14
    for _ in range(2):
        if ether not in (0x8100, 0x88a8): break
        _need(offset + 4 <= len(raw))
        ether = int.from_bytes(raw[offset+2:offset+4], 'big'); offset += 4
    _need(ether not in (0x8100, 0x88a8))
    record['ether_type'] = ether
    data = raw[offset:]
    if ether == 0x86dd:
        _need(len(data) >= 40 and data[0] >> 4 == 6)
        length = int.from_bytes(data[4:6], 'big') + 40
        _need(length <= len(data))
        record.update(ipv6=True, source_ip=str(ipaddress.IPv6Address(data[8:24])))
        next_header, cursor = data[6], 40
        for _ in range(8):
            if next_header not in (0, 43, 60): break
            _need(cursor + 2 <= length)
            next_header, skip = data[cursor], (data[cursor+1]+1)*8
            cursor += skip; _need(cursor <= length)
        record['ra'] = next_header == 58 and cursor + 16 <= length and data[cursor] == 134
    elif ether == 0x0800:
        _need(len(data) >= 20 and data[0] >> 4 == 4)
        header, length = (data[0] & 15)*4, int.from_bytes(data[2:4], 'big')
        _need(20 <= header <= length <= len(data))
        record['source_ip'] = socket.inet_ntoa(data[12:16])
        if data[9] != 17: return record
        _need(int.from_bytes(data[6:8], 'big') & 0x3fff == 0 and header + 8 <= length)
        source, dest, size, _ = struct.unpack('!4H', data[header:header+8])
        _need(8 <= size and header + size <= length)
        if (source, dest) not in ((67, 68), (68, 67)): return record
        payload = data[header+8:header+size]
        _need(len(payload) >= 240 and payload[236:240] == b'\x63\x82\x53\x63'
              and payload[1:3] == b'\x01\x06' and payload[0] in (1, 2))
        record.update(dhcp_op=payload[0], client_mac=_mac(payload[28:34]))
        cursor = 240; types = []
        while cursor < len(payload):
            option = payload[cursor]; cursor += 1
            if option == 255: break
            if option == 0: continue
            _need(cursor < len(payload)); size = payload[cursor]; cursor += 1
            _need(cursor + size <= len(payload))
            if option == 53:
                _need(size == 1); types.append(payload[cursor])
            cursor += size
        _need(len(types) == 1 and 1 <= types[0] <= 8)
        record['dhcp_type'] = types[0]
    return record


def parse_frames(frames, *, host_macs, router_macs):
    """Count observed senders. Empty/malformed capture is never denial proof."""
    _need(type(frames) is list and len(frames) <= 100000)
    hosts, routers = set(map(str.lower, host_macs)), set(map(str.lower, router_macs))
    result = dict(frames=len(frames), malformed=0, host_dhcp=0, host_ipv6=0,
                  router_dhcp_server=0, router_ra=0, dhcp_offers=0, router_advertisements=0)
    result['packets'] = []
    for entry in frames:
        try:
            _need(type(entry) is dict and type(entry.get('hex')) is str and len(entry['hex']) <= 131070
                  and entry.get('zone') in ('wan', 'management', 'infrastructure', 'workload', 'relay')
                  and type(entry.get('time')) in (int, float))
            packet = _frame(bytes.fromhex(entry['hex']))
            packet.update(zone=entry['zone'], time=entry['time'])
            sender = packet['source_mac']; host, router = sender in hosts, sender in routers
            result['host_dhcp'] += int(host and packet.get('dhcp_op') == 1)
            result['host_ipv6'] += int(host and packet.get('ipv6') is True)
            result['router_dhcp_server'] += int(router and packet.get('dhcp_op') == 2)
            result['router_ra'] += int(router and packet.get('ra') is True)
            result['dhcp_offers'] += int(packet.get('dhcp_type') == 2)
            result['router_advertisements'] += int(packet.get('ra') is True)
            result['packets'].append(packet)
        except (ValueError, TypeError, UnicodeError, struct.error):
            result['malformed'] += 1
    return result

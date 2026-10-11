import socket
import ssl
import struct
import subprocess
import threading

import pytest


def udp_exchange(handler):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0)); sock.settimeout(3)
    port = sock.getsockname()[1]
    def serve():
        try:
            data, peer = sock.recvfrom(4096)
            sock.sendto(handler(data), peer)
        finally:
            sock.close()
    thread = threading.Thread(target=serve); thread.start()
    return port, thread


def test_real_dns_query_checks_transaction_question_and_answer():
    from appliance.lab_probe import probe_network
    def answer(data):
        return data[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + data[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('198.18.0.1')
    port, thread = udp_exchange(answer)
    try:
        result = probe_network('dns', host='127.0.0.1', port=port, nonce='challenge-one')
        assert result['addresses'] == ['198.18.0.1'] and result['response_nonce'] == 'challenge-one'
        assert result['connected'] is True and result['error'] is None
    finally:
        thread.join(timeout=4)


def test_dns_wrong_transaction_never_proves_listener():
    from appliance.lab_probe import probe_network
    port, thread = udp_exchange(lambda data: b'\x00\x00' + data[2:])
    try:
        result = probe_network('dns', host='127.0.0.1', port=port, nonce='challenge-two')
        assert result['error'] == 'malformed-response' and result.get('response_nonce') is None
    finally:
        thread.join(timeout=4)


@pytest.mark.parametrize('wrong_origin,stratum', [(False, 1), (True, 1), (False, 0), (False, 16)])
def test_ntp_checks_echo_and_reports_sync_separately(wrong_origin, stratum):
    from appliance.lab_probe import probe_network
    def answer(data):
        response = bytearray(48); response[0] = 0x24; response[1] = stratum
        response[24:32] = b'badnonce' if wrong_origin else data[40:48]
        response[40:48] = b'nonzerot'
        return bytes(response)
    port, thread = udp_exchange(answer)
    try:
        result = probe_network('ntp', host='127.0.0.1', port=port, nonce='ntp-challenge')
        assert result['origin_matches'] is (not wrong_origin)
        assert result['synchronized'] is (not wrong_origin and 1 <= stratum <= 15)
    finally:
        thread.join(timeout=4)


def test_real_http_echo_and_closed_listener_are_distinct():
    from appliance.lab_probe import probe_network
    sock = socket.socket(); sock.bind(('127.0.0.1', 0)); sock.listen(1)
    port = sock.getsockname()[1]
    def serve():
        try:
            connection, _ = sock.accept()
            with connection:
                data = connection.recv(4096)
                assert b'GET /echo-nonce HTTP/1.1' in data
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\necho-nonce\n')
        finally:
            sock.close()
    thread = threading.Thread(target=serve); thread.start()
    result = probe_network('http', host='127.0.0.1', port=port, nonce='echo-nonce')
    thread.join(timeout=4)
    assert result['http_status'] == 200 and result['response_nonce'] == 'echo-nonce'
    refused = probe_network('http', host='127.0.0.1', port=port, nonce='second')
    assert refused['connected'] is False and refused['error'] == 'connection-refused'


def test_https_requires_ca_and_name_before_any_socket():
    from appliance.lab_probe import probe_network
    with pytest.raises(ValueError):
        probe_network('https', host='127.0.0.1', nonce='nonce')


def test_real_tls_probe_requires_certificate_and_hostname(tmp_path):
    from appliance.lab_probe import probe_network
    key, cert = tmp_path / 'key.pem', tmp_path / 'cert.pem'
    subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=lab.invalid'],
                   check=True, capture_output=True, timeout=15)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(2); listener.settimeout(5)
    port = listener.getsockname()[1]
    def serve():
        try:
            for _ in range(2):
                connection, _ = listener.accept()
                try:
                    with context.wrap_socket(connection, server_side=True) as stream:
                        stream.recv(4096)
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntls-test')
                except ssl.SSLError:
                    connection.close()
        finally:
            listener.close()
    thread = threading.Thread(target=serve); thread.start()
    try:
        good = probe_network('https', host='127.0.0.1', port=port, nonce='tls-test', ca_file=cert, server_name='lab.invalid')
        bad = probe_network('https', host='127.0.0.1', port=port, nonce='tls-test', ca_file=cert, server_name='wrong.invalid')
        assert good['certificate_valid'] is True and good['response_nonce'] == 'tls-test'
        assert bad['certificate_valid'] is False and bad['error'] == 'tls-rejected' and bad['connected'] is True
    finally:
        thread.join(timeout=6)


def test_dns_pointer_cycle_and_short_responses_refused():
    from appliance.lab_probe import parse_dns, dns_request
    request = dns_request('query-1', transaction=123)
    for response in (b'', b'x' * 10, struct.pack('!6H', 123, 0x8180, 1, 1, 0, 0) + b'\xc0\x0c' + b'\x00' * 20):
        with pytest.raises(ValueError): parse_dns(response, request)


def test_local_dns_override_remains_bound_to_exact_question_and_random_transaction():
    from appliance.lab_probe import dns_request, parse_dns
    request = dns_request('fresh-nonce', query_name='router.lab.invalid', transaction=321)
    response = request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + request[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('198.18.0.1')
    assert parse_dns(response, request)['question'] == 'router.lab.invalid'
    with pytest.raises(ValueError):
        parse_dns(response, dns_request('fresh-nonce', query_name='other.lab.invalid', transaction=321))
    for name in ('', '.', 'bad..invalid', '-bad.invalid', 'x'*64 + '.invalid', 'bad\ninvalid'):
        with pytest.raises(ValueError): dns_request('fresh', query_name=name)


def dhcp_frame(source_mac, message):
    mac = bytes.fromhex(source_mac.replace(':', ''))
    bootp = bytearray(240); bootp[0] = 1 if message in (1, 3) else 2
    bootp[1:3] = b'\x01\x06'; bootp[28:34] = mac; bootp[236:240] = b'\x63\x82\x53\x63'
    payload = bytes(bootp) + bytes((53, 1, message, 255))
    udp = struct.pack('!4H', 68 if bootp[0] == 1 else 67, 67 if bootp[0] == 1 else 68, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b'\x00'*4, b'\xff'*4)
    return b'\xff'*6 + mac + b'\x08\x00' + ip + udp


def test_packet_parser_distinguishes_host_dhcp_router_server_and_peer_control():
    from appliance.lab_probe import parse_frames
    host, router, peer = '52:54:00:00:00:01', '52:54:00:00:00:02', '52:54:00:00:00:03'
    frames = [{'time': 1, 'zone': 'wan', 'hex': dhcp_frame(mac, message).hex()}
              for mac, message in ((host, 1), (router, 2), (peer, 2))]
    result = parse_frames(frames, host_macs=[host], router_macs=[router])
    assert result['host_dhcp'] == 1 and result['router_dhcp_server'] == 1
    assert result['dhcp_offers'] == 2 and result['malformed'] == 0
    assert parse_frames([], host_macs=[host], router_macs=[router])['frames'] == 0


def test_ipv6_ra_and_vlan_are_observed_not_silently_discarded():
    from appliance.lab_probe import parse_frames
    mac = bytes.fromhex('525400000001')
    ipv6 = b'\x60\x00\x00\x00\x00\x10\x3a\xff' + b'\xfe\x80' + b'\x00'*14 + b'\xff\x02' + b'\x00'*13 + b'\x01'
    frame = b'\xff'*6 + mac + b'\x81\x00\x00\x01\x86\xdd' + ipv6 + b'\x86' + b'\x00'*15
    result = parse_frames([{'time': 1, 'zone': 'wan', 'hex': frame.hex()}], host_macs=['52:54:00:00:00:01'], router_macs=[])
    assert result['host_ipv6'] == 1 and result['router_advertisements'] == 1
    assert result['malformed'] == 0
    assert parse_frames([{'time': 1, 'zone': 'wan', 'hex': frame[:30].hex()}], host_macs=[], router_macs=[])['malformed'] == 1

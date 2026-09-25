"""Probe observations must reject mismatched or untrustworthy wire replies."""
import importlib.util
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_portable_network import plan, settings


def answer(query, ip='10.76.30.11', flags=0x8180):
    return query[:2] + struct.pack('!5H', flags, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)


def test_dns_wire_verifies_question_and_exact_address():
    from portable_network_probe import dns_query, dns_answer
    request = dns_query('chat.example.org', 123)
    assert dns_answer(answer(request), request, '10.76.30.11') is True
    for reply in (answer(request, '10.76.30.99'), b'\0\0'+answer(request)[2:], answer(request, flags=0x8380),
                  answer(request).replace(b'chat', b'xxxx'), answer(request)[:-1], b'\0'*12):
        with pytest.raises(ValueError): dns_answer(reply, request, '10.76.30.11')


def test_dns_compression_loop_and_wrong_answer_name_rejected():
    from portable_network_probe import dns_query, dns_answer
    query = dns_query('chat.example.org', 123)
    loop = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + b'\xc0\x0c' + query[-4:]
    with pytest.raises(ValueError): dns_answer(loop, query, '10.76.30.11')
    wrong = query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:]+b'\x04evil\0'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('10.76.30.11')
    with pytest.raises(ValueError): dns_answer(wrong, query, '10.76.30.11')


def test_ntp_checks_origin_sync_and_clock_difference():
    from portable_network_probe import ntp_query, ntp_answer, timestamp
    now = time.time(); request = ntp_query(now)
    reply = bytearray(48); reply[0] = 0x24; reply[1] = 10
    reply[24:32] = request[40:48]; reply[32:40] = timestamp(now); reply[40:48] = timestamp(now)
    result = ntp_answer(bytes(reply), request, now, now+.02)
    assert abs(result['offset_seconds']) < .02
    assert result['utc_verified'] is False
    for index, value in ((0,0xe4),(1,0),(1,16),(24,255),(0,0x23)):
        bad = bytearray(reply); bad[index] = value
        with pytest.raises(ValueError): ntp_answer(bytes(bad), request, now, now+.02)
    reply[32:40] = reply[40:48] = timestamp(now+60)
    with pytest.raises(ValueError): ntp_answer(bytes(reply), request, now, now+.02)


def test_client_reports_failure_and_never_infers_offline_or_application_readiness():
    from portable_network_probe import check
    def failed_dns(*args, **kwargs): raise TimeoutError()
    def failed_ntp(*args, **kwargs): raise OSError()
    result = check(plan(), settings(), dns_probe=failed_dns, ntp_probe=failed_ntp)
    assert result['state'] == 'network-check-failed'
    assert result['checks'] and all(c['outcome']=='fail' for c in result['checks'])
    assert result['wan_isolation_verified'] is False
    assert result['applications_verified'] is False
    assert result['utc_verified'] is False


def test_actual_udp_socket_probe_matches_response():
    from portable_network_probe import dns_probe
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1',0)); server.settimeout(2)
        def respond():
            request, client = server.recvfrom(4096); server.sendto(answer(request),client)
        thread=threading.Thread(target=respond); thread.start()
        assert dns_probe('127.0.0.1','chat.example.org','10.76.30.11',port=server.getsockname()[1]) is True
        thread.join(timeout=3)


def test_actual_tcp_probe_handles_split_frame():
    from portable_network_probe import dns_probe
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(2)
        def respond():
            with server.accept()[0] as connection:
                size=struct.unpack('!H',connection.recv(2))[0]
                request=b''
                while len(request)<size: request+=connection.recv(size-len(request))
                reply=answer(request); frame=struct.pack('!H',len(reply))+reply
                connection.sendall(frame[:1]);connection.sendall(frame[1:15]);connection.sendall(frame[15:])
        thread=threading.Thread(target=respond);thread.start()
        assert dns_probe('127.0.0.1','chat.example.org','10.76.30.11',tcp=True,port=server.getsockname()[1]) is True
        thread.join(timeout=3)

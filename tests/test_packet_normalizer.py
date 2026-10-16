from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from app.services.packet_normalizer import PacketNormalizer, decode_tcp_flags, format_safe_ascii, format_hex_dump

def test_decode_tcp_flags():
    flags_list, code = decode_tcp_flags('SA')
    assert 'SYN' in flags_list
    assert 'ACK' in flags_list
    assert code == 'SA'

    flags_list_rst, _ = decode_tcp_flags('R')
    assert 'RST' in flags_list_rst

    empty_list, empty_code = decode_tcp_flags('')
    assert empty_list == []
    assert empty_code == ''

def test_format_safe_ascii():
    data = b"Hello\x00\x01\x1fWorld!~"
    ascii_out = format_safe_ascii(data)
    assert ascii_out.startswith("Hello...World!~")
    assert '\x00' not in ascii_out

def test_format_hex_dump():
    data = b"\x01\x02\x0a\xff"
    hex_out = format_hex_dump(data)
    assert hex_out == "01 02 0A FF"

def test_normalize_ipv4_tcp():
    pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")/IP(src="192.168.1.50", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="S")
    pkt.time = 1700000000.0

    norm = PacketNormalizer.normalize(pkt, index=1, start_time=1700000000.0)
    assert norm['index'] == 1
    assert norm['src_ip'] == "192.168.1.50"
    assert norm['dst_ip'] == "10.0.0.1"
    assert norm['src_port'] == 12345
    assert norm['dst_port'] == 80
    assert norm['protocol'] == "TCP"
    assert 'SYN' in norm['tcp_flags']
    assert norm['is_cleartext'] == 1  # port 80

def test_normalize_ipv6():
    pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")/IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(sport=5000, dport=5001)
    pkt.time = 1700000001.0

    norm = PacketNormalizer.normalize(pkt, index=2, start_time=1700000000.0)
    assert norm['src_ip'] == "2001:db8::1"
    assert norm['dst_ip'] == "2001:db8::2"
    assert norm['protocol'] == "UDP"
    assert norm['relative_time'] == 1.0

def test_normalize_dns():
    pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")/IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=53000, dport=53)/DNS(
        id=1234, qr=0, qd=DNSQR(qname="portal.example.com", qtype="A")
    )
    pkt.time = 1700000002.0

    norm = PacketNormalizer.normalize(pkt, index=3, start_time=1700000000.0)
    assert norm['protocol'] == "DNS"
    assert norm['dns_query'] == "portal.example.com"
    assert norm['dns_type'] == "A"
    assert "portal.example.com" in norm['summary']

def test_normalize_icmp():
    pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")/IP(src="192.168.1.50", dst="192.168.1.1")/ICMP(type=8, code=0)/Raw(load=b"pingtest")
    pkt.time = 1700000003.0

    norm = PacketNormalizer.normalize(pkt, index=4, start_time=1700000000.0)
    assert norm['protocol'] == "ICMP"
    assert "Echo Request" in norm['summary']
    assert norm['raw_payload_len'] == 8

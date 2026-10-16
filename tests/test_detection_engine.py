from app.services.detection_engine import DetectionEngine

def make_pkt(index=1, timestamp=100.0, src_ip="192.168.1.10", dst_ip="192.168.1.1",
             protocol="TCP", src_port=50000, dst_port=80, flags="S", dns_query=None,
             payload_len=0):
    return {
        'index': index,
        'timestamp': timestamp,
        'time_iso': '2024-06-10 12:00:00.000000',
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'tcp_flags': flags,
        'dns_query': dns_query,
        'dns_type': 'A' if dns_query else None,
        'raw_payload_len': payload_len,
        'length': 64 + payload_len
    }

def test_nth001_port_scan_triggered():
    engine = DetectionEngine()
    packets = []
    # 15 distinct ports scanned within 10 seconds
    for i in range(15):
        packets.append(make_pkt(index=i+1, timestamp=100.0 + i*0.5, src_ip="10.0.0.5", dst_ip="192.168.1.20", dst_port=1000+i))

    alerts = engine.analyze(packets)
    scan_alerts = [a for a in alerts if a['rule_id'] == 'NTH-001']
    assert len(scan_alerts) == 1
    assert scan_alerts[0]['observed_values']['distinct_ports_count'] == 15
    assert len(scan_alerts[0]['packet_indices']) == 15
    assert scan_alerts[0]['severity'] in ('Medium', 'High')

def test_nth001_port_scan_below_threshold():
    engine = DetectionEngine()
    packets = []
    # Only 5 distinct ports (threshold is 12)
    for i in range(5):
        packets.append(make_pkt(index=i+1, timestamp=100.0 + i*0.5, src_ip="10.0.0.5", dst_ip="192.168.1.20", dst_port=1000+i))

    alerts = engine.analyze(packets)
    scan_alerts = [a for a in alerts if a['rule_id'] == 'NTH-001']
    assert len(scan_alerts) == 0

def test_nth002_connection_rate_triggered():
    engine = DetectionEngine()
    packets = []
    # 22 SYN packets within 1.0 second (rate 22 conn/sec > threshold 12)
    for i in range(22):
        packets.append(make_pkt(index=i+1, timestamp=100.0 + i*0.04, src_ip="10.0.0.99", dst_ip="192.168.1.20", dst_port=80, flags="SYN"))

    alerts = engine.analyze(packets)
    rate_alerts = [a for a in alerts if a['rule_id'] == 'NTH-002']
    assert len(rate_alerts) == 1
    assert rate_alerts[0]['observed_values']['attempts_count'] >= 20
    assert rate_alerts[0]['severity'] == 'High'

def test_nth002_connection_rate_below_threshold():
    engine = DetectionEngine()
    packets = []
    # Only 5 attempts (min_attempts is 20)
    for i in range(5):
        packets.append(make_pkt(index=i+1, timestamp=100.0 + i*0.04, src_ip="10.0.0.99", dst_ip="192.168.1.20", dst_port=80, flags="SYN"))

    alerts = engine.analyze(packets)
    rate_alerts = [a for a in alerts if a['rule_id'] == 'NTH-002']
    assert len(rate_alerts) == 0

def test_nth003_dns_heuristics():
    engine = DetectionEngine()
    # 1 benign query, 1 long tunneling query
    packets = [
        make_pkt(index=1, timestamp=100.0, src_ip="192.168.1.5", dst_ip="8.8.8.8", protocol="DNS",
                 dns_query="normal.com"),
        make_pkt(index=2, timestamp=101.0, src_ip="192.168.1.5", dst_ip="8.8.8.8", protocol="DNS",
                 dns_query="v1-tunneling-long-exfiltration-payload-string-abcdef123456789.c2-domain.com")  # 72 chars
    ]

    alerts = engine.analyze(packets)
    dns_alerts = [a for a in alerts if a['rule_id'] == 'NTH-003']
    assert len(dns_alerts) == 1
    assert dns_alerts[0]['observed_values']['max_character_length'] > 45

def test_nth004_unusual_port():
    engine = DetectionEngine()
    # 6 packets directed to Metasploit port 4444 (threshold is >= 5)
    packets = [
        make_pkt(index=i+1, timestamp=100.0 + i, src_ip="192.168.1.50", dst_ip="198.51.100.2", dst_port=4444)
        for i in range(6)
    ]

    alerts = engine.analyze(packets)
    port_alerts = [a for a in alerts if a['rule_id'] == 'NTH-004']
    assert len(port_alerts) == 1
    assert port_alerts[0]['observed_values']['port'] == 4444

def test_nth005_cleartext_protocol():
    engine = DetectionEngine()
    packets = [
        make_pkt(index=1, timestamp=100.0, src_ip="192.168.1.10", dst_ip="93.184.216.34", dst_port=80, protocol="HTTP"),
        make_pkt(index=2, timestamp=101.0, src_ip="192.168.1.10", dst_ip="10.0.0.2", dst_port=21, protocol="TCP")
    ]

    alerts = engine.analyze(packets)
    cleartext_alerts = [a for a in alerts if a['rule_id'] == 'NTH-005']
    assert len(cleartext_alerts) >= 2
    protos_detected = {a['observed_values']['protocol'] for a in cleartext_alerts}
    assert 'HTTP' in protos_detected
    assert 'FTP' in protos_detected

def test_nth006_icmp_benign_ping_not_flagged():
    engine = DetectionEngine()
    # 2 standard pings (32 byte payload) - must NOT trigger alert
    packets = [
        make_pkt(index=1, timestamp=100.0, src_ip="192.168.1.10", dst_ip="192.168.1.1", protocol="ICMP", payload_len=32),
        make_pkt(index=2, timestamp=101.0, src_ip="192.168.1.10", dst_ip="192.168.1.1", protocol="ICMP", payload_len=32)
    ]

    alerts = engine.analyze(packets)
    icmp_alerts = [a for a in alerts if a['rule_id'] == 'NTH-006']
    assert len(icmp_alerts) == 0

def test_nth006_icmp_large_payload_triggered():
    engine = DetectionEngine()
    # 5 oversized ICMP packets (150 byte payload > threshold 96 bytes)
    packets = [
        make_pkt(index=i+1, timestamp=100.0 + i*0.2, src_ip="192.168.1.10", dst_ip="198.51.100.99", protocol="ICMP", payload_len=150)
        for i in range(5)
    ]

    alerts = engine.analyze(packets)
    icmp_alerts = [a for a in alerts if a['rule_id'] == 'NTH-006']
    assert len(icmp_alerts) == 1
    assert icmp_alerts[0]['observed_values']['max_payload_observed'] == 150

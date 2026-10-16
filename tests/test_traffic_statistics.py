from app.services.traffic_statistics import TrafficStatistics

def test_traffic_statistics_empty():
    stats = TrafficStatistics.calculate([])
    assert stats['total_packets'] == 0
    assert stats['total_bytes'] == 0
    assert stats['duration_seconds'] == 0.0
    assert stats['protocol_distribution'] == {}

def test_traffic_statistics_calculations():
    packets = [
        {
            'index': 1, 'timestamp': 100.0, 'time_iso': '2024-06-10 12:00:00.000000',
            'src_ip': '192.168.1.10', 'dst_ip': '93.184.216.34', 'src_port': 50000,
            'dst_port': 80, 'protocol': 'TCP', 'length': 60, 'tcp_flags': 'SYN'
        },
        {
            'index': 2, 'timestamp': 100.1, 'time_iso': '2024-06-10 12:00:00.100000',
            'src_ip': '93.184.216.34', 'dst_ip': '192.168.1.10', 'src_port': 80,
            'dst_port': 50000, 'protocol': 'TCP', 'length': 60, 'tcp_flags': 'SYN, ACK'
        },
        {
            'index': 3, 'timestamp': 105.0, 'time_iso': '2024-06-10 12:00:05.000000',
            'src_ip': '192.168.1.20', 'dst_ip': '8.8.8.8', 'src_port': 53000,
            'dst_port': 53, 'protocol': 'DNS', 'length': 85, 'dns_query': 'example.com', 'dns_type': 'A'
        }
    ]

    stats = TrafficStatistics.calculate(packets)
    assert stats['total_packets'] == 3
    assert stats['total_bytes'] == 205
    assert stats['duration_seconds'] == 5.0
    assert stats['unique_src_ips'] == 3
    assert stats['unique_dst_ips'] == 3

    # Protocol breakdown
    proto_names = [p['protocol'] for p in stats['protocol_distribution']]
    assert 'TCP' in proto_names
    assert 'DNS' in proto_names

    # Flow reconstruction
    assert len(stats['tcp_flows']) == 1
    flow = stats['tcp_flows'][0]
    assert flow['state'] == 'ESTABLISHED'  # Both SYN and SYN, ACK were observed
    assert flow['packet_count'] == 2

    # DNS summary
    assert len(stats['dns_summaries']) == 1
    assert stats['dns_summaries'][0]['query_name'] == 'example.com'

    # Time buckets
    assert len(stats['time_buckets']) > 0

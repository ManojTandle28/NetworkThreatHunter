import math
from typing import List, Dict, Any
from collections import defaultdict, Counter

COMMON_PORTS_DESC = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client', 80: 'HTTP', 110: 'POP3',
    123: 'NTP', 137: 'NetBIOS Name', 138: 'NetBIOS Datagram', 139: 'NetBIOS Session',
    143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS / TLS', 445: 'SMB',
    465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MS-SQL',
    1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit / RAT',
    5432: 'PostgreSQL', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
}

class TrafficStatistics:
    """Calculates comprehensive traffic metrics, protocol distribution, flow states, and time series buckets."""

    @staticmethod
    def calculate(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not packets:
            return {
                'total_packets': 0,
                'total_bytes': 0,
                'duration_seconds': 0.0,
                'start_time_iso': None,
                'end_time_iso': None,
                'unique_src_ips': 0,
                'unique_dst_ips': 0,
                'protocol_distribution': {},
                'top_src_ips': [],
                'top_dst_ips': [],
                'top_ports': [],
                'time_buckets': [],
                'tcp_flows': [],
                'dns_summaries': []
            }

        total_packets = len(packets)
        total_bytes = sum(p.get('length', 0) for p in packets)

        timestamps = [p['timestamp'] for p in packets if p.get('timestamp') is not None]
        if timestamps:
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            duration = max(0.0, max_ts - min_ts)
            start_iso = packets[0]['time_iso']
            end_iso = packets[-1]['time_iso']
        else:
            min_ts = 0.0
            max_ts = 0.0
            duration = 0.0
            start_iso = None
            end_iso = None

        # Protocol distribution
        proto_counts = Counter(p.get('protocol', 'OTHER') for p in packets)
        proto_dist = [
            {'protocol': proto, 'count': count, 'percentage': round((count / total_packets) * 100, 1)}
            for proto, count in proto_counts.most_common()
        ]

        # IP metrics
        src_ip_counts = Counter()
        src_ip_bytes = Counter()
        dst_ip_counts = Counter()
        dst_ip_bytes = Counter()

        for p in packets:
            src = p.get('src_ip')
            dst = p.get('dst_ip')
            length = p.get('length', 0)
            if src and src != 'N/A':
                src_ip_counts[src] += 1
                src_ip_bytes[src] += length
            if dst and dst != 'N/A':
                dst_ip_counts[dst] += 1
                dst_ip_bytes[dst] += length

        top_src_ips = [
            {
                'ip': ip,
                'packet_count': count,
                'byte_count': src_ip_bytes[ip],
                'percentage': round((count / total_packets) * 100, 1)
            }
            for ip, count in src_ip_counts.most_common(10)
        ]

        top_dst_ips = [
            {
                'ip': ip,
                'packet_count': count,
                'byte_count': dst_ip_bytes[ip],
                'percentage': round((count / total_packets) * 100, 1)
            }
            for ip, count in dst_ip_counts.most_common(10)
        ]

        # Port metrics (both src and dst)
        port_counts = Counter()
        for p in packets:
            dport = p.get('dst_port')
            if dport is not None:
                port_counts[dport] += 1

        top_ports = [
            {
                'port': port,
                'service': COMMON_PORTS_DESC.get(port, 'Unknown / Dynamic'),
                'count': count,
                'percentage': round((count / total_packets) * 100, 1)
            }
            for port, count in port_counts.most_common(10)
        ]

        # Time series buckets
        time_buckets = TrafficStatistics._compute_time_buckets(packets, min_ts, max_ts, duration)

        # Flow reconstruction
        tcp_flows = TrafficStatistics._reconstruct_tcp_flows(packets)

        # DNS query summaries
        dns_summaries = TrafficStatistics._summarize_dns(packets)

        return {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'duration_seconds': round(duration, 3),
            'start_time_iso': start_iso,
            'end_time_iso': end_iso,
            'unique_src_ips': len(src_ip_counts),
            'unique_dst_ips': len(dst_ip_counts),
            'protocol_distribution': proto_dist,
            'top_src_ips': top_src_ips,
            'top_dst_ips': top_dst_ips,
            'top_ports': top_ports,
            'time_buckets': time_buckets,
            'tcp_flows': tcp_flows[:50],  # Keep top 50 in summary
            'dns_summaries': dns_summaries[:50]
        }

    @staticmethod
    def _compute_time_buckets(packets: List[Dict[str, Any]], min_ts: float, max_ts: float, duration: float) -> List[Dict[str, Any]]:
        """Slice the capture time into 10 to 30 intervals for responsive line/bar charts."""
        if duration <= 0.001 or not packets:
            return [{'bucket_label': '0s', 'packet_count': len(packets), 'byte_count': sum(p.get('length', 0) for p in packets)}]

        # Target between 10 and 25 intervals
        num_buckets = 20 if duration >= 5.0 else max(5, int(math.ceil(duration)))
        interval = duration / num_buckets

        buckets = [{'bucket_index': i, 'start_rel': round(i * interval, 2), 'packet_count': 0, 'byte_count': 0} for i in range(num_buckets)]

        for p in packets:
            ts = p.get('timestamp', min_ts)
            rel = max(0.0, ts - min_ts)
            idx = min(num_buckets - 1, int(rel / interval)) if interval > 0 else 0
            buckets[idx]['packet_count'] += 1
            buckets[idx]['byte_count'] += p.get('length', 0)

        for b in buckets:
            b['bucket_label'] = f"{b['start_rel']}s"

        return buckets

    @staticmethod
    def _reconstruct_tcp_flows(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Reconstruct TCP flows and estimate connection state from observed packets."""
        flows: Dict[str, Dict[str, Any]] = {}

        for p in packets:
            if p.get('protocol') != 'TCP' or not p.get('src_port') or not p.get('dst_port'):
                continue

            src = p['src_ip']
            sport = p['src_port']
            dst = p['dst_ip']
            dport = p['dst_port']

            # Canonical bidirectional key
            if (src, sport) <= (dst, dport):
                flow_key = f"{src}:{sport}<->{dst}:{dport}"
                forward = True
            else:
                flow_key = f"{dst}:{dport}<->{src}:{sport}"
                forward = False

            flags = p.get('tcp_flags', '')
            ts = p['timestamp']

            if flow_key not in flows:
                flows[flow_key] = {
                    'flow_key': flow_key,
                    'src_ip': src if forward else dst,
                    'src_port': sport if forward else dport,
                    'dst_ip': dst if forward else src,
                    'dst_port': dport if forward else sport,
                    'packet_count': 0,
                    'byte_count': 0,
                    'has_syn': False,
                    'has_synack': False,
                    'has_fin': False,
                    'has_rst': False,
                    'start_time': ts,
                    'end_time': ts
                }

            f = flows[flow_key]
            f['packet_count'] += 1
            f['byte_count'] += p.get('length', 0)
            f['end_time'] = max(f['end_time'], ts)

            if 'SYN' in flags:
                if 'ACK' in flags:
                    f['has_synack'] = True
                else:
                    f['has_syn'] = True
            if 'FIN' in flags:
                f['has_fin'] = True
            if 'RST' in flags:
                f['has_rst'] = True

        result = []
        for key, f in flows.items():
            state = 'INCOMPLETE'
            if f['has_rst']:
                state = 'RESET'
            elif f['has_fin']:
                state = 'CLOSED'
            elif f['has_syn'] and f['has_synack']:
                state = 'ESTABLISHED'
            elif f['has_syn']:
                state = 'SYN_SENT'
            elif f['packet_count'] > 3:
                state = 'TRANSIENT'

            flow_duration = round(f['end_time'] - f['start_time'], 3)
            result.append({
                'flow_key': key,
                'src_ip': f['src_ip'],
                'src_port': f['src_port'],
                'dst_ip': f['dst_ip'],
                'dst_port': f['dst_port'],
                'packet_count': f['packet_count'],
                'byte_count': f['byte_count'],
                'state': state,
                'duration': flow_duration
            })

        result.sort(key=lambda x: x['packet_count'], reverse=True)
        return result

    @staticmethod
    def _summarize_dns(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Summarize unique DNS queries, query types, counts, and observation timestamps."""
        dns_map: Dict[tuple, Dict[str, Any]] = {}
        for p in packets:
            if p.get('dns_query'):
                qname = p['dns_query']
                qtype = p.get('dns_type', 'A')
                key = (qname, qtype)
                if key not in dns_map:
                    dns_map[key] = {
                        'query_name': qname,
                        'query_type': qtype,
                        'count': 0,
                        'first_seen': p['time_iso'],
                        'last_seen': p['time_iso']
                    }
                dns_map[key]['count'] += 1
                dns_map[key]['last_seen'] = p['time_iso']

        summaries = list(dns_map.values())
        summaries.sort(key=lambda x: x['count'], reverse=True)
        return summaries

import uuid
from typing import List, Dict, Any, Optional
from collections import defaultdict
from app.config import Config

class DetectionEngine:
    """Deterministic, explainable cybersecurity detection engine for network packet captures."""

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = thresholds or Config.DETECTION_THRESHOLDS

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all detection rules across normalized packets and return structured alerts."""
        if not packets:
            return []

        alerts: List[Dict[str, Any]] = []

        alerts.extend(self._detect_port_scan(packets))
        alerts.extend(self._detect_high_connection_rate(packets))
        alerts.extend(self._detect_suspicious_dns(packets))
        alerts.extend(self._detect_unusual_ports(packets))
        alerts.extend(self._detect_cleartext_protocols(packets))
        alerts.extend(self._detect_icmp_anomaly(packets))

        # Assign unique IDs if not already set
        for alert in alerts:
            if 'id' not in alert:
                alert['id'] = str(uuid.uuid4())
            if 'status' not in alert:
                alert['status'] = 'New'
            if 'analyst_notes' not in alert:
                alert['analyst_notes'] = ''

        return alerts

    def _detect_port_scan(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-001: Identify a source IP attempting connections to an unusually large number of distinct ports."""
        rule_cfg = self.thresholds.get('port_scan', {})
        min_ports = rule_cfg.get('min_distinct_ports', 12)
        window = rule_cfg.get('time_window_seconds', 60.0)

        # Group attempts by (src_ip, dst_ip)
        targets_by_source: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            if pkt.get('protocol') in ('TCP', 'UDP') and pkt.get('dst_port') is not None:
                src = pkt.get('src_ip')
                dst = pkt.get('dst_ip')
                if src and dst and src != 'N/A' and dst != 'N/A':
                    targets_by_source[(src, dst)].append(pkt)

        alerts = []
        for (src_ip, dst_ip), pkts in targets_by_source.items():
            if len(pkts) < min_ports:
                continue

            pkts.sort(key=lambda x: x['timestamp'])
            
            # Sliding window over packets
            left = 0
            distinct_ports = set()
            window_pkts = []
            
            for right in range(len(pkts)):
                while pkts[right]['timestamp'] - pkts[left]['timestamp'] > window:
                    left += 1

                current_window = pkts[left:right + 1]
                ports_in_window = {p['dst_port'] for p in current_window}
                
                if len(ports_in_window) >= min_ports and len(ports_in_window) > len(distinct_ports):
                    distinct_ports = ports_in_window
                    window_pkts = current_window

            if len(distinct_ports) >= min_ports:
                start_iso = window_pkts[0]['time_iso']
                end_iso = window_pkts[-1]['time_iso']
                duration = round(window_pkts[-1]['timestamp'] - window_pkts[0]['timestamp'], 2)
                packet_indices = [p['index'] for p in window_pkts]
                
                severity = 'High' if len(distinct_ports) >= 20 else 'Medium'

                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-001',
                    'rule_name': 'Potential Port Scan Detected',
                    'severity': severity,
                    'trigger_summary': f"Source {src_ip} attempted connections to {len(distinct_ports)} distinct destination ports on {dst_ip} within {duration}s",
                    'rationale': (
                        "A single source host initiated connections across multiple distinct destination ports within a short time window. "
                        "This behavior strongly correlates with active reconnaissance, network service mapping, or automated port scanning utilities."
                    ),
                    'observed_values': {
                        'source_ip': src_ip,
                        'target_ip': dst_ip,
                        'distinct_ports_count': len(distinct_ports),
                        'sample_ports': sorted(list(distinct_ports))[:25],
                        'duration_seconds': duration,
                        'packet_count': len(window_pkts)
                    },
                    'packet_indices': packet_indices,
                    'timestamp_range': f"{start_iso} to {end_iso}",
                    'limitations': (
                        "Legitimate security scanners, vulnerability assessment tools, network asset discovery, or complex microservices "
                        "can produce identical connection patterns. This alert does not prove malicious intent or successful system compromise."
                    ),
                    'recommendations': (
                        "1. Verify if source IP belongs to an authorized internal scanner or IT inventory tool.\n"
                        "2. Inspect target server responses (SYN-ACK vs RST) to determine if any scanned services were open.\n"
                        "3. Review firewall telemetry to evaluate whether to rate-limit or block this source."
                    )
                })

        return alerts

    def _detect_high_connection_rate(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-002: Identify unusually frequent TCP connection attempts (SYN packets) from one source."""
        rule_cfg = self.thresholds.get('connection_rate', {})
        rate_threshold = rule_cfg.get('rate_threshold_per_sec', 12.0)
        min_attempts = rule_cfg.get('min_attempts', 20)
        window = rule_cfg.get('burst_window_seconds', 5.0)

        # Collect TCP SYN packets (connection requests)
        syn_by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            if pkt.get('protocol') == 'TCP' and 'SYN' in pkt.get('tcp_flags', '') and 'ACK' not in pkt.get('tcp_flags', ''):
                src = pkt.get('src_ip')
                if src and src != 'N/A':
                    syn_by_source[src].append(pkt)

        alerts = []
        for src_ip, syn_pkts in syn_by_source.items():
            if len(syn_pkts) < min_attempts:
                continue

            syn_pkts.sort(key=lambda x: x['timestamp'])

            # Sliding window to detect highest rate burst
            max_burst_pkts = []
            max_rate = 0.0

            left = 0
            for right in range(len(syn_pkts)):
                while syn_pkts[right]['timestamp'] - syn_pkts[left]['timestamp'] > window:
                    left += 1

                current_window = syn_pkts[left:right + 1]
                if len(current_window) >= min_attempts:
                    duration = max(0.001, current_window[-1]['timestamp'] - current_window[0]['timestamp'])
                    rate = len(current_window) / duration
                    if rate >= rate_threshold and rate > max_rate:
                        max_rate = rate
                        max_burst_pkts = current_window

            if max_burst_pkts:
                start_iso = max_burst_pkts[0]['time_iso']
                end_iso = max_burst_pkts[-1]['time_iso']
                duration = round(max_burst_pkts[-1]['timestamp'] - max_burst_pkts[0]['timestamp'], 2)
                packet_indices = [p['index'] for p in max_burst_pkts]
                targets = list({p['dst_ip'] for p in max_burst_pkts})

                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-002',
                    'rule_name': 'High Connection Attempt Rate',
                    'severity': 'High',
                    'trigger_summary': f"Source {src_ip} generated {len(max_burst_pkts)} TCP SYN connection attempts in {duration}s ({round(max_rate, 1)} conn/sec)",
                    'rationale': (
                        "Source host generated TCP connection requests at an abnormally elevated frequency. "
                        "This pattern is commonly seen in SYN flood attacks, automated brute-force attempts, or aggressive web scrapers."
                    ),
                    'observed_values': {
                        'source_ip': src_ip,
                        'attempts_count': len(max_burst_pkts),
                        'rate_per_sec': round(max_rate, 2),
                        'burst_duration_sec': duration,
                        'targets_contacted': targets[:10],
                        'target_count': len(targets)
                    },
                    'packet_indices': packet_indices,
                    'timestamp_range': f"{start_iso} to {end_iso}",
                    'limitations': (
                        "High-volume load testing tools, web crawlers, or peer-to-peer applications can legitimately create connection bursts. "
                        "This capture alone does not confirm server exhaustion or whether connections were completed without reviewing destination response metrics."
                    ),
                    'recommendations': (
                        "1. Verify destination server TCP connection tables for backlog exhaustion (SYN_RECV state buildup).\n"
                        "2. Correlate with application authentication logs to rule out credential stuffing.\n"
                        "3. Apply SYN-proxying or rate limiting at the edge router or firewall."
                    )
                })

        return alerts

    def _detect_suspicious_dns(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-003: Flag unusually high DNS query rates or unusually long query names."""
        rule_cfg = self.thresholds.get('suspicious_dns', {})
        max_query_len = rule_cfg.get('max_query_length', 45)
        rate_threshold = rule_cfg.get('query_rate_per_sec', 8.0)
        min_burst = rule_cfg.get('min_burst_queries', 15)
        window = rule_cfg.get('burst_window_seconds', 5.0)

        dns_pkts_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            if pkt.get('protocol') == 'DNS' and pkt.get('dns_query'):
                src = pkt.get('src_ip')
                if src and src != 'N/A':
                    dns_pkts_by_src[src].append(pkt)

        alerts = []
        for src_ip, pkts in dns_pkts_by_src.items():
            # Heuristic A: Unusually long DNS query names (tunneling / DGA)
            long_queries = [p for p in pkts if len(p.get('dns_query', '')) >= max_query_len]
            if long_queries:
                distinct_long = list({p['dns_query'] for p in long_queries})
                max_len = max(len(q) for q in distinct_long)
                packet_indices = [p['index'] for p in long_queries]
                start_iso = long_queries[0]['time_iso']
                end_iso = long_queries[-1]['time_iso']

                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-003',
                    'rule_name': 'Suspicious DNS Query Activity (Long Queries)',
                    'severity': 'Medium',
                    'trigger_summary': f"Source {src_ip} queried {len(distinct_long)} unusually long domain names (max length: {max_len} chars)",
                    'rationale': (
                        "Observed DNS queries with character lengths significantly exceeding standard web domain averages. "
                        "Extremely long query labels are characteristic of DNS tunneling techniques (e.g., iodine, dnscat2) or Domain Generation Algorithms (DGA)."
                    ),
                    'observed_values': {
                        'source_ip': src_ip,
                        'suspicious_domain_samples': distinct_long[:10],
                        'max_character_length': max_len,
                        'total_long_queries': len(long_queries)
                    },
                    'packet_indices': packet_indices,
                    'timestamp_range': f"{start_iso} to {end_iso}",
                    'limitations': (
                        "Content Delivery Networks (CDNs), anti-virus reputation telemetry, DKIM/SPF lookups, and cloud microservices "
                        "frequently make long, hashed queries. A long domain name does not guarantee malicious exfiltration on its own."
                    ),
                    'recommendations': (
                        "1. Inspect DNS record types requested (TXT, NULL, and CNAME records are common tunneling vectors).\n"
                        "2. Perform Shannon entropy analysis on query subdomains to check for encoded binary data.\n"
                        "3. Check WHOIS registration age and threat reputation for the apex domain."
                    )
                })

            # Heuristic B: DNS query burst rate
            if len(pkts) >= min_burst:
                pkts.sort(key=lambda x: x['timestamp'])
                left = 0
                max_rate = 0.0
                burst_pkts = []

                for right in range(len(pkts)):
                    while pkts[right]['timestamp'] - pkts[left]['timestamp'] > window:
                        left += 1

                    cur_window = pkts[left:right + 1]
                    if len(cur_window) >= min_burst:
                        span = max(0.001, cur_window[-1]['timestamp'] - cur_window[0]['timestamp'])
                        rate = len(cur_window) / span
                        if rate >= rate_threshold and rate > max_rate:
                            max_rate = rate
                            burst_pkts = cur_window

                if burst_pkts:
                    alerts.append({
                        'id': str(uuid.uuid4()),
                        'rule_id': 'NTH-003',
                        'rule_name': 'Suspicious DNS Query Activity (High Query Rate)',
                        'severity': 'Medium',
                        'trigger_summary': f"Source {src_ip} issued {len(burst_pkts)} DNS queries in {round(burst_pkts[-1]['timestamp'] - burst_pkts[0]['timestamp'], 2)}s ({round(max_rate, 1)} queries/sec)",
                        'rationale': (
                            "Unusually dense cluster of DNS requests observed from a single internal endpoint, suggesting automated reconnaissance, "
                            "aggressive domain brute-forcing, or data exfiltration over DNS."
                        ),
                        'observed_values': {
                            'source_ip': src_ip,
                            'query_count': len(burst_pkts),
                            'rate_per_sec': round(max_rate, 2),
                            'sample_queries': [p['dns_query'] for p in burst_pkts[:10]]
                        },
                        'packet_indices': [p['index'] for p in burst_pkts],
                        'timestamp_range': f"{burst_pkts[0]['time_iso']} to {burst_pkts[-1]['time_iso']}",
                        'limitations': (
                            "Client application startups, browser tab restores, and recursive resolver lookups can cause brief high-density DNS bursts."
                        ),
                        'recommendations': (
                            "1. Inspect query diversity (many unique domains vs repeat queries for the same domain).\n"
                            "2. Check whether queries resolved successfully or returned high volumes of NXDOMAIN."
                        )
                    })

        return alerts

    def _detect_unusual_ports(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-004: Identify communication targeting known suspicious indicator ports or unusual port concentrations."""
        rule_cfg = self.thresholds.get('unusual_port', {})
        indicator_ports = rule_cfg.get('suspicious_indicator_ports', {1337, 31337, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 12345, 27017, 65535})
        min_pkts = rule_cfg.get('min_packets_threshold', 5)

        port_pkts: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            dport = pkt.get('dst_port')
            sport = pkt.get('src_port')
            src = pkt.get('src_ip')
            dst = pkt.get('dst_ip')

            # Check if dport is in indicator list
            if dport in indicator_ports and src and dst:
                port_pkts[(src, dst, dport)].append(pkt)

        alerts = []
        for (src_ip, dst_ip, port), pkts in port_pkts.items():
            if len(pkts) >= min_pkts:
                pkts.sort(key=lambda x: x['timestamp'])
                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-004',
                    'rule_name': 'Unusual Destination or Port Concentration',
                    'severity': 'Medium',
                    'trigger_summary': f"Observed {len(pkts)} packets directed to uncommon/suspicious port {port} on {dst_ip}",
                    'rationale': (
                        f"Network traffic was concentrated toward port {port}, which is commonly associated with reverse command shells, "
                        "RAT backdoors (e.g. Metasploit default handler port 4444, Back Orifice, NetBus), or unapproved peer services."
                    ),
                    'observed_values': {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'port': port,
                        'packet_count': len(pkts),
                        'transport_protocol': pkts[0].get('protocol', 'TCP')
                    },
                    'packet_indices': [p['index'] for p in pkts],
                    'timestamp_range': f"{pkts[0]['time_iso']} to {pkts[-1]['time_iso']}",
                    'limitations': (
                        "Development web services, non-standard staging applications, and custom proprietary tools frequently run on arbitrary high ports. "
                        "Port presence alone does not confirm that an active exploit or backdoor payload was delivered."
                    ),
                    'recommendations': (
                        "1. Review process listening on port {port} at destination endpoint.\n"
                        "2. Inspect payload content and flow direction for command shell banners or binary communication.\n"
                        "3. Verify whether host has an authorized change ticket to run services on this port."
                    )
                })

        return alerts

    def _detect_cleartext_protocols(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-005: Identify observable use of unencrypted protocols (HTTP, FTP, Telnet)."""
        rule_cfg = self.thresholds.get('cleartext_protocols', {})
        monitored = rule_cfg.get('monitored_ports', {80: 'HTTP', 21: 'FTP', 23: 'Telnet'})

        cleartext_flows: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            proto = pkt.get('protocol')
            dport = pkt.get('dst_port')
            sport = pkt.get('src_port')

            identified_proto = None
            relevant_port = None
            if dport in monitored:
                identified_proto = monitored[dport]
                relevant_port = dport
            elif sport in monitored:
                identified_proto = monitored[sport]
                relevant_port = sport
            elif proto == 'HTTP':
                identified_proto = 'HTTP'
                relevant_port = dport or 80

            if identified_proto and pkt.get('src_ip') and pkt.get('dst_ip'):
                cleartext_flows[(pkt['src_ip'], pkt['dst_ip'], identified_proto, relevant_port)].append(pkt)

        alerts = []
        for (src_ip, dst_ip, proto_name, port), pkts in cleartext_flows.items():
            # Avoid noise: require at least 1 packet with actual data or multiple packets
            if len(pkts) >= 1:
                pkts.sort(key=lambda x: x['timestamp'])
                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-005',
                    'rule_name': 'Cleartext Protocol Exposure',
                    'severity': 'Low',
                    'trigger_summary': f"Cleartext protocol {proto_name} observed in transit between {src_ip} and {dst_ip}:{port} ({len(pkts)} packets)",
                    'rationale': (
                        f"Unencrypted protocol {proto_name} traffic was detected in the packet stream. Unencrypted communications transmit headers, "
                        "resource paths, and potential authentication tokens across the wire without confidentiality protection."
                    ),
                    'observed_values': {
                        'protocol': proto_name,
                        'port': port,
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'packet_count': len(pkts)
                    },
                    'packet_indices': [p['index'] for p in pkts],
                    'timestamp_range': f"{pkts[0]['time_iso']} to {pkts[-1]['time_iso']}",
                    'limitations': (
                        "Reporting protocol exposure highlights transport security posture; it does NOT assert that passwords or credentials were stolen. "
                        "Cleartext services are sometimes legitimately maintained in segmented legacy networks or isolated development lab setups."
                    ),
                    'recommendations': (
                        "1. Migrate unencrypted communication channels to TLS-encrypted equivalents (e.g. HTTPS, SFTP, SSH).\n"
                        "2. Inspect application payloads to confirm whether any sensitive credentials or session tokens traversed the channel unmasked.\n"
                        "3. Enforce HTTP Strict Transport Security (HSTS) on web endpoints."
                    )
                })

        return alerts

    def _detect_icmp_anomaly(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """NTH-006: Identify unusually high ICMP packet volumes or repeated ICMP activity (ignoring normal pings)."""
        rule_cfg = self.thresholds.get('icmp_anomaly', {})
        volume_threshold = rule_cfg.get('high_volume_threshold', 15)
        window = rule_cfg.get('time_window_seconds', 5.0)
        large_payload_bytes = rule_cfg.get('large_payload_bytes', 96)

        icmp_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in packets:
            if 'ICMP' in pkt.get('protocol', ''):
                src = pkt.get('src_ip')
                if src and src != 'N/A':
                    icmp_by_src[src].append(pkt)

        alerts = []
        for src_ip, pkts in icmp_by_src.items():
            # Check 1: Large ICMP payload (potential tunneling)
            large_pkts = [p for p in pkts if p.get('raw_payload_len', 0) >= large_payload_bytes]
            if len(large_pkts) >= 4:
                large_pkts.sort(key=lambda x: x['timestamp'])
                alerts.append({
                    'id': str(uuid.uuid4()),
                    'rule_id': 'NTH-006',
                    'rule_name': 'ICMP Activity Anomaly (Large Payload / Potential Covert Channel)',
                    'severity': 'Medium',
                    'trigger_summary': f"Source {src_ip} transmitted {len(large_pkts)} ICMP packets with unusually large payload sizes (>= {large_payload_bytes} bytes)",
                    'rationale': (
                        "ICMP echo packets with oversized payloads were detected. Standard ICMP pings carry minimal padding (32-64 bytes). "
                        "Anomalously large payloads are often utilized in ICMP data exfiltration or tunneling tools (e.g., ptunnel, icmpsh)."
                    ),
                    'observed_values': {
                        'source_ip': src_ip,
                        'large_packet_count': len(large_pkts),
                        'threshold_bytes': large_payload_bytes,
                        'max_payload_observed': max(p.get('raw_payload_len', 0) for p in large_pkts)
                    },
                    'packet_indices': [p['index'] for p in large_pkts],
                    'timestamp_range': f"{large_pkts[0]['time_iso']} to {large_pkts[-1]['time_iso']}",
                    'limitations': (
                        "Network path MTU discovery tools and custom diagnostic stress-tests can intentionally send larger ICMP packets to test network framing."
                    ),
                    'recommendations': (
                        "1. Inspect raw ICMP payload content for base64 or encrypted data chunks.\n"
                        "2. Verify whether source host is running authorized MTU diagnostic tests.\n"
                        "3. Inspect router ICMP packet-size filtering policies."
                    )
                })

            # Check 2: High ICMP volume / flood
            if len(pkts) >= volume_threshold:
                pkts.sort(key=lambda x: x['timestamp'])
                left = 0
                max_burst = []

                for right in range(len(pkts)):
                    while pkts[right]['timestamp'] - pkts[left]['timestamp'] > window:
                        left += 1

                    cur_window = pkts[left:right + 1]
                    if len(cur_window) >= volume_threshold and len(cur_window) > len(max_burst):
                        max_burst = cur_window

                if max_burst:
                    span = max(0.001, max_burst[-1]['timestamp'] - max_burst[0]['timestamp'])
                    rate = round(len(max_burst) / span, 1)
                    alerts.append({
                        'id': str(uuid.uuid4()),
                        'rule_id': 'NTH-006',
                        'rule_name': 'ICMP Activity Anomaly (High Volume / Flood)',
                        'severity': 'Low',
                        'trigger_summary': f"Source {src_ip} generated {len(max_burst)} ICMP packets in {round(span, 2)}s ({rate} pkts/sec)",
                        'rationale': (
                            "Unusually dense concentration of ICMP messages detected. Standard diagnostic ping typically generates 1-4 packets at 1-second intervals. "
                            "Sustained high rates may indicate ping sweep enumeration or ICMP flood activity."
                        ),
                        'observed_values': {
                            'source_ip': src_ip,
                            'packet_count': len(max_burst),
                            'duration_seconds': round(span, 2),
                            'rate_per_sec': rate,
                            'destinations_count': len({p['dst_ip'] for p in max_burst})
                        },
                        'packet_indices': [p['index'] for p in max_burst],
                        'timestamp_range': f"{max_burst[0]['time_iso']} to {max_burst[-1]['time_iso']}",
                        'limitations': (
                            "Network monitoring systems (e.g. Zabbix, PRTG, Nagios) polling multiple subnet targets simultaneously can generate bursts of ICMP packets."
                        ),
                        'recommendations': (
                            "1. Check if source IP corresponds to an enterprise network health monitoring agent.\n"
                            "2. Determine if destination IPs span an entire subnet (sweep pattern).\n"
                            "3. Assess if target devices experienced CPU throttling due to ICMP processing."
                        )
                    })

        return alerts

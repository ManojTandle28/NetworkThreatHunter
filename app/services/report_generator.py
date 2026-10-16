import io
import csv
import json
import html
from typing import List, Dict, Any

class ReportGenerator:
    """Generates sanitized CSV exports, structured JSON summaries, and printable HTML incident reports."""

    @staticmethod
    def sanitize_csv_cell(value: Any) -> str:
        """Mitigate CSV formula injection (DDE attacks) by prefixing dangerous characters with single quote."""
        if value is None:
            return ""
        s = str(value)
        # Characters that can trigger formula execution in spreadsheet software
        if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
            return f"'{s}"
        return s

    @classmethod
    def generate_packets_csv(cls, packets: List[Dict[str, Any]]) -> str:
        """Export packets to CSV with formula injection mitigation."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        headers = [
            'Packet Index', 'Timestamp (UTC)', 'Relative Time (s)',
            'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
            'Protocol', 'Length (Bytes)', 'TCP Flags', 'DNS Query', 'Summary'
        ]
        writer.writerow(headers)

        for p in packets:
            row = [
                cls.sanitize_csv_cell(p.get('packet_index') or p.get('index')),
                cls.sanitize_csv_cell(p.get('time_iso')),
                cls.sanitize_csv_cell(p.get('relative_time')),
                cls.sanitize_csv_cell(p.get('src_ip')),
                cls.sanitize_csv_cell(p.get('src_port') or ''),
                cls.sanitize_csv_cell(p.get('dst_ip')),
                cls.sanitize_csv_cell(p.get('dst_port') or ''),
                cls.sanitize_csv_cell(p.get('protocol')),
                cls.sanitize_csv_cell(p.get('length')),
                cls.sanitize_csv_cell(p.get('tcp_flags') or ''),
                cls.sanitize_csv_cell(p.get('dns_query') or ''),
                cls.sanitize_csv_cell(p.get('summary') or '')
            ]
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def generate_alerts_json(alerts: List[Dict[str, Any]], capture_meta: Dict[str, Any] = None) -> str:
        """Export alerts as formatted JSON string."""
        payload = {
            'report_type': 'NetworkThreatHunter Alerts Export',
            'capture_metadata': capture_meta or {},
            'alert_count': len(alerts),
            'alerts': alerts
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def generate_summary_json(capture_meta: Dict[str, Any], statistics: Dict[str, Any], alerts: List[Dict[str, Any]]) -> str:
        """Export complete analysis summary as formatted JSON string."""
        payload = {
            'platform': 'NetworkThreatHunter — Traffic Analysis & Threat Hunting',
            'capture_metadata': capture_meta,
            'summary_statistics': {
                'total_packets': statistics.get('total_packets', 0),
                'total_bytes': statistics.get('total_bytes', 0),
                'duration_seconds': statistics.get('duration_seconds', 0),
                'unique_src_ips': statistics.get('unique_src_ips', 0),
                'unique_dst_ips': statistics.get('unique_dst_ips', 0),
                'protocol_distribution': statistics.get('protocol_distribution', []),
                'top_source_ips': statistics.get('top_src_ips', []),
                'top_destination_ips': statistics.get('top_dst_ips', []),
                'top_ports': statistics.get('top_ports', [])
            },
            'alerts_summary': {
                'total_alerts': len(alerts),
                'severity_counts': {
                    'Critical': sum(1 for a in alerts if a.get('severity') == 'Critical'),
                    'High': sum(1 for a in alerts if a.get('severity') == 'High'),
                    'Medium': sum(1 for a in alerts if a.get('severity') == 'Medium'),
                    'Low': sum(1 for a in alerts if a.get('severity') == 'Low'),
                },
                'findings': alerts
            }
        }
        return json.dumps(payload, indent=2)

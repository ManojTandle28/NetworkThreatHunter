import os
import time
import json
import uuid
from typing import Dict, Any, List, Tuple
from scapy.utils import PcapReader, PcapNgReader, Scapy_Exception
from app.config import Config
from app.services.packet_normalizer import PacketNormalizer
from app.services.detection_engine import DetectionEngine
from app.services.traffic_statistics import TrafficStatistics
from app.database import get_db

PCAP_MAGIC_NUMBERS = {
    b'\xa1\xb2\xc3\xd4',  # standard pcap, big-endian
    b'\xd4\xc3\xb2\xa1',  # standard pcap, little-endian
    b'\xa1\xb2\x3c\x4d',  # nanosecond pcap, big-endian
    b'\x4d\x3c\xb2\xa1',  # nanosecond pcap, little-endian
}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

class PcapAnalysisError(Exception):
    """Custom exception for PCAP parsing errors with analyst-friendly messages."""
    pass

class PcapAnalyzer:
    """Safe, bounded packet capture parser with pcap/pcapng auto-detection and persistence."""

    def __init__(self, max_packets: int = None, max_preview: int = None):
        self.max_packets = max_packets or Config.MAX_PACKETS_PER_CAPTURE
        self.max_preview = max_preview or Config.MAX_PAYLOAD_PREVIEW_BYTES
        self.detection_engine = DetectionEngine()

    @staticmethod
    def detect_capture_format(file_path: str) -> str:
        """Inspect file header magic bytes to identify format."""
        if not os.path.exists(file_path):
            raise PcapAnalysisError("Specified capture file does not exist.")
        
        size = os.path.getsize(file_path)
        if size == 0:
            raise PcapAnalysisError("The uploaded capture file is completely empty (0 bytes).")
        if size < 4:
            raise PcapAnalysisError("File is too small to contain a valid PCAP or PCAPNG header.")

        with open(file_path, 'rb') as f:
            magic = f.read(4)

        if magic == PCAPNG_MAGIC:
            return 'pcapng'
        elif magic in PCAP_MAGIC_NUMBERS:
            return 'pcap'
        else:
            # Check extension as hint
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.pcapng':
                return 'pcapng'
            return 'pcap'

    def parse_file(self, file_path: str, capture_id: str = None, original_filename: str = None, is_demo: bool = False, db_path: str = None) -> Dict[str, Any]:
        """Stream and analyze packets from a capture file, storing results to SQLite."""
        t0 = time.time()
        file_size = os.path.getsize(file_path)
        capture_format = self.detect_capture_format(file_path)
        cid = capture_id or str(uuid.uuid4())
        orig_name = original_filename or os.path.basename(file_path)

        packets_normalized: List[Dict[str, Any]] = []
        parsing_errors = 0
        parsing_warnings = []
        is_truncated = False
        start_time = None

        # Choose primary reader
        reader = None
        try:
            if capture_format == 'pcapng':
                try:
                    reader = PcapNgReader(file_path)
                except Exception as e:
                    parsing_warnings.append(f"PcapNgReader error ({str(e)}), attempting fallback to standard PcapReader.")
                    reader = PcapReader(file_path)
            else:
                try:
                    reader = PcapReader(file_path)
                except Exception as e:
                    parsing_warnings.append(f"PcapReader error ({str(e)}), attempting fallback to PcapNgReader.")
                    reader = PcapNgReader(file_path)

            pkt_index = 1
            for pkt in reader:
                try:
                    if start_time is None and hasattr(pkt, 'time') and pkt.time is not None:
                        start_time = float(pkt.time)

                    norm = PacketNormalizer.normalize(
                        pkt=pkt,
                        index=pkt_index,
                        start_time=start_time,
                        max_preview=self.max_preview
                    )
                    packets_normalized.append(norm)
                    pkt_index += 1

                    if pkt_index > self.max_packets:
                        is_truncated = True
                        parsing_warnings.append(
                            f"Analysis limit reached ({self.max_packets} packets). Additional packets in capture were omitted to prevent memory exhaustion."
                        )
                        break

                except Exception as err:
                    parsing_errors += 1
                    if len(parsing_warnings) < 5:
                        parsing_warnings.append(f"Packet #{pkt_index} parsing error: {str(err)}")
                    pkt_index += 1

        except Scapy_Exception as se:
            raise PcapAnalysisError(f"Scapy encountered an error parsing capture file: {str(se)}")
        except Exception as e:
            raise PcapAnalysisError(f"Failed to read capture file: {str(e)}")
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass

        if not packets_normalized:
            if parsing_errors > 0:
                raise PcapAnalysisError(f"Unable to parse packets from capture. Encountered {parsing_errors} packet decoding errors.")
            raise PcapAnalysisError("The capture file contains no recognizable network packets or has an unsupported link-layer format.")

        # Compute traffic statistics
        stats = TrafficStatistics.calculate(packets_normalized)

        # Run threat detection rules
        alerts = self.detection_engine.analyze(packets_normalized)

        analysis_duration = round(time.time() - t0, 3)

        # Save to SQLite
        self._persist_to_database(
            db_path=db_path,
            capture_id=cid,
            file_name=os.path.basename(file_path),
            original_filename=orig_name,
            file_size=file_size,
            packet_count=len(packets_normalized),
            duration=analysis_duration,
            is_demo=is_demo,
            packets=packets_normalized,
            alerts=alerts,
            flows=stats.get('tcp_flows', [])
        )

        return {
            'capture_id': cid,
            'original_filename': orig_name,
            'file_size': file_size,
            'packet_count': len(packets_normalized),
            'analysis_duration': analysis_duration,
            'is_truncated': is_truncated,
            'parsing_errors': parsing_errors,
            'parsing_warnings': parsing_warnings,
            'statistics': stats,
            'alerts': alerts
        }

    def _persist_to_database(self, db_path: str, capture_id: str, file_name: str, original_filename: str, file_size: int,
                            packet_count: int, duration: float, is_demo: bool, packets: List[Dict[str, Any]],
                            alerts: List[Dict[str, Any]], flows: List[Dict[str, Any]]):
        """Batch save capture metadata, normalized packets, alerts, and flows to SQLite."""
        with get_db(db_path) as conn:
            # 1. Insert Capture
            conn.execute(
                """INSERT OR REPLACE INTO captures (id, filename, original_filename, file_size, packet_count, analyzed_duration, is_demo, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'completed')""",
                (capture_id, file_name, original_filename, file_size, packet_count, duration, 1 if is_demo else 0)
            )

            # 2. Insert Packets
            packet_rows = []
            for p in packets:
                packet_rows.append((
                    capture_id,
                    p['index'],
                    p['timestamp'],
                    p['time_iso'],
                    p['relative_time'],
                    p['src_ip'],
                    p['src_port'],
                    p['dst_ip'],
                    p['dst_port'],
                    p['protocol'],
                    p['length'],
                    p['tcp_flags'],
                    p['dns_query'],
                    p['dns_type'],
                    p['summary'],
                    p['is_cleartext'],
                    p['is_encrypted'],
                    p['payload_hex'],
                    p['payload_ascii'],
                    json.dumps(p.get('layer_details', {}))
                ))

            conn.executemany(
                """INSERT INTO packets (capture_id, packet_index, timestamp, time_iso, relative_time,
                                       src_ip, src_port, dst_ip, dst_port, protocol, length,
                                       tcp_flags, dns_query, dns_type, summary, is_cleartext,
                                       is_encrypted, payload_hex, payload_ascii, layer_details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                packet_rows
            )

            # 3. Insert Alerts
            alert_rows = []
            for a in alerts:
                alert_rows.append((
                    a['id'],
                    capture_id,
                    a['rule_id'],
                    a['rule_name'],
                    a['severity'],
                    a['trigger_summary'],
                    a['rationale'],
                    json.dumps(a['observed_values']),
                    json.dumps(a['packet_indices']),
                    a['timestamp_range'],
                    a['limitations'],
                    a['recommendations'],
                    a.get('status', 'New'),
                    a.get('analyst_notes', '')
                ))

            conn.executemany(
                """INSERT OR REPLACE INTO alerts (id, capture_id, rule_id, rule_name, severity,
                                                  trigger_summary, rationale, observed_values_json,
                                                  packet_indices_json, timestamp_range, limitations,
                                                  recommendations, status, analyst_notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                alert_rows
            )

            # 4. Insert Flows
            flow_rows = []
            for f in flows:
                flow_rows.append((
                    capture_id,
                    f['flow_key'],
                    f['src_ip'],
                    f['src_port'],
                    f['dst_ip'],
                    f['dst_port'],
                    'TCP',
                    f['packet_count'],
                    f['byte_count'],
                    f['state'],
                    f.get('start_time', 0.0),
                    f.get('end_time', 0.0),
                    f.get('duration', 0.0)
                ))

            conn.executemany(
                """INSERT INTO flows (capture_id, flow_key, src_ip, src_port, dst_ip, dst_port,
                                     protocol, packet_count, byte_count, state, start_time, end_time, duration)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                flow_rows
            )

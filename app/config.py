import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Application configuration for NetworkThreatHunter."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'nth-threat-hunter-dev-secret-key-3914')
    
    # Upload limits and storage
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 25 * 1024 * 1024))  # 25 MB default
    ALLOWED_EXTENSIONS = {'.pcap', '.pcapng'}
    
    # Parsing limits
    MAX_PACKETS_PER_CAPTURE = int(os.environ.get('MAX_PACKETS_PER_CAPTURE', 50000))
    MAX_PAYLOAD_PREVIEW_BYTES = 256
    
    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'threat_hunter.db')
    
    # Detection Engine Thresholds (Configurable)
    DETECTION_THRESHOLDS = {
        'port_scan': {
            'min_distinct_ports': 12,       # Minimum distinct ports scanned
            'time_window_seconds': 60.0,    # Time window for scanning activity
        },
        'connection_rate': {
            'rate_threshold_per_sec': 12.0, # SYN attempts per second threshold
            'min_attempts': 20,             # Minimum attempts required before rate evaluation
            'burst_window_seconds': 5.0,    # Evaluation interval
        },
        'suspicious_dns': {
            'max_query_length': 45,         # Character length for suspicious domain query
            'query_rate_per_sec': 8.0,      # High DNS query rate threshold
            'min_burst_queries': 15,        # Minimum queries in burst window
            'burst_window_seconds': 5.0,
        },
        'unusual_port': {
            'common_ports': {
                20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143,
                161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389,
                5432, 8000, 8080, 8443, 8888
            },
            'suspicious_indicator_ports': {
                1337, 31337, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 12345, 27017, 65535
            },
            'min_packets_threshold': 5,     # Min packets to high/suspicious port
        },
        'cleartext_protocols': {
            'monitored_ports': {
                80: 'HTTP',
                21: 'FTP',
                23: 'Telnet',
                110: 'POP3',
                143: 'IMAP',
            }
        },
        'icmp_anomaly': {
            'high_volume_threshold': 15,    # ICMP packets within window
            'time_window_seconds': 5.0,     # Time window
            'large_payload_bytes': 96,      # Unusual payload size (standard ping is ~32-64 bytes)
        }
    }

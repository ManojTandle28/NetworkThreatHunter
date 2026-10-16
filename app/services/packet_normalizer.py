import datetime
from typing import Dict, Any, List, Optional
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
try:
    from scapy.layers.inet6 import IPv6, _ICMPv6
except ImportError:
    IPv6 = None
    _ICMPv6 = None
try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    DNS = None
    DNSQR = None
    DNSRR = None

DNS_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    255: 'ANY'
}

DNS_RCODES = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED'
}

TCP_FLAG_MAP = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR'
}

def decode_tcp_flags(flags_val) -> tuple[List[str], str]:
    """Decode TCP flags into list of readable flag names and short code."""
    if not flags_val:
        return [], ''
    flag_str = str(flags_val)
    readable = []
    for char in flag_str:
        if char in TCP_FLAG_MAP:
            readable.append(TCP_FLAG_MAP[char])
    return readable, flag_str

def format_safe_ascii(data: bytes, max_len: int = 256) -> str:
    """Produce safe ASCII representation replacing control chars with dots."""
    snippet = data[:max_len]
    chars = []
    for b in snippet:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append('.')
    return ''.join(chars)

def format_hex_dump(data: bytes, max_len: int = 256) -> str:
    """Format bytes into space-separated uppercase hex pairs."""
    snippet = data[:max_len]
    return ' '.join(f'{b:02X}' for b in snippet)

class PacketNormalizer:
    """Extracts standardized, safe, and explainable metadata from raw Scapy packets."""

    @staticmethod
    def normalize(pkt: Packet, index: int, start_time: Optional[float] = None, max_preview: int = 256) -> Dict[str, Any]:
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') and pkt.time is not None else 0.0
        ref_time = start_time if start_time is not None else pkt_time
        relative_time = max(0.0, pkt_time - ref_time)
        
        try:
            dt = datetime.datetime.fromtimestamp(pkt_time, tz=datetime.timezone.utc)
            time_iso = dt.strftime('%Y-%m-%d %H:%M:%S.%f')
        except (ValueError, OSError, OverflowError):
            time_iso = '1970-01-01 00:00:00.000000'

        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = 'OTHER'
        tcp_flags_list = []
        tcp_flags_str = ''
        dns_query = None
        dns_type = None
        is_cleartext = False
        is_encrypted = False
        summary = ''

        # Layer discovery
        layers_present = []
        layer_details: Dict[str, Any] = {}
        
        curr_layer = pkt
        while curr_layer:
            layer_name = curr_layer.__class__.__name__
            if layer_name != 'Padding':
                layers_present.append(layer_name)
            curr_layer = curr_layer.payload if hasattr(curr_layer, 'payload') and curr_layer.payload else None

        # Network layer parsing
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = f'IPv4-{pkt[IP].proto}'
            layer_details['IP'] = {
                'version': 4,
                'src': src_ip,
                'dst': dst_ip,
                'ttl': pkt[IP].ttl,
                'id': pkt[IP].id,
                'proto': pkt[IP].proto,
                'len': pkt[IP].len
            }
        elif IPv6 and IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            protocol = f'IPv6-{pkt[IPv6].nh}'
            layer_details['IPv6'] = {
                'version': 6,
                'src': src_ip,
                'dst': dst_ip,
                'tc': pkt[IPv6].tc,
                'nh': pkt[IPv6].nh,
                'hlim': pkt[IPv6].hlim
            }
        elif ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            protocol = 'ARP'
            op_name = 'Request' if pkt[ARP].op == 1 else ('Reply' if pkt[ARP].op == 2 else str(pkt[ARP].op))
            layer_details['ARP'] = {
                'op': op_name,
                'src_mac': pkt[ARP].hwsrc,
                'dst_mac': pkt[ARP].hwdst,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            }
            summary = f"ARP {op_name}: {src_ip} -> {dst_ip}"

        # Transport & Application layers
        raw_payload = b''
        
        if TCP in pkt:
            protocol = 'TCP'
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags_list, tcp_flags_str = decode_tcp_flags(pkt[TCP].flags)
            layer_details['TCP'] = {
                'sport': src_port,
                'dport': dst_port,
                'seq': pkt[TCP].seq,
                'ack': pkt[TCP].ack,
                'flags': tcp_flags_str,
                'flags_decoded': tcp_flags_list,
                'window': pkt[TCP].window
            }
            
            # Check for TLS
            if src_port == 443 or dst_port == 443 or 'TLS' in layers_present:
                is_encrypted = True
                
            # Check for Cleartext HTTP / FTP / Telnet
            if src_port in (80, 8080) or dst_port in (80, 8080):
                is_cleartext = True
            elif src_port == 21 or dst_port == 21:
                is_cleartext = True
            elif src_port == 23 or dst_port == 23:
                is_cleartext = True

            summary = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{tcp_flags_str}]"

        elif UDP in pkt:
            protocol = 'UDP'
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            layer_details['UDP'] = {
                'sport': src_port,
                'dport': dst_port,
                'len': pkt[UDP].len
            }
            
            if src_port == 443 or dst_port == 443:
                is_encrypted = True  # QUIC / DoH / etc.
                
            summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        elif ICMP in pkt:
            protocol = 'ICMP'
            icmp_type = pkt[ICMP].type
            icmp_code = pkt[ICMP].code
            type_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
            type_name = type_names.get(icmp_type, f'Type {icmp_type}')
            layer_details['ICMP'] = {
                'type': icmp_type,
                'code': icmp_code,
                'name': type_name
            }
            summary = f"ICMP {type_name}: {src_ip} -> {dst_ip}"

        elif _ICMPv6 and _ICMPv6 in pkt:
            protocol = 'ICMPv6'
            summary = f"ICMPv6: {src_ip} -> {dst_ip}"

        # DNS extraction
        if DNS and DNS in pkt:
            protocol = 'DNS'
            dns_pkt = pkt[DNS]
            is_response = bool(dns_pkt.qr == 1)
            dns_info: Dict[str, Any] = {
                'qr': 'Response' if is_response else 'Query',
                'id': dns_pkt.id,
                'rcode': DNS_RCODES.get(dns_pkt.rcode, str(dns_pkt.rcode)) if is_response else None
            }
            qd_obj = None
            if dns_pkt.qd:
                if hasattr(dns_pkt.qd, 'qname'):
                    qd_obj = dns_pkt.qd
                elif isinstance(dns_pkt.qd, (list, tuple)) and len(dns_pkt.qd) > 0:
                    qd_obj = dns_pkt.qd[0]
            
            if qd_obj and hasattr(qd_obj, 'qname'):
                raw_qname = getattr(qd_obj, 'qname', None)
                if isinstance(raw_qname, bytes):
                    query_str = raw_qname.decode('utf-8', errors='replace').rstrip('.')
                else:
                    query_str = str(raw_qname).rstrip('.')
                dns_query = query_str
                raw_qtype = getattr(qd_obj, 'qtype', 1)
                dns_type = DNS_TYPES.get(raw_qtype, str(raw_qtype))
                dns_info['query'] = dns_query
                dns_info['type'] = dns_type
                summary = f"DNS {'Resp' if is_response else 'Query'} ({dns_type}): {dns_query}"
            layer_details['DNS'] = dns_info

        # Extract payload data for preview
        if hasattr(pkt, 'load') and pkt.load:
            raw_payload = bytes(pkt.load)
        elif hasattr(pkt, 'lastlayer') and hasattr(pkt.lastlayer(), 'load'):
            raw_payload = bytes(pkt.lastlayer().load)

        # Inspect raw payload for HTTP markers if port or payload indicates it
        if raw_payload and (protocol == 'TCP' or protocol == 'HTTP'):
            http_methods = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'HTTP/1.', b'HTTP/2.')
            if any(raw_payload.startswith(m) for m in http_methods):
                protocol = 'HTTP'
                is_cleartext = True
                first_line = raw_payload.split(b'\r\n')[0].decode('utf-8', errors='replace')
                layer_details['HTTP'] = {'header_line': first_line}
                summary = f"HTTP {first_line[:40]}"

        payload_hex = format_hex_dump(raw_payload, max_preview) if raw_payload else ''
        payload_ascii = format_safe_ascii(raw_payload, max_preview) if raw_payload else ''

        return {
            'index': index,
            'timestamp': pkt_time,
            'time_iso': time_iso,
            'relative_time': round(relative_time, 6),
            'src_ip': src_ip or 'N/A',
            'src_port': src_port,
            'dst_ip': dst_ip or 'N/A',
            'dst_port': dst_port,
            'protocol': protocol,
            'length': len(pkt),
            'tcp_flags': ', '.join(tcp_flags_list) if tcp_flags_list else '',
            'tcp_flags_str': tcp_flags_str,
            'dns_query': dns_query,
            'dns_type': dns_type,
            'summary': summary or f"{protocol} packet",
            'is_cleartext': 1 if is_cleartext else 0,
            'is_encrypted': 1 if is_encrypted else 0,
            'payload_hex': payload_hex,
            'payload_ascii': payload_ascii,
            'layers': layers_present,
            'layer_details': layer_details,
            'raw_payload_len': len(raw_payload)
        }

import os
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PCAP = BASE_DIR / "sample_traffic.pcap"

def create_synthetic_pcap():
    """Generates a realistic, safe synthetic network traffic capture containing normal and threat patterns."""
    packets = []
    base_time = 1718000000.0  # Deterministic reference timestamp
    src_mac = "00:11:22:33:44:55"
    dst_mac = "00:aa:bb:cc:dd:ee"

    # Helper to append packet with timestamp and explicit MACs
    def add_pkt(ip_layer, offset_sec):
        eth = Ether(src=src_mac, dst=dst_mac)
        pkt = eth / ip_layer
        pkt.time = base_time + offset_sec
        packets.append(pkt)

    # -------------------------------------------------------------
    # 1. Normal DNS Resolution (Benign baseline)
    # -------------------------------------------------------------
    t = 0.1
    # Query google.com
    dns_q1 = IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=51234, dport=53)/DNS(
        id=0x1001, qr=0, qd=DNSQR(qname="google.com", qtype="A")
    )
    add_pkt(dns_q1, t)
    t += 0.03
    dns_r1 = IP(src="8.8.8.8", dst="192.168.1.50")/UDP(sport=53, dport=51234)/DNS(
        id=0x1001, qr=1, ancount=1, qd=DNSQR(qname="google.com", qtype="A"),
        an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46", ttl=300)
    )
    add_pkt(dns_r1, t)

    # Query github.com
    t += 0.2
    dns_q2 = IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=51235, dport=53)/DNS(
        id=0x1002, qr=0, qd=DNSQR(qname="github.com", qtype="A")
    )
    add_pkt(dns_q2, t)
    t += 0.04
    dns_r2 = IP(src="8.8.8.8", dst="192.168.1.50")/UDP(sport=53, dport=51235)/DNS(
        id=0x1002, qr=1, ancount=1, qd=DNSQR(qname="github.com", qtype="A"),
        an=DNSRR(rrname="github.com", type="A", rdata="140.82.121.4", ttl=300)
    )
    add_pkt(dns_r2, t)

    # -------------------------------------------------------------
    # 2. Normal Web Traffic & Cleartext HTTP Exposure (NTH-005)
    # -------------------------------------------------------------
    # TCP 3-Way Handshake
    t += 0.3
    syn = IP(src="192.168.1.50", dst="93.184.216.34")/TCP(sport=49210, dport=80, flags="S", seq=1000)
    add_pkt(syn, t)
    t += 0.02
    synack = IP(src="93.184.216.34", dst="192.168.1.50")/TCP(sport=80, dport=49210, flags="SA", seq=5000, ack=1001)
    add_pkt(synack, t)
    t += 0.01
    ack = IP(src="192.168.1.50", dst="93.184.216.34")/TCP(sport=49210, dport=80, flags="A", seq=1001, ack=5001)
    add_pkt(ack, t)

    # HTTP GET Request (Cleartext protocol exposure)
    t += 0.05
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
    http_req = IP(src="192.168.1.50", dst="93.184.216.34")/TCP(sport=49210, dport=80, flags="PA", seq=1001, ack=5001)/Raw(load=http_payload)
    add_pkt(http_req, t)

    # HTTP Response
    t += 0.06
    http_resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>Example Domain</body></html>"
    http_resp = IP(src="93.184.216.34", dst="192.168.1.50")/TCP(sport=80, dport=49210, flags="PA", seq=5001, ack=1001 + len(http_payload))/Raw(load=http_resp_payload)
    add_pkt(http_resp, t)

    # TCP Teardown
    t += 0.02
    fin = IP(src="192.168.1.50", dst="93.184.216.34")/TCP(sport=49210, dport=80, flags="FA", seq=1001 + len(http_payload), ack=5001 + len(http_resp_payload))
    add_pkt(fin, t)

    # -------------------------------------------------------------
    # 3. Normal ICMP Diagnostic Echo (Ping)
    # -------------------------------------------------------------
    for i in range(3):
        t += 0.2
        ping_req = IP(src="192.168.1.20", dst="192.168.1.1")/ICMP(type=8, code=0, id=0x200, seq=i+1)/Raw(load=b"A"*32)
        add_pkt(ping_req, t)
        t += 0.01
        ping_rep = IP(src="192.168.1.1", dst="192.168.1.20")/ICMP(type=0, code=0, id=0x200, seq=i+1)/Raw(load=b"A"*32)
        add_pkt(ping_rep, t)

    # -------------------------------------------------------------
    # 4. Port Scan Pattern (NTH-001)
    # Source 192.168.1.105 scanning target 192.168.1.10 across 16 distinct ports
    # -------------------------------------------------------------
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080]
    t += 0.5
    for port in scan_ports:
        scan_pkt = IP(src="192.168.1.105", dst="192.168.1.10")/TCP(sport=40000 + port % 1000, dport=port, flags="S", seq=20000 + port)
        add_pkt(scan_pkt, t)
        t += 0.05

    # -------------------------------------------------------------
    # 5. High Connection Attempt Rate (NTH-002)
    # Source 10.0.0.99 generating rapid SYN burst to target port 80
    # -------------------------------------------------------------
    t += 0.5
    for i in range(25):
        burst_pkt = IP(src="10.0.0.99", dst="192.168.1.10")/TCP(sport=30000 + i, dport=80, flags="S", seq=50000 + i)
        add_pkt(burst_pkt, t)
        t += 0.04  # 25 attempts in ~1.0 second (~25 conn/sec)

    # -------------------------------------------------------------
    # 6. Suspicious DNS Activity (NTH-003) - Long query names
    # -------------------------------------------------------------
    t += 0.5
    suspicious_domains = [
        "v1-staging-exfil-94f71a0b3e218c5412df7a9b0c1e.data.tunnel-c2.net",  # 64 chars
        "dga-node7b2c91fa64820dc719e482bf10.malicious-fastflux.org",         # 57 chars
        "beacon-auth-token-c399b1742df810ea.c2.threat-domain.xyz"            # 55 chars
    ]
    for dom in suspicious_domains:
        t += 0.1
        dns_susp = IP(src="192.168.1.75", dst="8.8.8.8")/UDP(sport=52000, dport=53)/DNS(
            id=0x3000, qr=0, qd=DNSQR(qname=dom, qtype="TXT")
        )
        add_pkt(dns_susp, t)

    # -------------------------------------------------------------
    # 7. Unusual Destination / Backdoor Port Concentration (NTH-004)
    # Traffic to Metasploit / RAT default port 4444
    # -------------------------------------------------------------
    t += 0.4
    for i in range(7):
        rat_pkt = IP(src="192.168.1.60", dst="198.51.100.23")/TCP(
            sport=45100 + i, dport=4444, flags="PA", seq=60000 + i * 10
        )/Raw(load=b"cmd.exe /c whoami\n")
        add_pkt(rat_pkt, t)
        t += 0.1

    # -------------------------------------------------------------
    # 8. ICMP Activity Anomaly (NTH-006) - Oversized Payload
    # -------------------------------------------------------------
    t += 0.4
    oversized_payload = b"EXFILTRATION_DATA_BLOCK_" + (b"0123456789ABCDEF" * 8)  # 152 bytes
    for i in range(5):
        icmp_large = IP(src="192.168.1.88", dst="198.51.100.99")/ICMP(type=8, code=0, id=0x400, seq=i+1)/Raw(load=oversized_payload)
        add_pkt(icmp_large, t)
        t += 0.08

    # Sort packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    os.makedirs(OUTPUT_PCAP.parent, exist_ok=True)
    wrpcap(str(OUTPUT_PCAP), packets)
    print(f"[+] Successfully generated synthetic PCAP at: {OUTPUT_PCAP}")
    print(f"[+] Total packets written: {len(packets)}")
    return OUTPUT_PCAP

if __name__ == "__main__":
    create_synthetic_pcap()

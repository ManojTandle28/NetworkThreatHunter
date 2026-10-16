import os
import tempfile
import pytest
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR
from app import create_app
from app.config import Config
from app.database import init_db

class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key-123'

@pytest.fixture
def app():
    temp_dir = tempfile.mkdtemp()
    test_db = os.path.join(temp_dir, 'test_threat_hunter.db')
    test_upload = os.path.join(temp_dir, 'uploads')
    os.makedirs(test_upload, exist_ok=True)

    app = create_app()
    app.config.update({
        'TESTING': True,
        'DATABASE_PATH': test_db,
        'UPLOAD_FOLDER': test_upload
    })

    with app.app_context():
        init_db(test_db)
        yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def test_db_path(app):
    return app.config['DATABASE_PATH']

@pytest.fixture
def sample_pcap_path():
    """Generates a small deterministic PCAP file for testing."""
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)

    src_mac = "00:11:22:33:44:55"
    dst_mac = "00:aa:bb:cc:dd:ee"
    t0 = 1700000000.0

    pkts = [
        Ether(src=src_mac, dst=dst_mac)/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=50000, dport=80, flags="S"),
        Ether(src=src_mac, dst=dst_mac)/IP(src="192.168.1.1", dst="192.168.1.10")/TCP(sport=80, dport=50000, flags="SA"),
        Ether(src=src_mac, dst=dst_mac)/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=50000, dport=80, flags="A"),
        Ether(src=src_mac, dst=dst_mac)/IP(src="192.168.1.20", dst="8.8.8.8")/UDP(sport=53000, dport=53)/DNS(
            id=1, qr=0, qd=DNSQR(qname="test.example.com")
        ),
        Ether(src=src_mac, dst=dst_mac)/IP(src="192.168.1.30", dst="192.168.1.1")/ICMP(type=8, code=0)
    ]
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.1

    wrpcap(path, pkts)
    yield path

    if os.path.exists(path):
        os.remove(path)

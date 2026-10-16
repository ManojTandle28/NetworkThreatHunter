import io
import os
from flask import session

def test_dashboard_empty(client):
    res = client.get('/dashboard')
    assert res.status_code == 200
    assert b"Network Traffic Threat Hunting Platform" in res.data

def test_load_demo(client):
    res = client.post('/demo', follow_redirects=True)
    assert res.status_code == 200
    assert b"Total Packets" in res.data
    assert b"SYNTHETIC DEMONSTRATION TRAFFIC" in res.data

def test_upload_invalid_extension(client):
    data = {'pcap_file': (io.BytesIO(b"fake payload"), "malware.exe")}
    res = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b"Unsupported file format" in res.data
    assert b".exe" in res.data

def test_upload_missing_file(client):
    res = client.post('/upload', data={}, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b"No file part provided" in res.data

def test_upload_valid_pcap(client, sample_pcap_path):
    with open(sample_pcap_path, 'rb') as f:
        file_bytes = f.read()

    data = {'pcap_file': (io.BytesIO(file_bytes), "sample.pcap")}
    res = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b"Successfully analyzed" in res.data
    assert b"sample.pcap" in res.data

def test_packet_explorer_api(client):
    # First load demo
    client.post('/demo')

    # Query explorer API
    res = client.get('/api/packets?page=1&page_size=10')
    assert res.status_code == 200
    data = res.get_json()
    assert data['total'] > 0
    assert len(data['packets']) <= 10

    # Query with protocol filter
    res_dns = client.get('/api/packets?protocol=DNS')
    assert res_dns.status_code == 200
    dns_data = res_dns.get_json()
    for p in dns_data['packets']:
        assert p['protocol'] == 'DNS'

    # Query single packet detail
    first_idx = data['packets'][0]['packet_index']
    res_detail = client.get(f'/api/packets/{first_idx}')
    assert res_detail.status_code == 200
    detail = res_detail.get_json()
    assert 'packet' in detail
    assert 'layer_details' in detail['packet']

def test_investigate_api(client):
    client.post('/demo')
    res = client.get('/api/investigate/192.168.1.50')
    assert res.status_code == 200
    data = res.get_json()
    assert data['ip'] == '192.168.1.50'
    assert 'packets_sent' in data
    assert 'peers_outbound' in data

def test_clear_history(client):
    client.post('/demo')
    res_clear = client.post('/clear', follow_redirects=True)
    assert res_clear.status_code == 200
    assert b"permanently cleared" in res_clear.data

    # Now status should be idle
    res_status = client.get('/api/status')
    assert res_status.get_json()['status'] == 'idle'

from app.services.report_generator import ReportGenerator

def test_sanitize_csv_formula_injection():
    # Characters that trigger formula execution in spreadsheet software
    assert ReportGenerator.sanitize_csv_cell("=1+1") == "'=1+1"
    assert ReportGenerator.sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert ReportGenerator.sanitize_csv_cell("-10") == "'-10"
    assert ReportGenerator.sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert ReportGenerator.sanitize_csv_cell("\tTABBED") == "'\tTABBED"
    assert ReportGenerator.sanitize_csv_cell("\rRETURN") == "'\rRETURN"

    # Benign strings should not be modified
    assert ReportGenerator.sanitize_csv_cell("192.168.1.1") == "192.168.1.1"
    assert ReportGenerator.sanitize_csv_cell("TCP") == "TCP"
    assert ReportGenerator.sanitize_csv_cell(None) == ""

def test_generate_csv_data():
    packets = [
        {
            'packet_index': 1, 'time_iso': '2024-06-10 12:00:00.000000',
            'relative_time': 0.0, 'src_ip': '=192.168.1.1', 'src_port': 50000,
            'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
            'length': 60, 'tcp_flags': 'SYN', 'dns_query': '', 'summary': 'TCP Test'
        }
    ]
    csv_text = ReportGenerator.generate_packets_csv(packets)
    assert "Packet Index,Timestamp (UTC)" in csv_text
    assert "'=192.168.1.1" in csv_text  # Formula injection properly mitigated

def test_export_endpoints(client):
    client.post('/demo')

    # CSV Export
    res_csv = client.get('/export/csv')
    assert res_csv.status_code == 200
    assert res_csv.mimetype == "text/csv"
    assert "attachment; filename=" in res_csv.headers.get("Content-Disposition", "")
    assert b"Packet Index" in res_csv.data

    # Alerts JSON Export
    res_alerts = client.get('/export/alerts/json')
    assert res_alerts.status_code == 200
    assert res_alerts.mimetype == "application/json"
    data = res_alerts.get_json()
    assert 'alerts' in data
    assert 'report_type' in data

    # Summary JSON Export
    res_summary = client.get('/export/summary/json')
    assert res_summary.status_code == 200
    assert res_summary.mimetype == "application/json"
    sum_data = res_summary.get_json()
    assert 'summary_statistics' in sum_data
    assert 'alerts_summary' in sum_data

    # Incident Report HTML
    res_report = client.get('/report')
    assert res_report.status_code == 200
    assert b"Incident & Threat Investigation Report" in res_report.data
    assert b"Executive Summary" in res_report.data
    assert b"DISCLAIMER & LIMITATIONS" in res_report.data

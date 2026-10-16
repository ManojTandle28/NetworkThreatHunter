from app.database import get_db

def test_alerts_list_and_detail(client):
    client.post('/demo')

    res = client.get('/alerts')
    assert res.status_code == 200
    assert b"Threat Hunting Findings" in res.data
    assert b"NTH-" in res.data

    # Fetch an alert ID
    res_json = client.get('/export/alerts/json')
    alerts_data = res_json.get_json()['alerts']
    assert len(alerts_data) > 0
    test_alert_id = alerts_data[0]['id']

    # Test alert detail view
    res_detail = client.get(f'/alerts/{test_alert_id}')
    assert res_detail.status_code == 200
    assert alerts_data[0]['rule_id'].encode() in res_detail.data

def test_update_alert_status_and_notes(client, test_db_path):
    client.post('/demo')

    res_json = client.get('/export/alerts/json')
    test_alert_id = res_json.get_json()['alerts'][0]['id']

    # Update status to Investigating
    res_status = client.post(
        f'/api/alerts/{test_alert_id}/status',
        json={'status': 'Investigating'}
    )
    assert res_status.status_code == 200
    assert res_status.get_json()['status'] == 'Investigating'

    # Save analyst notes
    note_content = "Observed suspicious recon activity. Correlated with firewall logs."
    res_note = client.post(
        f'/api/alerts/{test_alert_id}/notes',
        json={'notes': note_content}
    )
    assert res_note.status_code == 200
    assert res_note.get_json()['notes'] == note_content

    # Verify persistence in SQLite
    with get_db(test_db_path) as conn:
        row = conn.execute("SELECT status, analyst_notes FROM alerts WHERE id = ?", (test_alert_id,)).fetchone()
        assert row['status'] == 'Investigating'
        assert row['analyst_notes'] == note_content

def test_invalid_status_rejection(client):
    client.post('/demo')
    res_json = client.get('/export/alerts/json')
    test_alert_id = res_json.get_json()['alerts'][0]['id']

    res = client.post(
        f'/api/alerts/{test_alert_id}/status',
        json={'status': 'HACKED_INVALID_STATE'}
    )
    assert res.status_code == 400
    assert "Invalid status" in res.get_json()['error']

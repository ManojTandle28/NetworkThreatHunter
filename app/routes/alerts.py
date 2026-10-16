import json
from flask import render_template, request, jsonify, flash, redirect, url_for
from app.routes import alerts_bp
from app.database import get_db
from app.routes.main import get_current_capture

@alerts_bp.route('/alerts')
def alerts_list():
    capture = get_current_capture()
    if not capture:
        flash("Please upload a packet capture or load the synthetic demo to review threat alerts.", "info")
        return redirect(url_for('main.dashboard'))

    cid = capture['id']
    severity_filter = request.args.get('severity', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = "SELECT * FROM alerts WHERE capture_id = ?"
    params = [cid]

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, created_at ASC"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        alerts = []
        for r in rows:
            a = dict(r)
            try:
                a['observed_values'] = json.loads(a.get('observed_values_json', '{}'))
            except Exception:
                a['observed_values'] = {}
            try:
                a['packet_indices'] = json.loads(a.get('packet_indices_json', '[]'))
            except Exception:
                a['packet_indices'] = []
            alerts.append(a)

        # Compute summary counts
        all_alerts_rows = conn.execute("SELECT severity, status FROM alerts WHERE capture_id = ?", (cid,)).fetchall()
        counts = {
            'total': len(all_alerts_rows),
            'critical': sum(1 for r in all_alerts_rows if r['severity'] == 'Critical'),
            'high': sum(1 for r in all_alerts_rows if r['severity'] == 'High'),
            'medium': sum(1 for r in all_alerts_rows if r['severity'] == 'Medium'),
            'low': sum(1 for r in all_alerts_rows if r['severity'] == 'Low'),
            'new': sum(1 for r in all_alerts_rows if r['status'] == 'New'),
            'investigating': sum(1 for r in all_alerts_rows if r['status'] == 'Investigating'),
            'closed': sum(1 for r in all_alerts_rows if r['status'] == 'Closed'),
        }

    return render_template(
        'alerts.html',
        capture=capture,
        alerts=alerts,
        counts=counts,
        severity_filter=severity_filter,
        status_filter=status_filter
    )

@alerts_bp.route('/alerts/<alert_id>')
def alert_detail(alert_id: str):
    capture = get_current_capture()
    if not capture:
        flash("No active capture found.", "warning")
        return redirect(url_for('main.dashboard'))

    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ? AND capture_id = ?", (alert_id, capture['id'])).fetchone()
        if not row:
            flash(f"Alert '{alert_id}' not found.", "error")
            return redirect(url_for('alerts.alerts_list'))

        alert = dict(row)
        try:
            alert['observed_values'] = json.loads(alert.get('observed_values_json', '{}'))
        except Exception:
            alert['observed_values'] = {}
        try:
            alert['packet_indices'] = json.loads(alert.get('packet_indices_json', '[]'))
        except Exception:
            alert['packet_indices'] = []

        # Fetch supporting evidence packets (up to 50)
        evidence_packets = []
        if alert['packet_indices']:
            placeholders = ','.join(['?'] * len(alert['packet_indices'][:50]))
            params = [capture['id']] + alert['packet_indices'][:50]
            evidence_rows = conn.execute(
                f"""SELECT packet_index, time_iso, relative_time, src_ip, src_port,
                           dst_ip, dst_port, protocol, length, tcp_flags, dns_query, summary
                    FROM packets WHERE capture_id = ? AND packet_index IN ({placeholders})
                    ORDER BY packet_index ASC""",
                params
            ).fetchall()
            evidence_packets = [dict(r) for r in evidence_rows]

    return render_template('alert_detail.html', capture=capture, alert=alert, evidence_packets=evidence_packets)

@alerts_bp.route('/api/alerts/<alert_id>/status', methods=['POST'])
def update_alert_status(alert_id: str):
    data = request.get_json(silent=True) or request.form
    new_status = data.get('status', '').strip()
    if new_status not in ('New', 'Investigating', 'Closed'):
        return jsonify({'error': f"Invalid status '{new_status}'. Allowed: 'New', 'Investigating', 'Closed'"}), 400

    with get_db() as conn:
        cur = conn.execute("UPDATE alerts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, alert_id))
        if cur.rowcount == 0:
            return jsonify({'error': 'Alert not found'}), 404

    return jsonify({'success': True, 'alert_id': alert_id, 'status': new_status})

@alerts_bp.route('/api/alerts/<alert_id>/notes', methods=['POST'])
def update_alert_notes(alert_id: str):
    data = request.get_json(silent=True) or request.form
    notes = data.get('notes', '')

    with get_db() as conn:
        cur = conn.execute("UPDATE alerts SET analyst_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (notes, alert_id))
        if cur.rowcount == 0:
            return jsonify({'error': 'Alert not found'}), 404

    return jsonify({'success': True, 'alert_id': alert_id, 'notes': notes})

@alerts_bp.route('/investigate')
def investigate_page():
    capture = get_current_capture()
    if not capture:
        flash("Please upload a capture or load demo traffic to investigate host endpoints.", "info")
        return redirect(url_for('main.dashboard'))

    selected_ip = request.args.get('ip', '').strip()
    cid = capture['id']

    with get_db() as conn:
        # Get list of unique IP addresses
        src_ips = conn.execute("SELECT DISTINCT src_ip FROM packets WHERE capture_id = ? AND src_ip != 'N/A'", (cid,)).fetchall()
        dst_ips = conn.execute("SELECT DISTINCT dst_ip FROM packets WHERE capture_id = ? AND dst_ip != 'N/A'", (cid,)).fetchall()
        all_ips = sorted(list({r[0] for r in src_ips + dst_ips if r[0]}))

        details = None
        if selected_ip:
            details = get_ip_investigation_data(conn, cid, selected_ip)

    return render_template('investigate.html', capture=capture, all_ips=all_ips, selected_ip=selected_ip, details=details)

@alerts_bp.route('/api/investigate/<ip>')
def api_investigate_ip(ip: str):
    capture = get_current_capture()
    if not capture:
        return jsonify({'error': 'No active capture found'}), 404

    with get_db() as conn:
        details = get_ip_investigation_data(conn, capture['id'], ip)

    return jsonify(details)

def get_ip_investigation_data(conn, capture_id: str, ip: str) -> dict:
    """Compile comprehensive threat hunting drilldown for a specific IP address."""
    # Traffic sent
    sent_row = conn.execute(
        "SELECT COUNT(*) as pkt_count, COALESCE(SUM(length), 0) as byte_count, MIN(time_iso) as first_seen, MAX(time_iso) as last_seen FROM packets WHERE capture_id = ? AND src_ip = ?",
        (capture_id, ip)
    ).fetchone()

    # Traffic received
    recv_row = conn.execute(
        "SELECT COUNT(*) as pkt_count, COALESCE(SUM(length), 0) as byte_count, MIN(time_iso) as first_seen, MAX(time_iso) as last_seen FROM packets WHERE capture_id = ? AND dst_ip = ?",
        (capture_id, ip)
    ).fetchone()

    # Communicated peers
    peers_out = conn.execute(
        "SELECT dst_ip as peer, COUNT(*) as packets, SUM(length) as bytes, 'outbound' as direction FROM packets WHERE capture_id = ? AND src_ip = ? GROUP BY dst_ip ORDER BY packets DESC LIMIT 15",
        (capture_id, ip)
    ).fetchall()

    peers_in = conn.execute(
        "SELECT src_ip as peer, COUNT(*) as packets, SUM(length) as bytes, 'inbound' as direction FROM packets WHERE capture_id = ? AND dst_ip = ? GROUP BY src_ip ORDER BY packets DESC LIMIT 15",
        (capture_id, ip)
    ).fetchall()

    # Destination ports targeted by this IP
    ports_targeted = conn.execute(
        "SELECT dst_port, COUNT(*) as count FROM packets WHERE capture_id = ? AND src_ip = ? AND dst_port IS NOT NULL GROUP BY dst_port ORDER BY count DESC LIMIT 15",
        (capture_id, ip)
    ).fetchall()

    # Protocols used
    protocols_used = conn.execute(
        "SELECT protocol, COUNT(*) as count FROM packets WHERE capture_id = ? AND (src_ip = ? OR dst_ip = ?) GROUP BY protocol ORDER BY count DESC",
        (capture_id, ip, ip)
    ).fetchall()

    # Related alerts where IP is mentioned in observed values
    alert_rows = conn.execute(
        "SELECT id, rule_id, rule_name, severity, trigger_summary, status, observed_values_json FROM alerts WHERE capture_id = ? AND (observed_values_json LIKE ? OR observed_values_json LIKE ?)",
        (capture_id, f'%"{ip}"%', f'%{ip}%')
    ).fetchall()

    related_alerts = []
    for r in alert_rows:
        a = dict(r)
        related_alerts.append(a)

    # Activity timeline packets (first 30)
    timeline_rows = conn.execute(
        """SELECT packet_index, time_iso, relative_time, src_ip, src_port, dst_ip, dst_port, protocol, length, summary
           FROM packets WHERE capture_id = ? AND (src_ip = ? OR dst_ip = ?)
           ORDER BY packet_index ASC LIMIT 30""",
        (capture_id, ip, ip)
    ).fetchall()

    return {
        'ip': ip,
        'packets_sent': sent_row['pkt_count'],
        'bytes_sent': sent_row['byte_count'],
        'packets_received': recv_row['pkt_count'],
        'bytes_received': recv_row['byte_count'],
        'first_seen': sent_row['first_seen'] or recv_row['first_seen'],
        'last_seen': sent_row['last_seen'] or recv_row['last_seen'],
        'peers_outbound': [dict(r) for r in peers_out],
        'peers_inbound': [dict(r) for r in peers_in],
        'ports_targeted': [dict(r) for r in ports_targeted],
        'protocols_used': [dict(r) for r in protocols_used],
        'related_alerts': related_alerts,
        'timeline': [dict(r) for r in timeline_rows]
    }

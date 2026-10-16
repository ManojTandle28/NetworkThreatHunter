import json
from flask import render_template, request, Response, flash, redirect, url_for
from app.routes import exports_bp
from app.database import get_db
from app.routes.main import get_current_capture
from app.services.report_generator import ReportGenerator
from app.services.traffic_statistics import TrafficStatistics

@exports_bp.route('/export/csv')
def export_csv():
    capture = get_current_capture()
    if not capture:
        flash("No active capture to export.", "warning")
        return redirect(url_for('main.dashboard'))

    cid = capture['id']
    src_ip = request.args.get('src_ip', '').strip()
    dst_ip = request.args.get('dst_ip', '').strip()
    protocol = request.args.get('protocol', '').strip()
    port = request.args.get('port', '').strip()
    search = request.args.get('search', '').strip()

    query = "SELECT * FROM packets WHERE capture_id = ?"
    params = [cid]

    if src_ip:
        query += " AND src_ip LIKE ?"
        params.append(f"%{src_ip}%")
    if dst_ip:
        query += " AND dst_ip LIKE ?"
        params.append(f"%{dst_ip}%")
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
    if port:
        try:
            p_num = int(port)
            query += " AND (src_port = ? OR dst_port = ?)"
            params.extend([p_num, p_num])
        except ValueError:
            pass
    if search:
        query += " AND (summary LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ?)"
        t = f"%{search}%"
        params.extend([t, t, t, t])

    query += " ORDER BY packet_index ASC"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        packets = [dict(r) for r in rows]

    csv_data = ReportGenerator.generate_packets_csv(packets)
    filename = f"network_packets_{cid[:8]}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@exports_bp.route('/export/alerts/json')
def export_alerts_json():
    capture = get_current_capture()
    if not capture:
        flash("No active capture to export.", "warning")
        return redirect(url_for('main.dashboard'))

    cid = capture['id']
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM alerts WHERE capture_id = ? ORDER BY created_at ASC", (cid,)).fetchall()
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

    json_data = ReportGenerator.generate_alerts_json(alerts, capture)
    filename = f"threat_alerts_{cid[:8]}.json"

    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@exports_bp.route('/export/summary/json')
def export_summary_json():
    capture = get_current_capture()
    if not capture:
        flash("No active capture to export.", "warning")
        return redirect(url_for('main.dashboard'))

    cid = capture['id']
    with get_db() as conn:
        packets_rows = conn.execute("SELECT * FROM packets WHERE capture_id = ? ORDER BY packet_index ASC", (cid,)).fetchall()
        packets = [dict(r) for r in packets_rows]
        stats = TrafficStatistics.calculate(packets)

        alert_rows = conn.execute("SELECT * FROM alerts WHERE capture_id = ? ORDER BY created_at ASC", (cid,)).fetchall()
        alerts = []
        for r in alert_rows:
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

    json_data = ReportGenerator.generate_summary_json(capture, stats, alerts)
    filename = f"threat_summary_{cid[:8]}.json"

    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@exports_bp.route('/report')
def incident_report():
    capture = get_current_capture()
    if not capture:
        flash("Please upload a capture or load demo traffic to generate an incident report.", "info")
        return redirect(url_for('main.dashboard'))

    cid = capture['id']
    with get_db() as conn:
        packets_rows = conn.execute("SELECT * FROM packets WHERE capture_id = ? ORDER BY packet_index ASC", (cid,)).fetchall()
        packets = [dict(r) for r in packets_rows]
        stats = TrafficStatistics.calculate(packets)

        alert_rows = conn.execute("SELECT * FROM alerts WHERE capture_id = ? ORDER BY created_at ASC", (cid,)).fetchall()
        alerts = []
        for r in alert_rows:
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

    return render_template('report.html', capture=capture, stats=stats, alerts=alerts)

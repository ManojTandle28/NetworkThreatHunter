import os
import uuid
import json
from pathlib import Path
from flask import render_template, request, redirect, url_for, flash, session, jsonify, current_app
from werkzeug.utils import secure_filename
from app.routes import main_bp
from app.config import Config
from app.database import get_db, clear_all_history, delete_capture_data
from app.services.pcap_analyzer import PcapAnalyzer, PcapAnalysisError
from app.services.traffic_statistics import TrafficStatistics

def get_current_capture():
    """Retrieve currently active capture row from session or latest record."""
    cid = session.get('current_capture_id')
    with get_db() as conn:
        if cid:
            row = conn.execute("SELECT * FROM captures WHERE id = ?", (cid,)).fetchone()
            if row:
                return dict(row)
        # Fallback to most recent capture
        row = conn.execute("SELECT * FROM captures ORDER BY created_at DESC LIMIT 1").fetchone()
        if row:
            session['current_capture_id'] = row['id']
            return dict(row)
    return None

@main_bp.route('/')
@main_bp.route('/dashboard')
def dashboard():
    capture = get_current_capture()
    if not capture:
        return render_template('dashboard.html', capture=None, stats=None, alerts_summary=None)

    cid = capture['id']
    with get_db() as conn:
        # Fetch packet summaries for statistics
        packets_rows = conn.execute(
            """SELECT packet_index, timestamp, time_iso, relative_time, src_ip, src_port,
                      dst_ip, dst_port, protocol, length, tcp_flags, dns_query, dns_type
               FROM packets WHERE capture_id = ? ORDER BY packet_index ASC""",
            (cid,)
        ).fetchall()
        packets = [dict(r) for r in packets_rows]

        # Calculate statistics
        stats = TrafficStatistics.calculate(packets)

        # Fetch alert counts by severity
        alert_rows = conn.execute(
            "SELECT id, rule_id, rule_name, severity, trigger_summary, status FROM alerts WHERE capture_id = ? ORDER BY created_at ASC",
            (cid,)
        ).fetchall()
        alerts = [dict(r) for r in alert_rows]

        alerts_summary = {
            'total': len(alerts),
            'critical': sum(1 for a in alerts if a['severity'] == 'Critical'),
            'high': sum(1 for a in alerts if a['severity'] == 'High'),
            'medium': sum(1 for a in alerts if a['severity'] == 'Medium'),
            'low': sum(1 for a in alerts if a['severity'] == 'Low'),
            'recent': alerts[:5]
        }

    return render_template(
        'dashboard.html',
        capture=capture,
        stats=stats,
        alerts_summary=alerts_summary
    )

@main_bp.route('/upload', methods=['POST'])
def upload_pcap():
    if 'pcap_file' not in request.files:
        flash("No file part provided in upload request.", "error")
        return redirect(url_for('main.dashboard'))

    file = request.files['pcap_file']
    if not file or file.filename == '':
        flash("Please select a valid network capture file.", "warning")
        return redirect(url_for('main.dashboard'))

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in Config.ALLOWED_EXTENSIONS:
        flash(f"Unsupported file format '{ext}'. Only .pcap and .pcapng files are accepted.", "error")
        return redirect(url_for('main.dashboard'))

    # Generate secure internal filename
    safe_name = f"{uuid.uuid4().hex}{ext}"
    upload_path = os.path.join(Config.UPLOAD_FOLDER, safe_name)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    try:
        file.save(upload_path)
    except Exception as e:
        flash(f"Failed to save uploaded file: {str(e)}", "error")
        return redirect(url_for('main.dashboard'))

    # Parse capture safely
    analyzer = PcapAnalyzer()
    try:
        cid = str(uuid.uuid4())
        result = analyzer.parse_file(
            file_path=upload_path,
            capture_id=cid,
            original_filename=file.filename,
            is_demo=False
        )
        session['current_capture_id'] = cid
        flash(
            f"Successfully analyzed '{file.filename}': {result['packet_count']} packets processed in {result['analysis_duration']}s.",
            "success"
        )
        if result.get('is_truncated'):
            flash(
                f"Note: Capture exceeded safety limit and was truncated at {result['packet_count']} packets to protect system resources.",
                "warning"
            )
    except PcapAnalysisError as pae:
        if os.path.exists(upload_path):
            try:
                os.remove(upload_path)
            except OSError:
                pass
        flash(f"Analysis Error: {str(pae)}", "error")
    except Exception as e:
        if os.path.exists(upload_path):
            try:
                os.remove(upload_path)
            except OSError:
                pass
        flash(f"An unexpected error occurred during packet analysis: {str(e)}", "error")

    return redirect(url_for('main.dashboard'))

@main_bp.route('/demo', methods=['POST'])
def load_demo():
    """One-click workflow to load the synthetic demonstration capture."""
    sample_dir = Path(__file__).resolve().parent.parent.parent / "sample_data"
    sample_pcap = sample_dir / "sample_traffic.pcap"

    if not sample_pcap.exists():
        # Generate on demand
        try:
            from sample_data.generate_pcaps import create_synthetic_pcap
            create_synthetic_pcap()
        except Exception as e:
            flash(f"Failed to generate demo capture: {str(e)}", "error")
            return redirect(url_for('main.dashboard'))

    analyzer = PcapAnalyzer()
    cid = f"demo-{uuid.uuid4().hex[:8]}"
    try:
        result = analyzer.parse_file(
            file_path=str(sample_pcap),
            capture_id=cid,
            original_filename="sample_traffic.pcap [DEMO]",
            is_demo=True
        )
        session['current_capture_id'] = cid
        flash(
            f"Loaded synthetic demo capture: {result['packet_count']} packets analyzed, {len(result['alerts'])} threat indicators identified.",
            "info"
        )
    except Exception as e:
        flash(f"Error loading demonstration capture: {str(e)}", "error")

    return redirect(url_for('main.dashboard'))

@main_bp.route('/clear', methods=['POST'])
def clear_history():
    """Clear all analysis records and remove uploaded files."""
    try:
        clear_all_history()
        session.pop('current_capture_id', None)

        # Clean upload folder files
        if os.path.exists(Config.UPLOAD_FOLDER):
            for fname in os.listdir(Config.UPLOAD_FOLDER):
                if fname == '.gitkeep':
                    continue
                fpath = os.path.join(Config.UPLOAD_FOLDER, fname)
                if os.path.isfile(fpath):
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass

        flash("All analysis history and temporary files have been permanently cleared.", "success")
    except Exception as e:
        flash(f"Failed to clear history: {str(e)}", "error")

    return redirect(url_for('main.dashboard'))

@main_bp.route('/api/status')
def api_status():
    capture = get_current_capture()
    if not capture:
        return jsonify({'status': 'idle', 'capture': None})
    return jsonify({'status': 'active', 'capture': capture})

import json
from flask import render_template, request, jsonify, session, flash, redirect, url_for
from app.routes import explorer_bp
from app.database import get_db
from app.routes.main import get_current_capture

@explorer_bp.route('/explorer')
def explorer():
    capture = get_current_capture()
    if not capture:
        flash("Please upload a packet capture or load the synthetic demo before exploring packets.", "info")
        return redirect(url_for('main.dashboard'))

    # Retrieve unique protocols for filter dropdown
    with get_db() as conn:
        protos = conn.execute(
            "SELECT DISTINCT protocol FROM packets WHERE capture_id = ? ORDER BY protocol ASC",
            (capture['id'],)
        ).fetchall()
        protocols = [r['protocol'] for r in protos]

    return render_template('explorer.html', capture=capture, protocols=protocols)

@explorer_bp.route('/api/packets')
def api_packets():
    capture = get_current_capture()
    if not capture:
        return jsonify({'error': 'No active capture found', 'packets': [], 'total': 0})

    cid = capture['id']
    page = max(1, int(request.args.get('page', 1)))
    page_size = min(200, max(10, int(request.args.get('page_size', 50))))
    offset = (page - 1) * page_size

    # Filter params
    src_ip = request.args.get('src_ip', '').strip()
    dst_ip = request.args.get('dst_ip', '').strip()
    protocol = request.args.get('protocol', '').strip()
    port = request.args.get('port', '').strip()
    search = request.args.get('search', '').strip()
    idx_filter = request.args.get('packet_index', '').strip()

    query = "FROM packets WHERE capture_id = ?"
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
            port_num = int(port)
            query += " AND (src_port = ? OR dst_port = ?)"
            params.extend([port_num, port_num])
        except ValueError:
            pass
    if idx_filter:
        try:
            idx_num = int(idx_filter)
            query += " AND packet_index = ?"
            params.append(idx_num)
        except ValueError:
            pass
    if search:
        query += " AND (summary LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    with get_db() as conn:
        count_query = f"SELECT COUNT(*) {query}"
        total = conn.execute(count_query, params).fetchone()[0]

        data_query = f"""SELECT packet_index, timestamp, time_iso, relative_time,
                                src_ip, src_port, dst_ip, dst_port, protocol, length,
                                tcp_flags, dns_query, dns_type, summary, is_cleartext, is_encrypted
                         {query} ORDER BY packet_index ASC LIMIT ? OFFSET ?"""
        rows = conn.execute(data_query, params + [page_size, offset]).fetchall()
        packets = [dict(r) for r in rows]

    total_pages = max(1, (total + page_size - 1) // page_size)

    return jsonify({
        'packets': packets,
        'page': page,
        'page_size': page_size,
        'total': total,
        'total_pages': total_pages
    })

@explorer_bp.route('/api/packets/<int:packet_index>')
def api_packet_detail(packet_index: int):
    capture = get_current_capture()
    if not capture:
        return jsonify({'error': 'No active capture found'}), 404

    cid = capture['id']
    with get_db() as conn:
        row = conn.execute(
            """SELECT packet_index, timestamp, time_iso, relative_time,
                      src_ip, src_port, dst_ip, dst_port, protocol, length,
                      tcp_flags, dns_query, dns_type, summary, is_cleartext,
                      is_encrypted, payload_hex, payload_ascii, layer_details_json
               FROM packets WHERE capture_id = ? AND packet_index = ?""",
            (cid, packet_index)
        ).fetchone()

    if not row:
        return jsonify({'error': f'Packet index {packet_index} not found'}), 404

    pkt = dict(row)
    try:
        pkt['layer_details'] = json.loads(pkt.pop('layer_details_json', '{}'))
    except Exception:
        pkt['layer_details'] = {}

    return jsonify({'packet': pkt})

import os
import sqlite3
import json
from contextlib import contextmanager
from app.config import Config

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    packet_count INTEGER NOT NULL,
    analyzed_duration REAL NOT NULL,
    is_demo INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    packet_index INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    time_iso TEXT NOT NULL,
    relative_time REAL NOT NULL,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    length INTEGER NOT NULL,
    tcp_flags TEXT,
    dns_query TEXT,
    dns_type TEXT,
    summary TEXT,
    is_cleartext INTEGER DEFAULT 0,
    is_encrypted INTEGER DEFAULT 0,
    payload_hex TEXT,
    payload_ascii TEXT,
    layer_details_json TEXT,
    FOREIGN KEY(capture_id) REFERENCES captures(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packets_capture_id ON packets(capture_id);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(capture_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(capture_id, dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(capture_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packets_ports ON packets(capture_id, src_port, dst_port);
CREATE INDEX IF NOT EXISTS idx_packets_index ON packets(capture_id, packet_index);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    trigger_summary TEXT NOT NULL,
    rationale TEXT NOT NULL,
    observed_values_json TEXT NOT NULL,
    packet_indices_json TEXT NOT NULL,
    timestamp_range TEXT NOT NULL,
    limitations TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    status TEXT DEFAULT 'New',
    analyst_notes TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(capture_id) REFERENCES captures(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_capture_id ON alerts(capture_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(capture_id, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(capture_id, status);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    flow_key TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    state TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL NOT NULL,
    duration REAL NOT NULL,
    FOREIGN KEY(capture_id) REFERENCES captures(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_flows_capture_id ON flows(capture_id);
"""

def init_db(db_path=None):
    """Initialize the SQLite database schema."""
    target_path = db_path or Config.DATABASE_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with sqlite3.connect(target_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(SCHEMA_SQL)
        conn.commit()

@contextmanager
def get_db(db_path=None):
    """Context manager for SQLite database connection."""
    target_path = db_path
    if not target_path:
        try:
            from flask import current_app, has_app_context
            if has_app_context() and current_app and 'DATABASE_PATH' in current_app.config:
                target_path = current_app.config['DATABASE_PATH']
        except Exception:
            pass
    target_path = target_path or Config.DATABASE_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def delete_capture_data(capture_id: str, db_path=None):
    """Deletes all database records associated with a capture."""
    with get_db(db_path) as conn:
        conn.execute("DELETE FROM flows WHERE capture_id = ?", (capture_id,))
        conn.execute("DELETE FROM alerts WHERE capture_id = ?", (capture_id,))
        conn.execute("DELETE FROM packets WHERE capture_id = ?", (capture_id,))
        conn.execute("DELETE FROM captures WHERE id = ?", (capture_id,))

def clear_all_history(db_path=None):
    """Clears all capture history and removes associated records."""
    with get_db(db_path) as conn:
        conn.execute("DELETE FROM flows")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM packets")
        conn.execute("DELETE FROM captures")

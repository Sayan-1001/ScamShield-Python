"""Database module for ScamShield India using SQLite."""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "scamshield.db"
UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                content TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                threat_level TEXT NOT NULL,
                impersonation TEXT,
                triggers_json TEXT,
                image_filename TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def save_scan_result(scan_type: str, content: str, result: dict, image_file=None) -> int:
    """Saves a scan record and uploaded screenshot evidence to the database."""
    init_db()

    image_filename = None
    if image_file is not None:
        try:
            image_file.seek(0)
            ext = os.path.splitext(getattr(image_file, "name", "screenshot.png"))[1] or ".png"
            image_filename = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            file_path = os.path.join(UPLOAD_DIR, image_filename)
            with open(file_path, "wb") as f:
                f.write(image_file.read())
            image_file.seek(0)
        except Exception:
            image_filename = None

    impersonation_str = ", ".join([f"{i['entity']} ({i['category']})" for i in result.get("impersonation_detected", [])])
    triggers_json = json.dumps([t["category"] for t in result.get("triggers", [])])

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_logs (
                scan_type, content, risk_score, threat_level, 
                impersonation, triggers_json, image_filename
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            content,
            result.get("risk_score", 0),
            result.get("risk_level", "SAFE"),
            impersonation_str,
            triggers_json,
            image_filename
        ))
        conn.commit()
        return cursor.lastrowid

def get_all_scans():
    """Fetches all past scans sorted by latest first."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]

def clear_all_scans():
    """Clears history and cleans evidence images."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_logs")
        conn.commit()
    # Clean uploaded images
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            try:
                os.remove(os.path.join(UPLOAD_DIR, f))
            except OSError:
                pass
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
    """Initializes the database schema with user support."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT DEFAULT 'guest',
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
        # Check if user_email column exists (migration helper)
        cursor.execute("PRAGMA table_info(scan_logs)")
        cols = [row["name"] for row in cursor.fetchall()]
        if "user_email" not in cols:
            cursor.execute("ALTER TABLE scan_logs ADD COLUMN user_email TEXT DEFAULT 'guest'")
        conn.commit()

def save_scan_result(scan_type: str, content: str, result: dict, image_file=None, user_email: str = "guest") -> int:
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
                user_email, scan_type, content, risk_score, threat_level, 
                impersonation, triggers_json, image_filename
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_email.strip().lower() if user_email else "guest",
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

def get_all_scans(user_email: str = None):
    """Fetches scans. If user_email is given, fetches records for that user."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        if user_email:
            cursor.execute(
                "SELECT * FROM scan_logs WHERE user_email = ? ORDER BY timestamp DESC", 
                (user_email.strip().lower(),)
            )
        else:
            cursor.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]

def clear_all_scans(user_email: str = None):
    """Clears history for a specific user or completely."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        if user_email:
            cursor.execute("DELETE FROM scan_logs WHERE user_email = ?", (user_email.strip().lower(),))
        else:
            cursor.execute("DELETE FROM scan_logs")
        conn.commit()
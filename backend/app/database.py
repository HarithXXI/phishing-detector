"""
SQLite Database Caching Module for PhishGuard Engine
Database File: backend/phishguard.db
Prevents redundant API calls to VirusTotal & external providers for URLs scanned within 24 hours.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "phishguard.db"))


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize SQLite scans and screenshot_cache tables if they do not exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                url TEXT PRIMARY KEY,
                score INTEGER,
                result TEXT,
                is_phishing BOOLEAN,
                created_at TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS screenshot_cache (
                url TEXT PRIMARY KEY,
                screenshot TEXT,
                created_at TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
        print(f"[SQLite DB] Initialized database at {DB_PATH}")
    except Exception as e:
        print(f"[SQLite DB Init Error]: {e}")


def get_cached_screenshot(url: str, max_age_hours: float = 24.0) -> Optional[str]:
    """Fetch base64 screenshot from SQLite cache if created within 24 hours."""
    if not url:
        return None
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        clean_url = url.strip()
        cursor.execute("SELECT screenshot, created_at FROM screenshot_cache WHERE url = ?", (clean_url,))
        row = cursor.fetchone()
        conn.close()

        if row:
            created_at_str = row["created_at"]
            created_at = datetime.fromisoformat(created_at_str) if isinstance(created_at_str, str) else created_at_str
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            age_hours = (now - created_at).total_seconds() / 3600.0

            if age_hours <= max_age_hours:
                print(f"[SQLite Screenshot Cache Hit]: {clean_url} (Age: {age_hours:.1f}h)")
                return row["screenshot"]
    except Exception as e:
        print(f"[SQLite Screenshot Cache Read Error]: {e}")
    return None


def save_cached_screenshot(url: str, screenshot_base64: str):
    """Save base64 screenshot in SQLite cache."""
    if not url or not screenshot_base64:
        return
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        clean_url = url.strip()
        created_at_str = datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            INSERT INTO screenshot_cache (url, screenshot, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                screenshot = excluded.screenshot,
                created_at = excluded.created_at
        """, (clean_url, screenshot_base64, created_at_str))

        conn.commit()
        conn.close()
        print(f"[SQLite Screenshot Cache Saved]: {clean_url}")
    except Exception as e:
        print(f"[SQLite Screenshot Cache Save Error]: {e}")



def get_cached_scan(url: str, max_age_hours: float = 24.0) -> Optional[Dict[str, Any]]:
    """Fetch scan result from SQLite cache if created within 24 hours."""
    if not url:
        return None
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        clean_url = url.strip().lower()
        cursor.execute("SELECT score, result, is_phishing, created_at FROM scans WHERE url = ?", (clean_url,))
        row = cursor.fetchone()
        conn.close()

        if row:
            created_at_str = row["created_at"]
            created_at = datetime.fromisoformat(created_at_str) if isinstance(created_at_str, str) else created_at_str
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            age_hours = (now - created_at).total_seconds() / 3600.0

            if age_hours <= max_age_hours:
                result_obj = json.loads(row["result"]) if isinstance(row["result"], str) else row["result"]
                print(f"[SQLite DB Cache Hit]: {clean_url} (Age: {age_hours:.1f}h)")
                result_obj["cached"] = True
                result_obj["cache_age_hours"] = round(age_hours, 1)
                return result_obj
    except Exception as e:
        print(f"[SQLite Cache Read Error]: {e}")
    return None


def save_scan(url: str, score: int, result: Any, is_phishing: bool):
    """Save or update scan result in SQLite cache."""
    if not url:
        return
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        clean_url = url.strip().lower()
        result_json = json.dumps(result) if not isinstance(result, str) else result
        created_at_str = datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            INSERT INTO scans (url, score, result, is_phishing, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                score = excluded.score,
                result = excluded.result,
                is_phishing = excluded.is_phishing,
                created_at = excluded.created_at
        """, (clean_url, score, result_json, is_phishing, created_at_str))

        conn.commit()
        conn.close()
        print(f"[SQLite DB Saved]: {clean_url} (Score: {score})")
    except Exception as e:
        print(f"[SQLite Cache Save Error]: {e}")


def get_recent_scans(limit: int = 10) -> list:
    """Fetch recent scans from SQLite scans table."""
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, score, is_phishing, created_at FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        conn.close()

        scans = []
        for r in rows:
            scans.append({
                "url": r["url"],
                "score": r["score"],
                "is_phishing": bool(r["is_phishing"]),
                "created_at": r["created_at"]
            })
        return scans
    except Exception as e:
        print(f"[SQLite get_recent_scans Error]: {e}")
        return []


if __name__ == "__main__":
    init_db()
    save_scan("http://sbi-verifiy.xyz", 85, {"test": "data"}, True)
    cached = get_cached_scan("http://sbi-verifiy.xyz")
    print("Cached fetch:", cached)

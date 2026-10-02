import sqlite3
import json

DB_NAME = "cyberguard.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT NOT NULL,
            input_text TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            ai_explanation TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    try:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN ai_explanation TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


init_db()


def save_scan_result(input_type: str, input_text: str, result: dict):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_logs (input_type, input_text, risk_score, risk_level, indicators, recommendation, ai_explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        input_type,
        input_text,
        result["score"],
        result["level"],
        json.dumps(result["indicators"], ensure_ascii=False),
        result["recommendation"],
        result.get("ai_explanation", "")
    ))
    conn.commit()
    conn.close()


def get_recent_scans(limit=10):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, input_type, input_text, risk_score, risk_level, timestamp, indicators, recommendation, ai_explanation
        FROM scan_logs 
        ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "type": row[1],
            "input": row[2],
            "score": row[3],
            "level": row[4],
            "time": row[5],
            "indicators": json.loads(row[6]) if row[6] else [],
            "recommendation": row[7],
            "ai_explanation": row[8] if len(row) > 8 else ""
        }
        for row in rows
    ]


def get_scan_by_id(scan_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, input_type, input_text, risk_score, risk_level, timestamp, indicators, recommendation, ai_explanation
        FROM scan_logs WHERE id = ?
    ''', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "type": row[1],
        "input": row[2],
        "score": row[3],
        "level": row[4],
        "time": row[5],
        "indicators": json.loads(row[6]) if row[6] else [],
        "recommendation": row[7],
        "ai_explanation": row[8] if len(row) > 8 else ""
    }


def get_scan_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM scan_logs')
    total = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE risk_score >= 65')
    high_risk = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE risk_score >= 30 AND risk_score < 65')
    medium_risk = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE risk_score < 30')
    low_risk = cursor.fetchone()[0]

    conn.close()
    return {
        "total": total,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk
    }

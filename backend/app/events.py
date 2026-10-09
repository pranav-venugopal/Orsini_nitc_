"""SQLite store for requests + sanitized security events. No raw prompts/answers are stored."""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from .config import settings

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(settings.db_path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock:
        c = _conn()
        with c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests(
                  request_id TEXT PRIMARY KEY, timestamp TEXT, status TEXT,
                  mode TEXT, latency_ms INTEGER);
                CREATE TABLE IF NOT EXISTS events(
                  event_id TEXT PRIMARY KEY, timestamp TEXT, request_id TEXT,
                  stage TEXT, label TEXT, categories TEXT, action TEXT, latency_ms INTEGER);
                                CREATE TABLE IF NOT EXISTS evaluations(
                                    evaluated_at TEXT NOT NULL, summary TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_events_ts ON events(timestamp);
                """
            )
        c.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _exec(sql: str, args: tuple) -> None:
    with _lock:
        c = _conn()
        with c:
            c.execute(sql, args)
        c.close()


def log_event(request_id: str, stage: str, label: str, categories: list[str], action: str, latency_ms: int) -> None:
    _exec("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
          (f"evt_{uuid.uuid4().hex[:10]}", now(), request_id, stage, label, json.dumps(categories), action, latency_ms))


def log_request(request_id: str, status: str, mode: str, latency_ms: int) -> None:
    _exec("INSERT INTO requests VALUES (?,?,?,?,?)", (request_id, now(), status, mode, latency_ms))


def save_evaluation_summary(summary: dict) -> None:
    _exec("INSERT INTO evaluations VALUES (?,?)", (now(), json.dumps(summary)))


def list_events(limit: int, offset: int, stage: Optional[str], action: Optional[str],
                since: Optional[str], until: Optional[str]) -> tuple[list[dict], int]:
    where, args = [], []
    for col, val, op in (("stage", stage, "="), ("action", action, "="), ("timestamp", since, ">="), ("timestamp", until, "<=")):
        if val:
            where.append(f"{col} {op} ?")
            args.append(val)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with _lock:
        c = _conn()
        total = c.execute(f"SELECT COUNT(*) FROM events {clause}", args).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM events {clause} ORDER BY timestamp DESC, rowid DESC LIMIT ? OFFSET ?", [*args, limit, offset]
        ).fetchall()
        c.close()
    def categories(value: str) -> list[str]:
        """Read current JSON arrays and legacy JSON/plain string category values."""
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            parsed = value
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, str)]
        return [parsed] if isinstance(parsed, str) and parsed else []

    return [{**dict(row), "categories": categories(row["categories"])} for row in rows], total


def metrics() -> dict:
    with _lock:
        c = _conn()
        total, avg = c.execute("SELECT COUNT(*), AVG(latency_ms) FROM requests WHERE mode='guarded'").fetchone()
        ib = c.execute("SELECT COUNT(*) FROM events WHERE stage='input' AND action='blocked_input'").fetchone()[0]
        ob = c.execute("SELECT COUNT(*) FROM events WHERE stage='output' AND action='blocked_output'").fetchone()[0]
        redactions = c.execute("SELECT COUNT(*) FROM events WHERE action='redacted'").fetchone()[0]
        latest_evaluation = c.execute("SELECT summary FROM evaluations ORDER BY rowid DESC LIMIT 1").fetchone()
        c.close()
    return {
        "total_requests": total,
        "input_blocks": ib,
        "output_blocks": ob,
        "redactions": redactions,
        "average_latency_ms": round(avg, 1) if avg is not None else None,
        "evaluation_summary": json.loads(latest_evaluation["summary"]) if latest_evaluation else None,
    }

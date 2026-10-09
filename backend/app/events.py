"""Persistent requests, events, and redacted chat history."""
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from .config import settings
from . import database

_lock = threading.Lock()


def init_db() -> None:
    with _lock:
        database.init_event_schema()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(val: object) -> str:
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val) if val is not None else ""


def _exec(sql: str, args: tuple) -> None:
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                database.execute(cursor, sql, args)


def log_event(request_id: str, stage: str, label: str, categories: list[str], action: str, latency_ms: int) -> None:
    _exec("INSERT INTO events (event_id, timestamp, request_id, stage, label, categories, action, latency_ms) VALUES (?,?,?,?,?,?,?,?)",
           (f"evt_{uuid.uuid4().hex[:10]}", now(), request_id, stage, label, json.dumps(categories), action, latency_ms))


def log_request(request_id: str, status: str, mode: str, latency_ms: int) -> None:
    _exec("INSERT INTO requests (request_id, timestamp, status, mode, latency_ms) VALUES (?,?,?,?,?)", (request_id, now(), status, mode, latency_ms))


def save_evaluation_summary(summary: dict) -> None:
    _exec("INSERT INTO evaluations (evaluated_at, summary) VALUES (?,?)", (now(), json.dumps(summary)))


def log_chat_message(request_id: str, conversation_id: str, username: str, role: str, content: str) -> None:
    _exec(
        "INSERT INTO chat_messages (message_id, request_id, conversation_id, username, role, content, created_at) VALUES (?,?,?,?,?,?,?)",
        (f"msg_{uuid.uuid4().hex[:12]}", request_id, conversation_id, username, role, content, now()),
    )


def list_events(limit: int, offset: int, stage: Optional[str], action: Optional[str],
                since: Optional[str], until: Optional[str]) -> tuple[list[dict], int]:
    where, args = [], []
    for col, val, op in (("stage", stage, "="), ("action", action, "="), ("timestamp", since, ">="), ("timestamp", until, "<=")):
        if val:
            where.append(f"{col} {op} ?")
            args.append(val)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                total_row = database.execute(cursor, f"SELECT COUNT(*) AS count FROM events {clause}", tuple(args)).fetchone()
                total = total_row["count"] if database.using_postgres() else total_row[0]
                order = "timestamp DESC, id DESC" if database.using_postgres() else "timestamp DESC, rowid DESC"
                rows = database.execute(
                    cursor, f"SELECT * FROM events {clause} ORDER BY {order} LIMIT ? OFFSET ?", tuple([*args, limit, offset])
                ).fetchall()
                req_ids = list({row["request_id"] for row in rows if row["request_id"]})
                prompts_by_rid: dict[str, str] = {}
                attempted_by_rid: dict[str, str] = {}
                final_by_rid: dict[str, str] = {}
                if req_ids:
                    order_msgs = "id" if database.using_postgres() else "rowid"
                    placeholders = ",".join("?" for _ in req_ids)
                    msg_rows = database.execute(
                        cursor,
                        f"SELECT request_id, role, content FROM chat_messages WHERE request_id IN ({placeholders}) ORDER BY {order_msgs} ASC",
                        tuple(req_ids),
                    ).fetchall()
                    for m in msg_rows:
                        rid = m["request_id"]
                        role = m["role"]
                        if role == "user" and rid not in prompts_by_rid:
                            prompts_by_rid[rid] = m["content"]
                        elif role == "attempted_output" and rid not in attempted_by_rid:
                            attempted_by_rid[rid] = m["content"]
                        elif role == "assistant" and rid not in final_by_rid:
                            final_by_rid[rid] = m["content"]
    def categories(value: str) -> list[str]:
        """Read current JSON arrays and legacy JSON/plain string category values."""
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            parsed = value
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, str)]
        return [parsed] if isinstance(parsed, str) and parsed else []

    return [
        {
            **dict(row),
            "timestamp": _iso(row["timestamp"]),
            "categories": categories(row["categories"]),
            "user_prompt": prompts_by_rid.get(row["request_id"]),
            "attempted_output": attempted_by_rid.get(row["request_id"]),
            "final_output": final_by_rid.get(row["request_id"]),
        }
        for row in rows
    ], total


def metrics() -> dict:
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                row = database.execute(cursor, "SELECT COUNT(*) AS total, AVG(latency_ms) AS average FROM requests WHERE mode='guarded'").fetchone()
                total = row["total"] if database.using_postgres() else row[0]
                avg = row["average"] if database.using_postgres() else row[1]
                def count(query: str) -> int:
                    item = database.execute(cursor, query).fetchone()
                    return item["count"] if database.using_postgres() else item[0]
                ib = count("SELECT COUNT(*) AS count FROM events WHERE stage='input' AND action='blocked_input'")
                ob = count("SELECT COUNT(*) AS count FROM events WHERE stage='output' AND action='blocked_output'")
                redactions = count("SELECT COUNT(*) AS count FROM events WHERE action='redacted'")
                order = "id" if database.using_postgres() else "rowid"
                latest_evaluation = database.execute(cursor, f"SELECT summary FROM evaluations ORDER BY {order} DESC LIMIT 1").fetchone()
    return {
        "total_requests": total,
        "input_blocks": ib,
        "output_blocks": ob,
        "redactions": redactions,
        "average_latency_ms": round(avg, 1) if avg is not None else None,
        "evaluation_summary": _json_value(latest_evaluation["summary"]) if latest_evaluation else None,
    }


def list_chat_messages(username: str, conversation_id: str | None, limit: int) -> list[dict]:
    where = "username = ? AND role IN ('user', 'assistant')"
    args: list[str | int] = [username]
    if conversation_id:
        where += " AND conversation_id = ?"
        args.append(conversation_id)
    order = "id" if database.using_postgres() else "rowid"
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                rows = database.execute(
                    cursor,
                    f"SELECT message_id, request_id, conversation_id, role, content, created_at FROM chat_messages WHERE {where} ORDER BY {order} DESC LIMIT ?",
                    tuple([*args, limit]),
                ).fetchall()
    return [{**dict(row), "created_at": _iso(row["created_at"])} for row in reversed(rows)]


def _json_value(value: object) -> object:
    return json.loads(value) if isinstance(value, str) else value


def get_request_chat_details(request_id: str) -> dict:
    order = "id" if database.using_postgres() else "rowid"
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                req_row = database.execute(
                    cursor,
                    "SELECT * FROM requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                evt_rows = database.execute(
                    cursor,
                    f"SELECT * FROM events WHERE request_id = ? ORDER BY {order} ASC",
                    (request_id,),
                ).fetchall()
                msg_rows = database.execute(
                    cursor,
                    f"SELECT * FROM chat_messages WHERE request_id = ? ORDER BY {order} ASC",
                    (request_id,),
                ).fetchall()

    def parse_cats(val: object) -> list[str]:
        if isinstance(val, list):
            return val
        if not isinstance(val, str):
            return []
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return [val] if val else []

    req = None
    if req_row:
        req = {**dict(req_row), "timestamp": _iso(req_row["timestamp"])}

    events_list = [
        {
            **dict(r),
            "timestamp": _iso(r["timestamp"]),
            "categories": parse_cats(r["categories"]),
        }
        for r in evt_rows
    ]

    messages_list = [
        {
            **dict(r),
            "created_at": _iso(r["created_at"]),
        }
        for r in msg_rows
    ]

    user_prompt = next((m["content"] for m in messages_list if m.get("role") == "user"), None)
    attempted_output = next((m["content"] for m in messages_list if m.get("role") == "attempted_output"), None)
    final_output = next((m["content"] for m in messages_list if m.get("role") == "assistant"), None)

    return {
        "request": req,
        "events": events_list,
        "messages": messages_list,
        "user_prompt": user_prompt,
        "attempted_output": attempted_output,
        "final_output": final_output,
    }


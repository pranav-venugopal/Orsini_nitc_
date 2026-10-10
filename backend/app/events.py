"""Persistent requests, events, and redacted chat history."""
import csv
import hashlib
import io
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from .config import settings
from . import database

_lock = threading.Lock()


def backfill_legacy_event_hashes() -> None:
    with database.connection() as conn:
        with conn.cursor() if database.using_postgres() else conn as cursor:
            order = "id ASC" if database.using_postgres() else "rowid ASC"
            rows = database.execute(
                cursor,
                f"SELECT event_id, timestamp, request_id, stage, label, categories, action, latency_ms, prev_hash, hash FROM events ORDER BY {order}",
            ).fetchall()
            if not rows:
                return
            needs_backfill = any(not (dict(r).get("hash")) for r in rows)
            if not needs_backfill:
                return
            prev = ""
            for r in rows:
                r_dict = dict(r)
                evt_id = r_dict["event_id"]
                ts = _iso(r_dict["timestamp"])
                req_id = r_dict["request_id"]
                stage = r_dict["stage"]
                label = r_dict["label"]
                action = r_dict["action"]
                lat = r_dict["latency_ms"]
                raw_cats = r_dict["categories"]
                try:
                    cats = json.loads(raw_cats) if isinstance(raw_cats, str) else raw_cats
                except Exception:
                    cats = [raw_cats]
                if not isinstance(cats, list):
                    cats = [str(cats)]
                canon = canonical_event_metadata(evt_id, ts, req_id, stage, label, cats, action, lat)
                curr_hash = compute_event_hash(prev, canon)
                database.execute(
                    cursor,
                    "UPDATE events SET prev_hash = ?, hash = ? WHERE event_id = ?",
                    (prev, curr_hash, evt_id),
                )
                prev = curr_hash


def init_db() -> None:
    with _lock:
        database.init_event_schema()
        backfill_legacy_event_hashes()


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


def canonical_event_metadata(event_id: str, timestamp: str, request_id: str, stage: str, label: str, categories: list[str], action: str, latency_ms: int) -> str:
    payload = {
        "action": action,
        "categories": sorted(categories) if isinstance(categories, list) else [str(categories)],
        "event_id": event_id,
        "label": label,
        "latency_ms": latency_ms,
        "request_id": request_id,
        "stage": stage,
        "timestamp": timestamp,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_event_hash(prev_hash: str | None, canonical_json: str) -> str:
    data = (prev_hash or "") + canonical_json
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def log_event(request_id: str, stage: str, label: str, categories: list[str], action: str, latency_ms: int) -> str:
    evt_id = f"evt_{uuid.uuid4().hex[:10]}"
    ts = now()
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                order = "id DESC" if database.using_postgres() else "rowid DESC"
                last_row = database.execute(cursor, f"SELECT hash FROM events ORDER BY {order} LIMIT 1").fetchone()
                prev_hash = ""
                if last_row:
                    prev_hash = (last_row["hash"] if database.using_postgres() else last_row[0]) or ""
                canon = canonical_event_metadata(evt_id, ts, request_id, stage, label, categories, action, latency_ms)
                evt_hash = compute_event_hash(prev_hash, canon)
                database.execute(
                    cursor,
                    "INSERT INTO events (event_id, timestamp, request_id, stage, label, categories, action, latency_ms, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (evt_id, ts, request_id, stage, label, json.dumps(categories), action, latency_ms, prev_hash, evt_hash),
                )
    return evt_id


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


def get_conversation_history(conversation_id: str, limit: int = 20) -> list[dict]:
    if not conversation_id:
        return []
    order = "id" if database.using_postgres() else "rowid"
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                rows = database.execute(
                    cursor,
                    f"SELECT role, content FROM chat_messages WHERE conversation_id = ? AND role IN ('user', 'assistant') ORDER BY {order} DESC LIMIT ?",
                    (conversation_id, limit),
                ).fetchall()
    return [{"role": str(row["role"]), "content": str(row["content"])} for row in reversed(rows)]


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


def verify_audit_chain() -> dict:
    order = "id ASC" if database.using_postgres() else "rowid ASC"
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                rows = database.execute(
                    cursor,
                    f"SELECT event_id, timestamp, request_id, stage, label, categories, action, latency_ms, prev_hash, hash FROM events ORDER BY {order}",
                ).fetchall()

    expected_prev = ""
    for idx, row in enumerate(rows):
        r_dict = dict(row)
        evt_id = r_dict["event_id"]
        ts = _iso(r_dict["timestamp"])
        req_id = r_dict["request_id"]
        stage = r_dict["stage"]
        label = r_dict["label"]
        action = r_dict["action"]
        latency_ms = r_dict["latency_ms"]
        raw_cats = r_dict["categories"]
        try:
            cats = json.loads(raw_cats) if isinstance(raw_cats, str) else raw_cats
        except Exception:
            cats = [raw_cats]
        if not isinstance(cats, list):
            cats = [str(cats)]

        stored_prev = r_dict.get("prev_hash") or ""
        stored_hash = r_dict.get("hash") or ""

        # Check prev_hash matches chain
        if stored_prev != expected_prev:
            return {
                "verified": False,
                "total_events": len(rows),
                "broken_at_index": idx,
                "broken_event_id": evt_id,
                "reason": f"prev_hash mismatch: expected '{expected_prev}', got '{stored_prev}'",
            }

        canon = canonical_event_metadata(evt_id, ts, req_id, stage, label, cats, action, latency_ms)
        computed = compute_event_hash(stored_prev, canon)
        if stored_hash != computed:
            return {
                "verified": False,
                "total_events": len(rows),
                "broken_at_index": idx,
                "broken_event_id": evt_id,
                "reason": f"hash mismatch: expected '{computed}', got '{stored_hash}'",
            }

        expected_prev = stored_hash

    return {
        "verified": True,
        "total_events": len(rows),
        "broken_at_index": None,
        "broken_event_id": None,
        "reason": None,
    }


def export_events(fmt: str = "json") -> tuple[str, str]:
    order = "id ASC" if database.using_postgres() else "rowid ASC"
    with _lock:
        with database.connection() as conn:
            with conn.cursor() if database.using_postgres() else conn as cursor:
                rows = database.execute(
                    cursor,
                    f"SELECT event_id, timestamp, request_id, stage, label, categories, action, latency_ms, prev_hash, hash FROM events ORDER BY {order}",
                ).fetchall()

    if fmt.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["event_id", "timestamp", "request_id", "stage", "label", "categories", "action", "latency_ms", "prev_hash", "hash"])
        for r in rows:
            r_dict = dict(r)
            writer.writerow([
                r_dict.get("event_id"),
                _iso(r_dict.get("timestamp")),
                r_dict.get("request_id"),
                r_dict.get("stage"),
                r_dict.get("label"),
                r_dict.get("categories"),
                r_dict.get("action"),
                r_dict.get("latency_ms"),
                r_dict.get("prev_hash") or "",
                r_dict.get("hash") or "",
            ])
        return output.getvalue(), "text/csv"

    # Default to json
    events_data = []
    for r in rows:
        r_dict = dict(r)
        raw_cats = r_dict.get("categories")
        try:
            cats = json.loads(raw_cats) if isinstance(raw_cats, str) else raw_cats
        except Exception:
            cats = [raw_cats]
        events_data.append({
            "event_id": r_dict.get("event_id"),
            "timestamp": _iso(r_dict.get("timestamp")),
            "request_id": r_dict.get("request_id"),
            "stage": r_dict.get("stage"),
            "label": r_dict.get("label"),
            "categories": cats if isinstance(cats, list) else [str(cats)],
            "action": r_dict.get("action"),
            "latency_ms": r_dict.get("latency_ms"),
            "prev_hash": r_dict.get("prev_hash") or "",
            "hash": r_dict.get("hash") or "",
        })
    return json.dumps(events_data, indent=2), "application/json"



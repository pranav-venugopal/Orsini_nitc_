"""Database connections and schema setup.

PostgreSQL is the production store. SQLite remains available only when
DATABASE_URL is omitted so unit tests can run without external services.
"""
import sqlite3
from contextlib import contextmanager
from typing import Iterator, Any

from .config import settings


def using_postgres() -> bool:
    return bool(settings.database_url)


@contextmanager
def connection() -> Iterator[Any]:
    if using_postgres():
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(settings.database_url, row_factory=dict_row) as conn:
            yield conn
        return

    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def execute(cursor: Any, sql: str, params: tuple = ()) -> Any:
    """Execute portable SQL written with SQLite-style positional placeholders."""
    return cursor.execute(sql.replace("?", "%s") if using_postgres() else sql, params)


def init_auth_schema() -> None:
    with connection() as conn:
        with conn.cursor() if using_postgres() else conn as cursor:
            execute(
                cursor,
                """CREATE TABLE IF NOT EXISTS registered_users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )""",
            )
            execute(cursor, "CREATE UNIQUE INDEX IF NOT EXISTS ix_registered_users_username_lower ON registered_users (lower(username))")
            if using_postgres():
                execute(
                    cursor,
                    """DO $$
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name = 'registered_users' AND column_name = 'email'
                        ) THEN
                            ALTER TABLE registered_users ALTER COLUMN email DROP NOT NULL;
                        END IF;
                    END $$;""",
                )


def init_event_schema() -> None:
    if using_postgres():
        with connection() as conn:
            with conn.cursor() as cursor:
                execute(cursor, """CREATE TABLE IF NOT EXISTS requests (
                    id BIGSERIAL PRIMARY KEY,
                    request_id TEXT UNIQUE NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    latency_ms INTEGER NOT NULL
                )""")
                execute(cursor, """CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    request_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    label TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    action TEXT NOT NULL,
                    latency_ms INTEGER NOT NULL
                )""")
                execute(cursor, """CREATE TABLE IF NOT EXISTS evaluations (
                    id BIGSERIAL PRIMARY KEY,
                    evaluated_at TIMESTAMPTZ NOT NULL,
                    summary TEXT NOT NULL
                )""")
                execute(cursor, """CREATE TABLE IF NOT EXISTS chat_messages (
                    id BIGSERIAL PRIMARY KEY,
                    message_id TEXT UNIQUE NOT NULL,
                    request_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL
                )""")
                execute(cursor, "CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events(timestamp DESC)")
                execute(cursor, "CREATE INDEX IF NOT EXISTS ix_chat_messages_conversation ON chat_messages (username, conversation_id, id)")
        return

    with connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS requests(
              request_id TEXT PRIMARY KEY, timestamp TEXT, status TEXT,
              mode TEXT, latency_ms INTEGER);
            CREATE TABLE IF NOT EXISTS events(
              event_id TEXT PRIMARY KEY, timestamp TEXT, request_id TEXT,
              stage TEXT, label TEXT, categories TEXT, action TEXT, latency_ms INTEGER);
            CREATE TABLE IF NOT EXISTS evaluations(
              evaluated_at TEXT NOT NULL, summary TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS chat_messages(
              message_id TEXT PRIMARY KEY, request_id TEXT, conversation_id TEXT,
              username TEXT, role TEXT, content TEXT, created_at TEXT);
            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS ix_chat_messages_conversation ON chat_messages(username, conversation_id, created_at);
            """
        )
